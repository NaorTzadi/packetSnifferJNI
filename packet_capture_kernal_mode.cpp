//C:\Users\neors\source\repos\PacketPidDriver\x64\Release this is where the sys file we created in visual studios

#define _WIN32_WINNT 0x0A00
#ifndef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN10
#endif
#define NDIS_WDM 1
#define INITGUID

#include <ntddk.h>
#include <ndis.h>
#include <ndis/nblapi.h>
#include <fwpsk.h>
#include <fwpmk.h>

#ifndef NET_BUFFER_LIST_FIRST_NB
#define NET_BUFFER_LIST_FIRST_NB(_NBL) ((_NBL)->FirstNetBuffer)
#endif
#ifndef NET_BUFFER_DATA_LENGTH
#define NET_BUFFER_DATA_LENGTH(_NB)    ((_NB)->DataLength)
#endif

#define DEVICE_NAME  L"\\Device\\PacketPid"
#define SYMLINK_NAME L"\\DosDevices\\PacketPid"

#define IOCTL_GET_PACKET     CTL_CODE(FILE_DEVICE_NETWORK,0x800,METHOD_OUT_DIRECT,FILE_READ_DATA)
#define IOCTL_START_CAPTURE  CTL_CODE(FILE_DEVICE_NETWORK,0x801,METHOD_BUFFERED,FILE_WRITE_DATA)
#define IOCTL_STOP_CAPTURE   CTL_CODE(FILE_DEVICE_NETWORK,0x802,METHOD_BUFFERED,FILE_WRITE_DATA)
#define IOCTL_SET_PID_LIST   CTL_CODE(FILE_DEVICE_NETWORK,0x803,METHOD_BUFFERED,FILE_WRITE_DATA)

DRIVER_INITIALIZE DriverEntry;

typedef struct _PACKET_RECORD {
    LIST_ENTRY List;
    UINT64     Pid;
    UINT32     Size;
    UINT8      Data[1];
} PACKET_RECORD, * PPACKET_RECORD;

static HANDLE         gEngine = NULL;
static UINT32         gCalloutId = 0;
static PDEVICE_OBJECT gDevice = NULL;
static LIST_ENTRY     gQueue;
static KSPIN_LOCK     gQueueLock;
static LONG           gCapturing = 0;
static UINT32         gPidCount = 0;
static UINT32         gPidList[128];
static KSPIN_LOCK     gPidLock;

// ---------------- queue helpers ----------------
static __forceinline void Enqueue(PPACKET_RECORD r)
{
    KIRQL irql; KeAcquireSpinLock(&gQueueLock, &irql); InsertTailList(&gQueue, &r->List); KeReleaseSpinLock(&gQueueLock, irql);
}

static __forceinline PPACKET_RECORD Dequeue(void)
{
    KIRQL irql; PPACKET_RECORD r = NULL; KeAcquireSpinLock(&gQueueLock, &irql); if (!IsListEmpty(&gQueue)) r = CONTAINING_RECORD(RemoveHeadList(&gQueue), PACKET_RECORD, List); KeReleaseSpinLock(&gQueueLock, irql); return r;
}

// ---------------- PID filter -------------------
static __forceinline BOOLEAN PidAllowed(UINT64 pid) { BOOLEAN ok = FALSE; KIRQL irql; KeAcquireSpinLock(&gPidLock, &irql); for (UINT32 i = 0; i < gPidCount; i++) { if (gPidList[i] == pid) { ok = TRUE; break; } }KeReleaseSpinLock(&gPidLock, irql); return ok; }

// ---------------- copy helper ------------------
static NDIS_STATUS CopyFromNetBuffer(PNET_BUFFER nb, UINT32 len, UINT8* dest) { PUCHAR buf = (PUCHAR)NdisGetDataBuffer(nb, len, dest, 1, 0); if (!buf)return NDIS_STATUS_RESOURCES; if (buf != dest)RtlCopyMemory(dest, buf, len); return NDIS_STATUS_SUCCESS; }

// ---------------- classify callback ------------
static VOID NTAPI ClassifyFn(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0* m, void* layerData, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0* out) {
    if (!InterlockedCompareExchange(&gCapturing, 0, 0)) { out->actionType = FWP_ACTION_PERMIT; return; }
    const NET_BUFFER_LIST* nbl = (const NET_BUFFER_LIST*)layerData;
    if (!nbl || !m->processId || !PidAllowed(m->processId)) { out->actionType = FWP_ACTION_PERMIT; return; }
    const NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    UINT32 len = NET_BUFFER_DATA_LENGTH(nb);
    PPACKET_RECORD rec = (PPACKET_RECORD)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PACKET_RECORD) + len, 'pktp');
    if (!rec) { out->actionType = FWP_ACTION_PERMIT; return; }
    rec->Pid = m->processId;
    rec->Size = len;
    if (CopyFromNetBuffer((PNET_BUFFER)nb, len, rec->Data) == NDIS_STATUS_SUCCESS)
        Enqueue(rec);
    else
        ExFreePool(rec);
    out->actionType = FWP_ACTION_PERMIT;
}

// ---------------- device IOCTL -----------------
static NTSTATUS DeviceIo(PDEVICE_OBJECT, PIRP irp) {
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    switch (sp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_GET_PACKET: {
        PPACKET_RECORD rec = Dequeue();
        if (rec) {
            ULONG need = sizeof(PACKET_RECORD) + rec->Size;
            if (sp->Parameters.DeviceIoControl.OutputBufferLength >= need) {
                RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, rec, need);
                irp->IoStatus.Information = need;
            }
            ExFreePool(rec);
        }
    }break;
    case IOCTL_START_CAPTURE: InterlockedExchange(&gCapturing, 1); break;
    case IOCTL_STOP_CAPTURE:  InterlockedExchange(&gCapturing, 0); break;
    case IOCTL_SET_PID_LIST: {
        UINT32 cnt = sp->Parameters.DeviceIoControl.InputBufferLength / sizeof(UINT32);
        if (cnt > 128)cnt = 128;
        KIRQL irql; KeAcquireSpinLock(&gPidLock, &irql);
        RtlCopyMemory(gPidList, irp->AssociatedIrp.SystemBuffer, cnt * sizeof(UINT32));
        gPidCount = cnt; KeReleaseSpinLock(&gPidLock, irql);
    }break;
    default: break;
    }
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ---------------- cleanup ----------------------
static VOID DriverUnload(PDRIVER_OBJECT) {
    if (gCalloutId) FwpsCalloutUnregisterById0(gCalloutId);
    if (gEngine)    FwpmEngineClose0(gEngine);
    UNICODE_STRING s; RtlInitUnicodeString(&s, SYMLINK_NAME); IoDeleteSymbolicLink(&s);
    if (gDevice)    IoDeleteDevice(gDevice);
}

// ---------------- entry ------------------------
NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING) {
    InitializeListHead(&gQueue); KeInitializeSpinLock(&gQueueLock); KeInitializeSpinLock(&gPidLock);
    UNICODE_STRING dn; RtlInitUnicodeString(&dn, DEVICE_NAME);
    NTSTATUS st = IoCreateDevice(drv, 0, &dn, FILE_DEVICE_NETWORK, 0, FALSE, &gDevice); if (!NT_SUCCESS(st))return st;
    UNICODE_STRING sl; RtlInitUnicodeString(&sl, SYMLINK_NAME); IoCreateSymbolicLink(&sl, &dn);
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIo; drv->DriverUnload = DriverUnload;

    GUID key = { 0xaabbccdd,0,0,{0,0,0,0,0,0,0,1} };
    FWPS_CALLOUT0 co = { 0 }; co.calloutKey = key; co.classifyFn = ClassifyFn;
    st = FwpsCalloutRegister0(gDevice, &co, &gCalloutId); if (!NT_SUCCESS(st))return st;

    FWPM_SESSION0 sess = { 0 }; sess.flags = FWPM_SESSION_FLAG_DYNAMIC;
    st = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &sess, &gEngine); if (!NT_SUCCESS(st))return st;

    const GUID* layers[] = { &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,&FWPM_LAYER_OUTBOUND_TRANSPORT_V6 };
    FWPM_CALLOUT0 mco = { 0 }; mco.calloutKey = key; mco.displayData.name = L"PacketPidCallout";
    for (int i = 0; i < 2; i++) {
        mco.applicableLayer = *layers[i]; FwpmCalloutAdd0(gEngine, &mco, NULL, NULL);
        FWPM_FILTER0 flt = { 0 }; flt.layerKey = *layers[i]; flt.displayData.name = L"PacketPidFilter";
        flt.action.type = FWP_ACTION_CALLOUT_TERMINATING; flt.action.calloutKey = key; flt.weight.type = FWP_EMPTY;
        FwpmFilterAdd0(gEngine, &flt, NULL, NULL);
    }
    return STATUS_SUCCESS;
}
