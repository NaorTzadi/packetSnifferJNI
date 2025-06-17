//C:\Users\neors\source\repos\PacketPidDriver\x64\Release this is where the sys file we created in visual studios

// PacketPid WFP driver — start/stop + PID filtering
// Build with WDK 10, link ndis.lib fwpkclnt.lib fwpuclnt.lib
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

#define IOCTL_GET_PACKET   CTL_CODE(FILE_DEVICE_NETWORK,0x800,METHOD_OUT_DIRECT,FILE_READ_DATA)
#define IOCTL_START_CAPTURE CTL_CODE(FILE_DEVICE_NETWORK,0x801,METHOD_BUFFERED,FILE_WRITE_DATA)
#define IOCTL_STOP_CAPTURE  CTL_CODE(FILE_DEVICE_NETWORK,0x802,METHOD_BUFFERED,FILE_WRITE_DATA)
#define IOCTL_SET_PID_LIST  CTL_CODE(FILE_DEVICE_NETWORK,0x803,METHOD_BUFFERED,FILE_WRITE_DATA)

DRIVER_INITIALIZE DriverEntry;

typedef struct _PACKET_RECORD {
    LIST_ENTRY List;
    UINT64     Pid;
    UINT32     Size;
    UINT8      Data[1];
} PACKET_RECORD, * PPACKET_RECORD;

/* globals */
static UINT32         gCalloutStore[2] = { 0 };   /* 32-bit callout IDs */
static UINT64         gFilterIds[2] = { 0 };   /* 64-bit filter IDs */
static UINT32         gFilterCount = 0;

static HANDLE         gEngine = NULL;
static UINT32         gCalloutId = 0;

static PDEVICE_OBJECT gDevice = NULL;

static LIST_ENTRY     gQueue;
static KSPIN_LOCK     gQueueLock;

static LONG           gCapturing = 0;

static UINT32         gPidCount = 0;
static UINT32         gPidList[128];
static KSPIN_LOCK     gPidLock;

/* queue helpers */
static __forceinline void Enqueue(PPACKET_RECORD r)
{
    KIRQL irql; KeAcquireSpinLock(&gQueueLock, &irql); InsertTailList(&gQueue, &r->List); KeReleaseSpinLock(&gQueueLock, irql);
}

static __forceinline PPACKET_RECORD Dequeue(void)
{
    KIRQL irql; PPACKET_RECORD r = NULL; KeAcquireSpinLock(&gQueueLock, &irql); if (!IsListEmpty(&gQueue)) r = CONTAINING_RECORD(RemoveHeadList(&gQueue), PACKET_RECORD, List); KeReleaseSpinLock(&gQueueLock, irql); return r;
}

/* PID filter */
static __forceinline BOOLEAN PidAllowed(UINT64 p)
{
    BOOLEAN ok = FALSE; KIRQL q; KeAcquireSpinLock(&gPidLock, &q); for (UINT32 i = 0; i < gPidCount; i++) { if (gPidList[i] == p) { ok = TRUE; break; } } KeReleaseSpinLock(&gPidLock, q); return ok;
}

/* buffer copy */
static NDIS_STATUS CopyFromNetBuffer(PNET_BUFFER nb, UINT32 len, UINT8* d)
{
    PUCHAR buf = (PUCHAR)NdisGetDataBuffer(nb, len, d, 1, 0); if (!buf) return NDIS_STATUS_RESOURCES; if (buf != d) RtlCopyMemory(d, buf, len); return NDIS_STATUS_SUCCESS;
}

/* flush */
static VOID FlushQueue(void) { while (TRUE) { PPACKET_RECORD r = Dequeue(); if (!r) break; ExFreePool(r); } }

/* WFP cleanup */
static VOID CleanupWfp(void)
{
    if (!gEngine) return;
    for (UINT32 i = 0; i < gFilterCount; i++) {
        if (gFilterIds[i])   FwpmFilterDeleteById0(gEngine, gFilterIds[i]);
        if (gCalloutStore[i])FwpmCalloutDeleteById0(gEngine, gCalloutStore[i]);
    }
    if (gCalloutId) FwpsCalloutUnregisterById0(gCalloutId);
    FwpmEngineClose0(gEngine);
    gEngine = NULL; gCalloutId = 0; gFilterCount = 0;
}

/* classify */
static VOID NTAPI ClassifyFn(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0* m, void* ld, const FWPS_FILTER0*, UINT64, FWPS_CLASSIFY_OUT0* o)
{
    if (!InterlockedCompareExchange(&gCapturing, 0, 0)) { o->actionType = FWP_ACTION_PERMIT; return; }
    if (!ld || !m || !m->processId || !PidAllowed(m->processId)) { o->actionType = FWP_ACTION_PERMIT; return; }

    const NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB((NET_BUFFER_LIST*)ld);
    if (!nb) { o->actionType = FWP_ACTION_PERMIT; return; }

    UINT32 len = NET_BUFFER_DATA_LENGTH(nb);
    PPACKET_RECORD rec = (PPACKET_RECORD)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PACKET_RECORD) + len, 'pktp');
    if (!rec) { o->actionType = FWP_ACTION_PERMIT; return; }

    rec->Pid = m->processId; rec->Size = len;
    if (CopyFromNetBuffer((PNET_BUFFER)nb, len, rec->Data) == NDIS_STATUS_SUCCESS) Enqueue(rec); else ExFreePool(rec);
    o->actionType = FWP_ACTION_PERMIT;
}

/* device IOCTL */
static NTSTATUS DeviceIo(PDEVICE_OBJECT, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS st = STATUS_SUCCESS;

    switch (sp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_GET_PACKET: {
        PPACKET_RECORD rec = Dequeue();
        PVOID out = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
        if (!rec || !out) { st = STATUS_NO_MORE_ENTRIES; break; }
        ULONG need = sizeof(PACKET_RECORD) + rec->Size;
        if (sp->Parameters.DeviceIoControl.OutputBufferLength < need) { st = STATUS_BUFFER_TOO_SMALL; ExFreePool(rec); break; }
        RtlCopyMemory(out, rec, need); irp->IoStatus.Information = need; ExFreePool(rec);
    } break;

    case IOCTL_START_CAPTURE: InterlockedExchange(&gCapturing, 1); break;
    case IOCTL_STOP_CAPTURE:  InterlockedExchange(&gCapturing, 0); break;

    case IOCTL_SET_PID_LIST: {
        UINT32 cnt = sp->Parameters.DeviceIoControl.InputBufferLength / sizeof(UINT32);
        if (cnt > 128) cnt = 128;
        KIRQL q; KeAcquireSpinLock(&gPidLock, &q);
        RtlCopyMemory(gPidList, irp->AssociatedIrp.SystemBuffer, cnt * sizeof(UINT32));
        gPidCount = cnt; KeReleaseSpinLock(&gPidLock, q);
    } break;

    default: st = STATUS_INVALID_DEVICE_REQUEST; break;
    }

    irp->IoStatus.Status = st; IoCompleteRequest(irp, IO_NO_INCREMENT); return st;
}

/* unload */
static VOID DriverUnload(PDRIVER_OBJECT)
{
    CleanupWfp();
    UNICODE_STRING s; RtlInitUnicodeString(&s, SYMLINK_NAME); IoDeleteSymbolicLink(&s);
    if (gDevice) IoDeleteDevice(gDevice);
    FlushQueue();
}

/* entry */
NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING)
{
    /* create device */
    NTSTATUS st;
    InitializeListHead(&gQueue); KeInitializeSpinLock(&gQueueLock); KeInitializeSpinLock(&gPidLock);

    UNICODE_STRING dn; RtlInitUnicodeString(&dn, DEVICE_NAME);
    st = IoCreateDevice(drv, 0, &dn, FILE_DEVICE_NETWORK, 0, FALSE, &gDevice); if (!NT_SUCCESS(st)) return st;

    UNICODE_STRING sl; RtlInitUnicodeString(&sl, SYMLINK_NAME); IoCreateSymbolicLink(&sl, &dn);

    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIo; drv->DriverUnload = DriverUnload;

    /* WFP */
    GUID key = { 0xaabbccdd,0,0,{0,0,0,0,0,0,0,1} };
    FWPS_CALLOUT0  co = { 0 };
    FWPM_SESSION0  sess = { 0 };
    FWPM_CALLOUT0  mco = { 0 };
    FWPM_FILTER0   flt = { 0 };
    const GUID* layers[2] = { &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,&FWPM_LAYER_OUTBOUND_TRANSPORT_V6 };

    co.calloutKey = key; co.classifyFn = ClassifyFn;
    st = FwpsCalloutRegister0(gDevice, &co, &gCalloutId); if (!NT_SUCCESS(st)) goto fail;

    sess.flags = FWPM_SESSION_FLAG_DYNAMIC;
    st = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &sess, &gEngine); if (!NT_SUCCESS(st)) goto fail;

    mco.calloutKey = key; mco.displayData.name = L"PacketPidCallout";
    flt.displayData.name = L"PacketPidFilter"; flt.action.type = FWP_ACTION_CALLOUT_TERMINATING; flt.action.calloutKey = key; flt.weight.type = FWP_EMPTY;

    for (int i = 0; i < 2; i++) {
        mco.applicableLayer = *layers[i];
        st = FwpmCalloutAdd0(gEngine, &mco, NULL, &gCalloutStore[gFilterCount]); if (!NT_SUCCESS(st)) goto fail;

        flt.layerKey = *layers[i];
        st = FwpmFilterAdd0(gEngine, &flt, NULL, &gFilterIds[gFilterCount]);   if (!NT_SUCCESS(st)) goto fail;

        gFilterCount++;
    }
    return STATUS_SUCCESS;

fail:
    CleanupWfp();
    if (gDevice) { UNICODE_STRING sl2; RtlInitUnicodeString(&sl2, SYMLINK_NAME); IoDeleteSymbolicLink(&sl2); IoDeleteDevice(gDevice); gDevice = NULL; }
    FlushQueue();
    return st;
}
