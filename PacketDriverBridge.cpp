#include <windows.h>
#include <thread>
#include <atomic>
#include <vector>
#include <jni.h>

#define IOCTL_GET_PACKET     CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define IOCTL_START_CAPTURE  CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_STOP_CAPTURE   CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_SET_PID_LIST   CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)

static std::atomic<bool> capturing = false;
static HANDLE hDriver = nullptr;
static std::thread captureThread;
static JavaVM* g_jvm = nullptr;
static jclass g_class = nullptr;
static jmethodID g_callbackMethod = nullptr;

static void sendIoctl(DWORD code, void* inBuf = nullptr, DWORD inLen = 0) {
    DWORD ignored;
    DeviceIoControl(hDriver, code, inBuf, inLen, nullptr, 0, &ignored, nullptr);
}

static void captureLoop() {
    JNIEnv* env = nullptr;
    g_jvm->AttachCurrentThread((void**)&env, nullptr);
    while (capturing) {
        uint8_t buffer[65536];
        DWORD ret = 0;
        if (DeviceIoControl(hDriver, IOCTL_GET_PACKET, nullptr, 0, buffer, sizeof(buffer), &ret, nullptr) && ret >= 12) {
            struct PacketHeader { uint64_t pid; uint32_t size; };
            auto* header = reinterpret_cast<PacketHeader*>(buffer);
            if (ret >= sizeof(PacketHeader) + header->size) {
                jbyteArray data = env->NewByteArray(header->size);
                env->SetByteArrayRegion(data, 0, header->size, reinterpret_cast<jbyte*>(buffer + sizeof(PacketHeader)));
                env->CallStaticVoidMethod(g_class, g_callbackMethod, (jint)header->pid, data);
                env->DeleteLocalRef(data);
            }
        } else {
            Sleep(10);
        }
    }
    g_jvm->DetachCurrentThread();
    CloseHandle(hDriver);
    hDriver = nullptr;
}

extern "C" {

__declspec(dllexport) void JNICALL Java_org_example_PacketCaptureBridge_JNI_startPacketCapture(JNIEnv* env, jclass, jintArray jPids) {
    if (capturing) return;
    hDriver = CreateFileW(L"\\\\.\\PacketPid", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) return;
    jsize n = env->GetArrayLength(jPids);
    std::vector<uint32_t> pids(n);
    env->GetIntArrayRegion(jPids, 0, n, reinterpret_cast<jint*>(pids.data()));
    sendIoctl(IOCTL_SET_PID_LIST, pids.data(), static_cast<DWORD>(pids.size() * sizeof(uint32_t)));
    sendIoctl(IOCTL_START_CAPTURE);
    capturing = true;
    captureThread = std::thread(captureLoop);
}

__declspec(dllexport) void JNICALL Java_org_example_PacketCaptureBridge_JNI_stopPacketCapture(JNIEnv*, jclass) {
    if (!capturing) return;
    sendIoctl(IOCTL_STOP_CAPTURE);
    capturing = false;
    if (captureThread.joinable()) captureThread.join();
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return -1;
    jclass cls = env->FindClass("org/example/PacketCaptureBridge");
    g_class = reinterpret_cast<jclass>(env->NewGlobalRef(cls));
    g_callbackMethod = env->GetStaticMethodID(g_class, "onPacket", "(I[B)V");
    return JNI_VERSION_1_6;
}

}
