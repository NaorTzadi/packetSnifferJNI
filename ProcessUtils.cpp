#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <jni.h>
#include <string>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// fixme: using 'OpenProcess' command is opening an handle to a process using the OS commands.
// it doesnt notify the process however a malware can check for new handles to see if there is an handle that is linked to it or one of its processes.
// the getExePath method is using 'OpenProcess' command so we need to figure out something else.

typedef NTSTATUS (NTAPI* NtQuerySystemInformation_t)(
    ULONG, PVOID, ULONG, PULONG
);
DWORD getParentPid(DWORD pid) {
    typedef struct {
        PVOID Reserved1;
        ULONG_PTR PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION;

    typedef NTSTATUS(WINAPI* NtQueryInformationProcessPtr)(
        HANDLE, UINT, PVOID, ULONG, PULONG
    );

    NtQueryInformationProcessPtr NtQueryInformationProcess =
        (NtQueryInformationProcessPtr)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"
        );
    if (!NtQueryInformationProcess) return 0;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return 0;

    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen;
    NTSTATUS status = NtQueryInformationProcess(
        hProc, 0, &pbi, sizeof(pbi), &retLen
    );
    CloseHandle(hProc);

    if (status != 0) return 0;
    return static_cast<DWORD>(pbi.InheritedFromUniqueProcessId);
}
std::string getExePath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "";

    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        return "";
    }

    CloseHandle(hProcess);
    return std::string(path);
}

extern "C"
JNIEXPORT jobjectArray JNICALL Java_org_example_JNI_ProcessUtils_getContactedRemoteIps
(JNIEnv* env, jclass, jintArray pidArray) {
    jsize len = env->GetArrayLength(pidArray);
    std::vector<DWORD> pids(len);
    env->GetIntArrayRegion(pidArray, 0, len, reinterpret_cast<jint*>(pids.data()));

    std::vector<std::string> result;
    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> buffer(size);

    if (GetExtendedTcpTable(buffer.data(), &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (std::find(pids.begin(), pids.end(), row.dwOwningPid) != pids.end() && row.dwRemoteAddr != 0) {
                struct in_addr addr;
                addr.S_un.S_addr = row.dwRemoteAddr;
                char ip[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &addr, ip, sizeof(ip)))
                    result.emplace_back(ip);
            }
        }
    }

    size = 0;
    GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> buffer6(size);

    if (GetExtendedTcpTable(buffer6.data(), &size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto table6 = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer6.data());
        for (DWORD i = 0; i < table6->dwNumEntries; ++i) {
            const auto& row = table6->table[i];
            if (std::find(pids.begin(), pids.end(), row.dwOwningPid) != pids.end()) {
                char ip[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, row.ucRemoteAddr, ip, sizeof(ip)))
                    result.emplace_back(ip);
            }
        }
    }

    jobjectArray ret = env->NewObjectArray(result.size(), env->FindClass("java/lang/String"), nullptr);
    for (size_t i = 0; i < result.size(); ++i)
        env->SetObjectArrayElement(ret, i, env->NewStringUTF(result[i].c_str()));
    return ret;
}
extern "C" JNIEXPORT jintArray JNICALL
Java_org_example_JNI_ProcessUtils_getAllExecutablePids(JNIEnv* env, jclass, jstring exeName) {
    const char* target = env->GetStringUTFChars(exeName, nullptr);
    std::vector<jint> pids;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(snap, &entry)) {
            do {
                if (_stricmp(entry.szExeFile, target) == 0) {
                    pids.push_back(entry.th32ProcessID);
                }
            } while (Process32Next(snap, &entry));
        }
        CloseHandle(snap);
    }

    env->ReleaseStringUTFChars(exeName, target);
    jintArray result = env->NewIntArray(pids.size());
    env->SetIntArrayRegion(result, 0, pids.size(), pids.data());
    return result;
}

extern "C"
JNIEXPORT jint JNICALL Java_org_example_JNI_ProcessUtils_getParentPid(JNIEnv* env, jclass, jint pid) {
    return static_cast<jint>(getParentPid(static_cast<DWORD>(pid)));
}

extern "C"
JNIEXPORT jint JNICALL Java_org_example_JNI_ProcessUtils_getExecutableParentPid(JNIEnv* env, jclass, jint pid) {
    std::string exePath = getExePath(pid);
    if (exePath.empty()) return -1;

    DWORD current = pid;
    while (true) {
        DWORD parent = getParentPid(current);
        if (parent == 0) break;

        std::string parentPath = getExePath(parent);
        if (_stricmp(exePath.c_str(), parentPath.c_str()) != 0) break;

        current = parent;
    }
    return static_cast<jint>(current);
}
extern "C"
JNIEXPORT jstring JNICALL Java_org_example_JNI_ProcessUtils_getExecutablePath(JNIEnv* env, jclass, jint pid) {
    std::string path = getExePath(static_cast<DWORD>(pid));
    return env->NewStringUTF(path.c_str());
}
