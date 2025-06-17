#include <windows.h>
#include <shlwapi.h>
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
// the launcher would be an exe file which would be the only file the user would press
//1. the launcher checks if the driver sys file is running in the services and if not then it mounts it to the services
//2.  the launcher would call a jar file which would be the java program
int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);

    std::wstring sysPath = std::wstring(exePath) + L"\\additionalFiles\\PacketPidDriver.sys";
    std::wstring jarPath = std::wstring(exePath) + L"\\javaProgram.jar";

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        MessageBoxW(NULL, L"Failed to open SCM", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    SC_HANDLE svc = OpenServiceW(scm, L"PacketPidDriver", SERVICE_START);
    if (!svc) {
        svc = CreateServiceW(
            scm,
            L"PacketPidDriver",
            L"Packet PID Driver",
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            sysPath.c_str(),
            NULL, NULL, NULL, NULL, NULL
        );

        if (!svc) {
            MessageBoxW(NULL, L"Failed to create driver service", L"Error", MB_OK | MB_ICONERROR);
            CloseServiceHandle(scm);
            return 1;
        }
    }

    StartServiceW(svc, 0, NULL);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    std::wstring cmd = L"javaw -jar \"" + jarPath + L"\"";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, 0, NULL, exePath, &si, &pi)) {
        MessageBoxW(NULL, L"Failed to launch Java program", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
