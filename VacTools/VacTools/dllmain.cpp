// dllmain.cpp : Defines the entry point for the DLL application.
#define _CRT_SECURE_NO_WARNINGS
#include "pch.h"
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <debugapi.h>
#include <winternl.h>
#pragma comment(lib, "ws2_32.lib")
#include <Psapi.h>
#include <intrin.h>

#include <array>
#include <cstring>
#include <string_view>
#include <Psapi.h>
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <array>
#include "MinHook/MinHook.h"

bool g_BAllowSteamMemoryRead = false;
LPVOID oReadProcessMemory = NULL;
typedef BOOL(__stdcall* ReadProcessMemoryFunc_t)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
BOOL __stdcall hk_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesRead)
{
    BOOL ret = ((ReadProcessMemoryFunc_t)oReadProcessMemory)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    for (int i = 0; i < nSize; i++)
        ((BYTE*)lpBuffer)[i] = NULL;

    return ret;
}

LPVOID oNtReadVirtualMemory = NULL;
typedef NTSTATUS(NTAPI* NtReadVirtualMemoryFunc_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
NTSTATUS NTAPI __stdcall hk_NtReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN ULONG NumberOfBytesToRead, OUT PULONG NumberOfBytesReaded OPTIONAL)
{
    NTSTATUS ret = ((NtReadVirtualMemoryFunc_t)oNtReadVirtualMemory)(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);

    char szFileName[MAX_PATH];
    if (!GetModuleFileNameExA(ProcessHandle, NULL, szFileName, MAX_PATH))
    {
        OutputDebugStringA("Zeroing Out Read Process Memory Call! Unable To Get File Name!\n");
        for (int i = 0; i < NumberOfBytesToRead; i++)
            ((BYTE*)Buffer)[i] = NULL;
    }
    else if (strstr(szFileName, "csgo") || strstr(szFileName, "Counter") || strstr(szFileName, "Discord") || strstr(szFileName, "OBS") || strstr(szFileName, "Harpoon"))
    {
        OutputDebugStringA("Zeroing Out Read Process Memory Call\n");
        for (int i = 0; i < NumberOfBytesToRead; i++)
            ((BYTE*)Buffer)[i] = NULL;
    }
    else if (strstr(szFileName, "steam") && !g_BAllowSteamMemoryRead)
    {
        OutputDebugStringA("Zeroing Out Read Process Memory Call To Steam!\n");
        for (int i = 0; i < NumberOfBytesToRead; i++)
            ((BYTE*)Buffer)[i] = NULL;
    } 
    else
    {
        if(IsDebuggerPresent())
            printf("Allowing Memory Read On Process %s\n", szFileName);
    }

    return ret;
}





char* strangememsetfunction(char* pAddress, unsigned int value, unsigned int count)
{
    if (count)
    {
        memset(pAddress, 0x1010101 * value, count >> 2);
        memset(&pAddress[4 * (count >> 2)], value, count & 3);
    }
    return pAddress;
}

signed int AllocShit(unsigned int a1, DWORD* a2, DWORD* a3, DWORD* a4)
{
    if (a1 < 176 || *(int*)a4 < 16)
    {
        return 4;
    }
    *(int*)a4 = 16;
}

signed int __stdcall GenericRunFunctionRebuild(int a1, int a2, int a3, int a4, int dllCrc)
{




}

/* Get Process ID */
void GET_PROC_ID(const char* window_title, DWORD& process_id) {
    GetWindowThreadProcessId(FindWindowA(NULL, window_title), &process_id);
}

void PrintProcessNameAndID(DWORD processID)
{
    CHAR szProcessName[MAX_PATH] = "<unknown>";

    // Get a handle to the process.

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);

    // Get the process name.

    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
            &cbNeeded))
        {
            GetModuleBaseNameA(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(CHAR));
        }
    }

    // Print the process name and identifier.

    printf("%s  (PID: %u)\n", szProcessName, processID);

    // Release the handle to the process.

    CloseHandle(hProcess);
}

HMODULE g_hThisMoudle = NULL;
LPVOID WhoCares = 0;
signed int first_ret{ 0 };
typedef signed int(__stdcall* ValveRunFunc_t)(int a1, int a2, int a3, int a4, int a5);
signed int __stdcall GenericRunFunction(int a1, int a2, int a3, int a4, int a5)
{
    char buffer[4096];
    if (!first_ret)
    {
        printf("[ALERT] GenericRunFunction Calling Original For Initial Load!\n");
        first_ret = ((ValveRunFunc_t)WhoCares)(a1, a2, a3, a4, a5);
    }
    //signed int ret = 1;
    snprintf(buffer, 4096, "[INFO]  GenericRunFunction(%d , %x , %d , %x , %x (%d))\n", a1, a2, a3, a4, a5);
    printf(buffer);

#if 0

    const char* game_name = "Counter-Strike: Global Offensive";
    const char* game_name2 = "csgo.exe";
    DWORD proc_id = 0;

    GET_PROC_ID(game_name, proc_id);
    if (proc_id != NULL) {


        HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, NULL, proc_id);
        if (h_process) {
            printf("CSGO Base Address %x\n", h_process);
        }
    }
    else {
        printf("CSGO Isnt Open.\n");
    }
    GET_PROC_ID(game_name2, proc_id);
    if (proc_id != NULL) {


        HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, NULL, proc_id);
        if (h_process) {
            printf("CSGO Base Address %x\n", h_process);
        }
    }
    else {
        printf("CSGO Isnt Open.\n");
    }


    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        printf("Can't enumerate Processes\n");
        return first_ret;
    }

    cProcesses = cbNeeded / sizeof(DWORD);
    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, aProcesses[i]);



            if (hProcess)
            {
                _PROCESS_BASIC_INFORMATION ProcInfo;
                ULONG dwSize = 0;
                HMODULE ntdll = LoadLibrary(L"ntdll.dll");
                NTSTATUS ProcAdd = ((NTSTATUS(__stdcall*)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG))GetProcAddress(ntdll, "NtQueryInformationProcess"))(hProcess, ProcessBasicInformation, &ProcInfo, sizeof(ProcInfo), &dwSize);


                if (ProcAdd)
                {
                    printf("NtQueryInformationProcess Failed!\n");
                }

                if ((HANDLE)a2 > ProcInfo.PebBaseAddress)
                {
                    MEMORY_BASIC_INFORMATION meminfo;
                    if (VirtualQueryEx(hProcess, (LPCVOID)a2, &meminfo, sizeof(meminfo)))
                    {



                        HMODULE hMod;
                        DWORD cbNeeded;

                        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
                            &cbNeeded))
                        {
                            CHAR szProcessName[MAX_PATH] = "<unknown>";
                            GetModuleBaseNameA(hProcess, hMod, szProcessName,
                                sizeof(szProcessName) / sizeof(CHAR));
                            printf("Found Containing Address Space for a2 %s, Base Address %x\n", szProcessName, ProcInfo.PebBaseAddress);
                        }
                    }
                    else
                    {
                        if (!(GetLastError() == ERROR_INVALID_PARAMETER))
                            printf("Failed with unknown error %d\n", GetLastError());
                    }
                }
                else if ((HANDLE)a4 > ProcInfo.PebBaseAddress)
                {
                    MEMORY_BASIC_INFORMATION meminfo;
                    if (VirtualQueryEx(hProcess, (LPCVOID)a4, &meminfo, sizeof(meminfo)))
                    {
                        CHAR szProcessName[MAX_PATH] = "<unknown>";
                        HMODULE hMod;
                        DWORD cbNeeded;

                        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
                            &cbNeeded))
                        {
                            GetModuleBaseNameA(hProcess, hMod, szProcessName,
                                sizeof(szProcessName) / sizeof(CHAR));
                            printf("Found Containing Address Space for a4 %s, Base Address %x\n", szProcessName, ProcInfo.PebBaseAddress);
                        }

                    }
                    else
                    {
                        if (!(GetLastError() == ERROR_INVALID_PARAMETER))
                            printf("Failed with unknown error %d\n", GetLastError());
                    }
                }

            }
        }
    }

#endif

    return first_ret;
}

__declspec(dllexport) signed int __stdcall runfunc(int a1, int a2, int a3, int a4, int a5)
{
    return GenericRunFunction(a1, a2, a3, a4, a5);
}

namespace Globals {
    BOOL g_bLoadLibaryLoad = TRUE;
    BOOL g_bDumpModules = TRUE;
    BOOL g_bAllowLoad = TRUE;
    int g_nSeenVacModules = 0;
    BOOL g_bShouldWait = TRUE;
}

struct CVacModule {
    LPVOID m_CRC;
    HANDLE m_hModule;
    DWORD m_pModule;
    FARPROC m_fnEntryPoint;
    DWORD m_nLastResult;
    DWORD m_dwModuleSize;
    LPVOID m_pRawModule;
    DWORD  m_dwUnknown;
};

struct mapped_module
{
    int m_nCrcData;
    void* m_pData = NULL;
    char pad2[12];
    int m_nSize = NULL;
};


std::vector<CVacModule*> m_vecLoadedModules;




void DumpVacModuleToDebugOut(CVacModule* pModule)
{
    char buffer[4096];
    const char* formatter = {
        ":::::: VAC MODULE DUMP ::::::\n"
        "   m_CRC          : %x\n"
        "   m_hModule      : %x\n"
        "   m_pModule      : %x\n"
        "   m_fnEntryPoint : %x\n"
        "   m_nLastResult  : %d\n"
        "   m_dwModuleSize : %d\n"
        "   m_pRawModule   : %d\n"
        "   m_dwUnknown    : %d\n"
        ":::::: END MODULE DUMP ::::::\n"
    };
    snprintf(buffer, 4096, formatter, pModule->m_CRC, pModule->m_hModule, pModule->m_pModule, pModule->m_fnEntryPoint, pModule->m_nLastResult, pModule->m_dwModuleSize, pModule->m_pRawModule, pModule->m_dwUnknown);
    printf(buffer);
}


bool __cdecl hk_WriteVacModuleToDisk(CVacModule* pModule, int a2, char dwFlags);

#define USE_VALVE_DLL_MAP 0x02
#define USE_LOAD_LIBRARY 0x01
#define USER_PROVIDED_MODULE 0x04
void* FindPattern(const char* szModuleName, const char* szPattern, const char* szName) noexcept;
template <typename T>
static constexpr auto relativeToAbsolute(uintptr_t address) noexcept
{
    return (T)(address + 4 + *reinterpret_cast<std::int32_t*>(address));
}

LPVOID oLoadVacModule = NULL;
typedef bool(__stdcall* LoadVacModuleFunc_t)(CVacModule*, DWORD);
DWORD CRC_OF_FIRST = 0;
BOOL DidGetFirst = 0;
char* pFirstLoadBuffer = 0;
SIZE_T nFirstLoadSize = 0;
bool __stdcall hk_LoadVacModule(CVacModule* Module, DWORD dwFlags)
{
    _SYSTEMTIME CurTime;
    GetSystemTime(&CurTime);
    char buffer[4096];
    snprintf(buffer, 4096, "[ALERT] SteamService.dll : Vac Module %x Loaded at (%d/%d/%d : %d:%d:%d)\n", Module->m_CRC, CurTime.wMonth, CurTime.wDay, CurTime.wYear, CurTime.wHour, CurTime.wMinute, CurTime.wSecond);
    printf(buffer);
    DumpVacModuleToDebugOut(Module);

    if (Module->m_CRC == (LPVOID)0x6969)
    {
       printf("[INFO]  User Provided DLL, Calling Original and returning\n");
       int ret = ((LoadVacModuleFunc_t)oLoadVacModule)(Module, 0x0);
       if (!Module->m_fnEntryPoint)
       {
           printf("User DLL Had No Entry Point\n");
           typedef ValveRunFunc_t* (__cdecl* ValveGetProcFunc_t)(DWORD, const char*);
           g_BAllowSteamMemoryRead = true;
           static ValveGetProcFunc_t ValveGetProc = relativeToAbsolute<ValveGetProcFunc_t>((uintptr_t)((char*)FindPattern("steamservice.dll", "\xE8????\x83\xC4\x08\x89\x46\x0C\x85\xC0\x0F\x85????", 0) + int(1))); 
           g_BAllowSteamMemoryRead = false;
           if (ValveGetProc)
           {
               printf("Valve Get Proc : %x\n", ValveGetProc);
               DumpVacModuleToDebugOut(Module);
               Module->m_fnEntryPoint = (FARPROC)ValveGetProc(Module->m_pModule, "_runfunc@20");

               if (!Module->m_fnEntryPoint)
               {
                   Module->m_fnEntryPoint = (FARPROC)ValveGetProc(Module->m_pModule, "runfunc");
                   if (!Module->m_fnEntryPoint)
                   {
                       printf("Fuck.");
                   }
               }
           }
           else {
               printf("No Valve Get Proc!\n");
           }


       }         
       //first_ret = 

       printf("GUCCI\n");

       return ret;
    }


    Globals::g_bAllowLoad = false;
    hk_WriteVacModuleToDisk(Module, 0, 1);
    Globals::g_bAllowLoad = true;
    //if (Globals::g_bLoadLibaryLoad || Globals::g_bDumpModules)
    //    dwFlags = 0;
#if 0

    return true;
#endif

    bool ret = 0;
    if (Globals::g_bAllowLoad && !WhoCares)
    {
        BOOL Allocd = false;
        if (!Module->m_pRawModule && !Module->m_pModule && !Module->m_hModule)
        {
            Module->m_pRawModule = malloc(nFirstLoadSize);
            memcpy(Module->m_pRawModule, pFirstLoadBuffer, nFirstLoadSize);
            Allocd = true;
        }
        else if (Module->m_pRawModule && !WhoCares && !pFirstLoadBuffer)
        {
            nFirstLoadSize = Module->m_dwModuleSize;
            pFirstLoadBuffer = (char*)malloc(nFirstLoadSize);
            memcpy(pFirstLoadBuffer, Module->m_pRawModule, nFirstLoadSize);
        }

        ret = ((LoadVacModuleFunc_t)oLoadVacModule)(Module, dwFlags);
        if(Module->m_fnEntryPoint)
            m_vecLoadedModules.push_back(Module);
        if(Allocd)
            free(Module->m_pRawModule);
    }
    Module->m_nLastResult = 0;

    if (!WhoCares)
    {
        printf("[INFO]  Dump After Load\n");
        DumpVacModuleToDebugOut(Module);
    }

    if (!WhoCares)
    {
        CRC_OF_FIRST = (DWORD)Module->m_CRC;
    }
    else {
        printf("[ALERT] Falsifying VAC Module Load for Module %x\n", Module->m_CRC);
        Module->m_fnEntryPoint = (FARPROC)GenericRunFunction;
        Module->m_hModule = g_hThisMoudle;
        Module->m_nLastResult = 0;
        Module->m_pRawModule = 0;
        return true;
    }

    if (Module->m_fnEntryPoint)
    {
        if (!WhoCares)
        {
            MH_CreateHook(Module->m_fnEntryPoint, &GenericRunFunction, &WhoCares);
            MH_EnableHook(MH_ALL_HOOKS);
        }
        else {
            LPVOID Nah = 0;
            MH_CreateHook(Module->m_fnEntryPoint, &GenericRunFunction, &Nah);
            MH_EnableHook(MH_ALL_HOOKS);
        }
    }

    return ret;
}

LPVOID oWriteVacModuleToDisk = NULL;
typedef bool(__cdecl* WriteVacModuleToDiskFunc_t)(CVacModule*, int, char);
bool __cdecl hk_WriteVacModuleToDisk(CVacModule* pModule, int a2, char dwFlags)
{

    if (!pModule->m_pRawModule || !pModule->m_dwModuleSize)
        return false;

    char pFileName[40];
    _SYSTEMTIME CurTime;
    GetSystemTime(&CurTime);
    snprintf(pFileName, 40, "C:\\VAC_%x_(%d-%d-%d).dll", pModule->m_CRC, CurTime.wMonth, CurTime.wDay, CurTime.wYear);
    char buffer[4096];
    snprintf(buffer, 4096, "[ALERT] SteamService.dll : Dumping VAC Module To Disk %s, size: %d\n", pFileName, pModule->m_dwModuleSize);
    printf(buffer);
    std::ofstream OutputFile(pFileName, std::ios::out | std::ios::binary);
    OutputFile.write((const char*)pModule->m_pRawModule, pModule->m_dwModuleSize);
    OutputFile.close();
    //printf("[ALERT] Vac Dump Disabled, Canceling!\n");

    if (Globals::g_bAllowLoad)
        return ((WriteVacModuleToDiskFunc_t)oWriteVacModuleToDisk)(pModule, a2, dwFlags);
}




void* FindPattern(const char* szModuleName, const char* szPattern, const char* szName) noexcept {
    static auto id = 0;
    ++id;
    HMODULE moduleHandle;
    if (moduleHandle = GetModuleHandleA(szModuleName)) {
        MODULEINFO moduleInfo;
        if (GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo, sizeof(moduleInfo))) {
            auto start = static_cast<const char*>(moduleInfo.lpBaseOfDll);
            const auto end = start + moduleInfo.SizeOfImage;

            auto first = start;
            auto second = szPattern;

            while (first < end && *second) {
                if (*first == *second || *second == '?') {
                    ++first;
                    ++second;
                }
                else {
                    first = ++start;
                    second = szPattern;
                }
            }

            if (!*second) {
#if 0
                const char* pE8Pos = strstr(szPattern, "\xE8");
                if (pE8Pos && ((pE8Pos - szPattern) < 5))
                {
                    start = start + 4 + *reinterpret_cast<DWORD*>(const_cast<char*>(start));
                }
#endif
                return const_cast<char*>(start);
            }
        }
    }
}



template <class T>
__forceinline T FindPattern(const char* szModule, const char* szPattern, const char* szName = nullptr) noexcept
{
    return reinterpret_cast<T>(FindPattern(szModule, szPattern, szName));
}

__forceinline void PlaceJMP(BYTE* bt_DetourAddress, DWORD dw_FunctionAddress, DWORD dw_Size)
{
    DWORD dw_OldProtection, dw_Distance;
    VirtualProtect(bt_DetourAddress, dw_Size, PAGE_EXECUTE_READWRITE, &dw_OldProtection);
    dw_Distance = (DWORD)(dw_FunctionAddress - (DWORD)bt_DetourAddress) - 5;
    *bt_DetourAddress = 0xE9;
    *(DWORD*)(bt_DetourAddress + 0x1) = dw_Distance;
    for (int i = 0x5; i < dw_Size; i++) *(bt_DetourAddress + i) = 0x90;
    VirtualProtect(bt_DetourAddress, dw_Size, dw_OldProtection, NULL);
    return;
}



typedef int(__stdcall* UnloadVacModuleFunc_t)(CVacModule* pModule);
DWORD WINAPI MainThread(void* handle)
{
    while (true)
    {
        if (GetAsyncKeyState(VK_NUMLOCK))
        {
            OutputDebugStringA("Removing VACTOOLS");
            MH_DisableHook(MH_ALL_HOOKS);
            MH_RemoveHook(MH_ALL_HOOKS);           
            FreeLibraryAndExitThread((HMODULE)handle, 0);
            return TRUE;
        }

        Sleep(2000);
        DWORD dwProcID = 0;
        GET_PROC_ID("Counter-Strike: Global Offensive", dwProcID);
        if (dwProcID && Globals::g_bShouldWait)
            Globals::g_bShouldWait = false;



        if (!dwProcID && WhoCares && !Globals::g_bShouldWait)
        {
            printf("[ALERT] Counter-Strike Detected Closed, Reseting.\n");
            Globals::g_bShouldWait = true;
            WhoCares = 0;
            first_ret = 0;
        }

        if (m_vecLoadedModules.size() > 0)
        {
            for (CVacModule* pModule : m_vecLoadedModules)
            {
                printf("[ALERT] Forcing Unload Of VAC Module %x...", pModule->m_CRC);
                g_BAllowSteamMemoryRead = true;
                static UnloadVacModuleFunc_t UnloadModule{ relativeToAbsolute<UnloadVacModuleFunc_t>(FindPattern<uintptr_t>("steamservice.dll", "\xE8????\x5E\x32\xC0") + 1) };
                g_BAllowSteamMemoryRead = false;
                printf("Ok\n");
                UnloadModule(pModule);  
                pModule->m_fnEntryPoint = (FARPROC)&GenericRunFunction;
            }
            m_vecLoadedModules.clear();

        }


    }
    return TRUE;
}

DWORD WINAPI InstanceThread(LPVOID);
VOID GetAnswerToRequest(LPCSTR, LPCSTR, LPDWORD);
DWORD WINAPI PipeThread(void* handle)
{
    BOOL   fConnected = FALSE;
    DWORD  dwThreadId = 0;
    HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL;
    LPCSTR lpszPipename = "\\\\.\\pipe\\vactools";

    // The main loop creates an instance of the named pipe and 
    // then waits for a client to connect to it. When the client 
    // connects, a thread is created to handle communications 
    // with that client, and this loop is free to wait for the
    // next client connect request. It is an infinite loop.
    printf("[ALERT] Starting PipeThread\n");
    for (;;)
    {
        printf("\n[INFO]  Pipe Server: Main thread awaiting client connection on %s\n", lpszPipename);
        hPipe = CreateNamedPipeA(
            lpszPipename,             // pipe name 
            PIPE_ACCESS_DUPLEX,       // read/write access 
            PIPE_TYPE_MESSAGE |       // message type pipe 
            PIPE_READMODE_MESSAGE |   // message-read mode 
            PIPE_WAIT,                // blocking mode 
            PIPE_UNLIMITED_INSTANCES, // max. instances  
            4096,                  // output buffer size 
            4096,                  // input buffer size 
            0,                        // client time-out 
            NULL);                    // default security attribute 

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            printf("[ALERT] CreateNamedPipe failed, GLE=%d.\n", GetLastError());
            return -1;
        }

        // Wait for the client to connect; if it succeeds, 
        // the function returns a nonzero value. If the function
        // returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

        fConnected = ConnectNamedPipe(hPipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (fConnected)
        {
            printf("[ALERT] Client connected, creating a processing thread.\n");

            // Create a thread for this client. 
            hThread = CreateThread(
                NULL,              // no security attribute 
                0,                 // default stack size 
                InstanceThread,    // thread proc
                (LPVOID)hPipe,    // thread parameter 
                0,                 // not suspended 
                &dwThreadId);      // returns thread ID 

            if (hThread == NULL)
            {
                printf("[ALERT] CreateThread failed, GLE=%d.\n", GetLastError());
                return -1;
            }
            else CloseHandle(hThread);
        }
        else
            // The client could not connect, so close the pipe. 
            CloseHandle(hPipe);
    }

    return 0;
}


DWORD WINAPI InstanceThread(LPVOID lpvParam)
// This routine is a thread processing function to read from and reply to a client
// via the open pipe connection passed from the main loop. Note this allows
// the main loop to continue executing, potentially creating more threads of
// of this procedure to run concurrently, depending on the number of incoming
// client connections.
{
    HANDLE hHeap = GetProcessHeap();
    LPCSTR pchRequest = (LPCSTR)HeapAlloc(hHeap, 0, 4096 * sizeof(LPCSTR));
    LPCSTR pchReply = (LPCSTR)HeapAlloc(hHeap, 0, 4096 * sizeof(LPCSTR));

    DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
    BOOL fSuccess = FALSE;
    HANDLE hPipe = NULL;

    // Do some extra error checking since the app will keep running even if this
    // thread fails.

    if (lpvParam == NULL)
    {
        printf("\nERROR - Pipe Server Failure:\n");
        printf("   InstanceThread got an unexpected NULL value in lpvParam.\n");
        printf("   InstanceThread exitting.\n");
        if (pchReply != NULL) HeapFree(hHeap, 0, (LPVOID)pchReply);
        if (pchRequest != NULL) HeapFree(hHeap, 0, (LPVOID)pchRequest);
        return (DWORD)-1;
    }

    if (pchRequest == NULL)
    {
        printf("\nERROR - Pipe Server Failure:\n");
        printf("   InstanceThread got an unexpected NULL heap allocation.\n");
        printf("   InstanceThread exitting.\n");
        if (pchReply != NULL) HeapFree(hHeap, 0, (LPVOID)pchReply);
        return (DWORD)-1;
    }

    if (pchReply == NULL)
    {
        printf("\nERROR - Pipe Server Failure:\n");
        printf("   InstanceThread got an unexpected NULL heap allocation.\n");
        printf("   InstanceThread exitting.\n");
        if (pchRequest != NULL) HeapFree(hHeap, 0, (LPVOID)pchRequest);
        return (DWORD)-1;
    }

    // Print verbose messages. In production code, this should be for debugging only.
    printf("InstanceThread created, receiving and processing messages.\n");

    // The thread's parameter is a handle to a pipe object instance. 

    hPipe = (HANDLE)lpvParam;

    // Loop until done reading
    while (1)
    {
        // Read client requests from the pipe. This simplistic code only allows messages
        // up to BUFSIZE characters in length.
        fSuccess = ReadFile(
            hPipe,        // handle to pipe 
            (LPVOID)pchRequest,    // buffer to receive data 
            4096 * sizeof(TCHAR), // size of buffer 
            &cbBytesRead, // number of bytes read 
            NULL);        // not overlapped I/O 

        if (!fSuccess || cbBytesRead == 0)
        {
            if (GetLastError() == ERROR_BROKEN_PIPE)
            {
                printf("InstanceThread: client disconnected.\n");
            }
            else
            {
                printf("InstanceThread ReadFile failed, GLE=%d.\n", GetLastError());
            }
            break;
        }

        // Process the incoming message.
        GetAnswerToRequest(pchRequest, pchReply, &cbReplyBytes);

        // Write the reply to the pipe. 
        fSuccess = WriteFile(
            hPipe,        // handle to pipe 
            pchReply,     // buffer to write from 
            cbReplyBytes, // number of bytes to write 
            &cbWritten,   // number of bytes written 
            NULL);        // not overlapped I/O 

        if (!fSuccess || cbReplyBytes != cbWritten)
        {
            printf("InstanceThread WriteFile failed, GLE=%d.\n", GetLastError());
            break;
        }
    }

    // Flush the pipe to allow the client to read the pipe's contents 
    // before disconnecting. Then disconnect the pipe, and close the 
    // handle to this pipe instance. 

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    HeapFree(hHeap, 0, (LPVOID)pchRequest);
    HeapFree(hHeap, 0, (LPVOID)pchReply);

    printf("InstanceThread exiting.\n");
    return 1;
}

VOID GetAnswerToRequest(LPCSTR pchRequest,
    LPCSTR pchReply,
    LPDWORD pchBytes)
    // This routine is a simple function to print the client request to the console
    // and populate the reply buffer with a default data string. This is where you
    // would put the actual client request processing code that runs in the context
    // of an instance thread. Keep in mind the main thread will continue to wait for
    // and receive other client connections while the instance thread is working.
{
    if (strstr(pchRequest, "INJ"))
    {
        printf("[ALERT] VacTools Has Recieved An InjectionRequest\n");
        int nPathSize = strlen(pchRequest + 4);
        if (!nPathSize || nPathSize > 512)
        {
            printf("[ERROR] Invalid Path\n");
            return;
        }

        std::ifstream File(pchRequest + 4, std::ios::in | std::ios::out);
        CVacModule InjectionModule;

        File.seekg(0, File.end);
        InjectionModule.m_dwModuleSize = File.tellg();
        File.seekg(0, File.beg);

        InjectionModule.m_pRawModule = (char*)malloc(InjectionModule.m_dwModuleSize);
        InjectionModule.m_CRC = (LPVOID)0x6969;
        File.read((char*)InjectionModule.m_pRawModule, InjectionModule.m_dwModuleSize);
        hk_LoadVacModule(&InjectionModule, 0x2);
        free(InjectionModule.m_pRawModule);

        printf("[ALERT] Injected User Supplied DLL %s\n", pchRequest + 3);
    }

    pchReply = "OK";

    *pchBytes = (strlen(pchReply) + 1) * sizeof(TCHAR);
}

void InitializeHooks()
{
    MH_Initialize();

    LPVOID LoadVacModuleAddr = relativeToAbsolute<LPVOID>(FindPattern<uintptr_t>("steamservice.dll", "\xE8????\x84\xC0\x75\x16\x8B\x43\x10") + 1);
    MH_CreateHook(LoadVacModuleAddr, &hk_LoadVacModule, &oLoadVacModule);

    LPVOID WriteVacModuleToDiskAddr = relativeToAbsolute<LPVOID>(FindPattern<uintptr_t>("steamservice.dll", "\xE8????\x84\xC0\x75\x16\x8B\x43\x10") + 1);
    MH_CreateHook(WriteVacModuleToDiskAddr, &hk_WriteVacModuleToDisk, &oWriteVacModuleToDisk);

    MH_CreateHook(GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadProcessMemory"), &hk_ReadProcessMemory, &oReadProcessMemory);
    MH_CreateHook(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory"), &hk_NtReadVirtualMemory, &oNtReadVirtualMemory);


    MH_EnableHook(MH_ALL_HOOKS);
}

void InitVacTools(HMODULE hModule)
{



   const char* ENLOGO = {
      "                                     ,,                                       \n"
      "                                   ,,,,,,                                     \n"
      "                                ,,,      ,,,                                  \n"
      "                              ,,,          ,,,                                \n"
      "                           ,,,          .,,,                                  \n"
      "                         ,,,          ,,,        ,,                           \n"
      "                      ,,,           ,,,       ,,, ,,,                         \n"
      "                    ,,,          ,,,        ,,,      ,,,                      \n"
      "                 ,,,           ,,,       ,,,           ,,,                    \n"
      "               ,,,          ,,,        ,,,          ,,,                       \n"
      "            ,,,           ,,,       ,,,           ,,,       ,,,               \n"
      "          ,,,  ,,,          .,,,  ,,,          ,,,        ,,,  ,,,            \n"
      "       ,,,.,,,                 ,,,           ,,,       ,,,       ,,,          \n"
      "      ,,,                                 ,,,        ,,,          ,,,         \n"
      "         ,,                   &%&&      ,,,       ,,,           ,,,           \n"
      "                /%.(%&(    &%&&&@&&   .,,,      ,,,          ,,,              \n"
      "               &&#(/% /%   %*&&&         ,,, ,,,           ,,,                \n"
      "                 # .                       ,,,          ,,,                   \n"
      "                       ,                              ,,,                     \n"
      "                      #.       *&                  ,,,.                       \n"
      "                      *   #&@% (%                ,,,                          \n"
      "                      ,    .#&/.       ,,,.   ,,,,                            \n"
      "                                     ,,,,.  ,,,                               \n"
      "                                  ,,, ,, ,,,,                                 \n"
      "                                 .,  ,,,,,                                    \n"
      "                                    ,,,,                                      \n"
      "\n"
    };
         
    printf(ENLOGO);
    printf("--------------  Enron's VacTools & VacDisabler v0.1  --------------\n");
    Sleep(500);
    printf("Initializing....\n");
    printf("Installing Hooks...");
    InitializeHooks();
    printf("Okay\n");
    printf("Creating Main Thread...");
    CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
    printf("Ok\n");
    printf("Creating Pipe Thread...");
    CreateThread(nullptr, 0, PipeThread, hModule, 0, nullptr);
    printf("Ok\n");


}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    g_hThisMoudle = hModule;
    //OutputDebugStringA("IS THERE ANYBODY OUT THERE???");
    int i = 0;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        FILE* fDummy;
        freopen_s(&fDummy, "CONOUT$", "w", stdout);
        freopen_s(&fDummy, "CONOUT$", "w", stderr);
        freopen_s(&fDummy, "CONIN$", "r", stdin);
        InitVacTools(hModule);
        printf("VacTools Loaded!\n");        
    case DLL_THREAD_ATTACH:
        i = i / i;
        break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

