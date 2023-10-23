#include <windows.h>
#include <winternl.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef __kernel_entry NTSTATUS(*NtQueryInformationProcessType)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);


DWORD SpawnWithSpoofedArgs(
    CONST PWCHAR Exe, 
    CONST PWCHAR FakeArgs, 
    CONST PWCHAR RealArgs,
    PHANDLE OutHandle)
{
    BOOL                OK                  = FALSE;
    DWORD               Status              = NULL;
    SIZE_T              BytesRead           = NULL;
    SIZE_T              BytesWritten        = NULL;
    SIZE_T              NewArgLen           = NULL;
    SIZE_T              OldArgLen           = NULL;
    HANDLE              hProcess            = NULL;
    HMODULE             NtdllBase           = NULL;
    PWCHAR              NewArgs             = NULL;
    PEB                 LocalPeb            = { NULL };
    STARTUPINFOW        StartupInfo         = { NULL };
    PROCESS_INFORMATION ProcessInfo         = { NULL };
    
    PWCHAR              OriginalBufferAddr  = NULL;
    PUNICODE_STRING     OriginalCommandLine = NULL;
    PUNICODE_STRING     NewCommandLine      = NULL;

    PRTL_USER_PROCESS_PARAMETERS    OriginalProcessParamsAddr   = NULL;
    RTL_USER_PROCESS_PARAMETERS     LocalProcessParameters      = { NULL };
    NtQueryInformationProcessType   pNtQueryInformationProcess  = NULL;
    PRTL_USER_PROCESS_PARAMETERS    ProcessParameters           = NULL;
    PROCESS_BASIC_INFORMATION       ProcessBasicInfo            = { NULL };

    if (!Exe || !FakeArgs || !RealArgs) return ERROR_INVALID_PARAMETER;

    // Resolve NT API
    NtdllBase = GetModuleHandleA("ntdll");
    if (!NtdllBase) return ERROR_NOT_FOUND;

    pNtQueryInformationProcess = (NtQueryInformationProcessType)GetProcAddress(
        NtdllBase, 
        "NtQueryInformationProcess"
    );

    if (!pNtQueryInformationProcess)
    {
        CloseHandle(ProcessInfo.hProcess);
        return ERROR_NOT_FOUND;
    };

    // Create suspended process
    OK = CreateProcessW(
        Exe,
        FakeArgs,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &StartupInfo,
        &ProcessInfo
    );

    if (!OK) return GetLastError();

    // Get PEB address

    Status = pNtQueryInformationProcess(
        ProcessInfo.hProcess,
        (PROCESSINFOCLASS)0,
        &ProcessBasicInfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );

    if (!NT_SUCCESS(Status))
    {
        CloseHandle(ProcessInfo.hProcess);
        return ERROR_INVALID_PARAMETER;
    };

    if (!ProcessBasicInfo.PebBaseAddress) return ERROR_NOT_FOUND;

    // Read the original PEB
    OK = ReadProcessMemory(
        ProcessInfo.hProcess,
        ProcessBasicInfo.PebBaseAddress,
        &LocalPeb,
        sizeof(LocalPeb),
        &BytesRead
    );

    if (!OK)
    {
        CloseHandle(ProcessInfo.hProcess);
        return GetLastError();
    }
    else if (BytesRead == 0)
    {
        CloseHandle(ProcessInfo.hProcess);
        return ERROR_READ_FAULT;
    };

    BytesRead = 0;
    OriginalProcessParamsAddr = LocalPeb.ProcessParameters;

    // Read the original process parameters
    OK = ReadProcessMemory(
        ProcessInfo.hProcess,
        OriginalProcessParamsAddr,
        &LocalProcessParameters,
        sizeof(RTL_USER_PROCESS_PARAMETERS),
        &BytesRead
    );

    if (!OK)
    {
        CloseHandle(ProcessInfo.hProcess);
        return GetLastError();
    }
    else if (BytesRead == 0)
    {
        CloseHandle(ProcessInfo.hProcess);
        return ERROR_READ_FAULT;
    };

    // If new args fit in old args, just overwrite
    OldArgLen = LocalProcessParameters.CommandLine.MaximumLength;
    NewArgLen = wcslen(RealArgs) * sizeof(WCHAR);

    if (NewArgLen > OldArgLen)
    {
        // Allocate new buffers
        NewArgs = (PWCHAR)VirtualAllocEx(
            ProcessInfo.hProcess,
            NULL,
            NewArgLen + 0xF,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!NewArgs)
        {
            CloseHandle(ProcessInfo.hProcess);
            return GetLastError();
        }

        NewCommandLine = (PUNICODE_STRING)VirtualAllocEx(
            ProcessInfo.hProcess,
            NULL,
            sizeof(UNICODE_STRING),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!NewCommandLine)
        {
            CloseHandle(ProcessInfo.hProcess);
            return GetLastError();
        }

        WriteProcessMemory(
            ProcessInfo.hProcess,
            LocalProcessParameters.CommandLine.Buffer,
            RealArgs,
            NewArgLen,
            &BytesWritten
        );

        if (!OK)
        {
            CloseHandle(ProcessInfo.hProcess);
            return GetLastError();
        }
        else if (BytesWritten == 0)
        {
            CloseHandle(ProcessInfo.hProcess);
            return ERROR_WRITE_FAULT;
        };


        // Write the new size
        WriteProcessMemory(
            ProcessInfo.hProcess,
            (PVOID)LocalProcessParameters.CommandLine.Length,
            &NewArgLen,
            sizeof(USHORT),
            &BytesWritten
        );

        if (!OK)
        {
            CloseHandle(ProcessInfo.hProcess);
            return GetLastError();
        }
        else if (BytesWritten == 0)
        {
            CloseHandle(ProcessInfo.hProcess);
            return ERROR_WRITE_FAULT;
        };

        // Write the new max size
        NewArgLen += 0xF;
        WriteProcessMemory(
            ProcessInfo.hProcess,
            (PVOID)LocalProcessParameters.CommandLine.MaximumLength,
            &NewArgLen,
            sizeof(USHORT),
            &BytesWritten
        );

        if (!OK)
        {
            CloseHandle(ProcessInfo.hProcess);
            return GetLastError();
        }
        else if (BytesWritten == 0)
        {
            CloseHandle(ProcessInfo.hProcess);
            return ERROR_WRITE_FAULT;
        };
    }
    else
    {
        OK = ReadProcessMemory(
            ProcessInfo.hProcess,
            (PVOID)LocalProcessParameters.CommandLine.Buffer,
            OriginalBufferAddr,
            sizeof(PVOID),
            &BytesRead
        );

        if (!OK)
        {
            CloseHandle(ProcessInfo.hProcess);
            return GetLastError();
        }
        else if (BytesRead == 0)
        {
            CloseHandle(ProcessInfo.hProcess);
            return ERROR_READ_FAULT;
        };

        WriteProcessMemory(
            ProcessInfo.hProcess,
            OriginalProcessParamsAddr->CommandLine.Buffer,
            RealArgs,
            NewArgLen,
            &BytesWritten
        );

        if (!OK)
        {
            CloseHandle(ProcessInfo.hProcess);
            return GetLastError();
        }
        else if (BytesWritten == 0)
        {
            CloseHandle(ProcessInfo.hProcess);
            return ERROR_WRITE_FAULT;
        };

    }

    Status = ResumeThread(ProcessInfo.hThread);
    if (Status == (DWORD)-1)
    {
        CloseHandle(ProcessInfo.hProcess);
        return GetLastError();
    }

    *OutHandle = ProcessInfo.hProcess;
    return ERROR_SUCCESS;
}


INT main()
{
    DWORD   Status      = NULL;
    HANDLE  hProcess    = NULL;

    Status = SpawnWithSpoofedArgs(
        (CONST PWCHAR)L"C:\\Windows\\System32\\cmd.exe",
        (CONST PWCHAR)L"Spoofed",
        (CONST PWCHAR)L"notepad.exe\0\0",
        &hProcess
    );

    TerminateProcess(hProcess, ERROR_SUCCESS);

    return Status;
}

