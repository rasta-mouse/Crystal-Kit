setup.x64:
    load "bin/spoof.x64.o"
        merge

    load "bin/spoof.x64.bin"
        linkfunc "spoofStub"

    load "bin/spoof_hooks.x64.o"
        merge

    attach "KERNEL32$LoadLibraryA"   "_LoadLibraryA_Spoof"
    attach "KERNEL32$VirtualAlloc"   "_VirtualAlloc_Spoof"
    attach "KERNEL32$VirtualProtect" "_VirtualProtect_Spoof"
    attach "KERNEL32$VirtualFree"    "_VirtualFree_Spoof"

hooks.x64:
    load "bin/spoof.x64.o"
        merge

    load "bin/spoof.x64.bin"
        linkfunc "spoofStub"

    load "bin/spoof_hooks.x64.o"
        merge

    addhook "ADVAPI32$AdjustTokenPrivileges"
    attach  "ADVAPI32$AdjustTokenPrivileges" "_AdjustTokenPrivileges_Spoof"

    addhook "ADVAPI32$DuplicateTokenEx"
    attach  "ADVAPI32$DuplicateTokenEx" "_DuplicateTokenEx_Spoof"

    addhook "ADVAPI32$ImpersonateLoggedOnUser"
    attach  "ADVAPI32$ImpersonateLoggedOnUser" "_ImpersonateLoggedOnUser_Spoof"
    
    addhook "ADVAPI32$ImpersonateNamedPipeClient"
    attach  "ADVAPI32$ImpersonateNamedPipeClient" "_ImpersonateNamedPipeClient_Spoof"

    addhook "ADVAPI32$LogonUserA"
    attach  "ADVAPI32$LogonUserA" "_LogonUserA_Spoof"

    addhook "ADVAPI32$OpenProcessToken"
    attach  "ADVAPI32$OpenProcessToken" "_OpenProcessToken_Spoof"

    addhook "ADVAPI32$OpenThreadToken"
    attach  "ADVAPI32$OpenThreadToken" "_OpenThreadToken_Spoof"
    
    addhook "KERNEL32$CloseHandle"
    attach  "KERNEL32$CloseHandle" "_CloseHandle_Spoof"

    addhook "KERNEL32$ConnectNamedPipe"
    attach  "KERNEL32$ConnectNamedPipe" "_ConnectNamedPipe_Spoof"
    
    addhook "KERNEL32$CreateFileMappingA"
    attach  "KERNEL32$CreateFileMappingA" "_CreateFileMappingA_Spoof"
    
    addhook "KERNEL32$CreatePipe"
    attach  "KERNEL32$CreatePipe" "_CreatePipe_Spoof"
    
    addhook "KERNEL32$CreateNamedPipeA"
    attach  "KERNEL32$CreateNamedPipeA" "_CreateNamedPipeA_Spoof"
    
    addhook "KERNEL32$CreateProcessA"
    attach  "KERNEL32$CreateProcessA" "_CreateProcessA_Spoof"
    
    addhook "KERNEL32$CreateRemoteThread"
    attach  "KERNEL32$CreateRemoteThread" "_CreateRemoteThread_Spoof"
    
    addhook "KERNEL32$CreateThread"
    attach  "KERNEL32$CreateThread" "_CreateThread_Spoof"
    
    addhook "KERNEL32$CreateToolhelp32Snapshot"
    attach  "KERNEL32$CreateToolhelp32Snapshot" "_CreateToolhelp32Snapshot_Spoof"
    
    addhook "KERNEL32$DisconnectNamedPipe"
    attach  "KERNEL32$DisconnectNamedPipe" "_DisconnectNamedPipe_Spoof"
    
    addhook "KERNEL32$DuplicateHandle"
    attach  "KERNEL32$DuplicateHandle" "_DuplicateHandle_Spoof"
    
    addhook "KERNEL32$ExitThread"
    attach  "KERNEL32$ExitThread" "_ExitThread_Spoof"
    
    addhook "KERNEL32$ExitProcess"
    attach  "KERNEL32$ExitProcess" "_ExitProcess_Spoof"
    
    addhook "KERNEL32$GetThreadContext"
    attach  "KERNEL32$GetThreadContext" "_GetThreadContext_Spoof"
    
    addhook "KERNEL32$LoadLibraryA"
    attach  "KERNEL32$LoadLibraryA" "_LoadLibraryA_Spoof"
    
    addhook "KERNEL32$LoadLibraryW"
    attach  "KERNEL32$LoadLibraryW" "_LoadLibraryW_Spoof"

    addhook "KERNEL32$LoadLibraryExW"
    attach  "KERNEL32$LoadLibraryExW" "_LoadLibraryExW_Spoof"

    addhook "KERNEL32$MapViewOfFile"
    attach  "KERNEL32$MapViewOfFile" "_MapViewOfFile_Spoof"
    
    addhook "KERNEL32$OpenProcess"
    attach  "KERNEL32$OpenProcess" "_OpenProcess_Spoof"
    
    addhook "KERNEL32$OpenThread"
    attach  "KERNEL32$OpenThread" "_OpenThread_Spoof"
    
    addhook "KERNEL32$PeekNamedPipe"
    attach  "KERNEL32$PeekNamedPipe" "_PeekNamedPipe_Spoof"
    
    addhook "KERNEL32$ReadProcessMemory"
    attach  "KERNEL32$ReadProcessMemory" "_ReadProcessMemory_Spoof"
    
    addhook "KERNEL32$ResumeThread"
    attach  "KERNEL32$ResumeThread" "_ResumeThread_Spoof"
    
    addhook "KERNEL32$SetThreadContext"
    attach  "KERNEL32$SetThreadContext" "_SetThreadContext_Spoof"
    
    addhook "KERNEL32$Sleep"
    attach  "KERNEL32$Sleep" "_Sleep_Spoof"
    
    addhook "KERNEL32$UnmapViewOfFile"
    attach  "KERNEL32$UnmapViewOfFile" "_UnmapViewOfFile_Spoof"
    
    addhook "KERNEL32$VirtualAlloc"
    attach  "KERNEL32$VirtualAlloc" "_VirtualAlloc_Spoof"
    
    addhook "KERNEL32$VirtualAllocEx"
    attach  "KERNEL32$VirtualAllocEx" "_VirtualAllocEx_Spoof"
    
    addhook "KERNEL32$VirtualFree"
    attach  "KERNEL32$VirtualFree" "_VirtualFree_Spoof"
    
    addhook "KERNEL32$VirtualProtect"
    attach  "KERNEL32$VirtualProtect" "_VirtualProtect_Spoof"
    
    addhook "KERNEL32$VirtualProtectEx"
    attach  "KERNEL32$VirtualProtectEx" "_VirtualProtectEx_Spoof"
    
    addhook "KERNEL32$VirtualQuery"
    attach  "KERNEL32$VirtualQuery" "_VirtualQuery_Spoof"
    
    addhook "KERNEL32$WaitNamedPipeA"
    attach  "KERNEL32$WaitNamedPipeA" "_WaitNamedPipeA_Spoof"
    
    addhook "KERNEL32$WriteProcessMemory"
    attach  "KERNEL32$WriteProcessMemory" "_WriteProcessMemory_Spoof"

    addhook "MSCOREE$CLRCreateInstance"
    attach "MSCOREE$CLRCreateInstance" "_CLRCreateInstance_Spoof"
    
    addhook "OLE32$CoCreateInstance"
    attach  "OLE32$CoCreateInstance" "_CoCreateInstance_Spoof"
    
    addhook "WININET$HttpOpenRequestA"
    attach  "WININET$HttpOpenRequestA" "_HttpOpenRequestA_Spoof"
    
    addhook "WININET$HttpSendRequestA"
    attach  "WININET$HttpSendRequestA" "_HttpSendRequestA_Spoof"
    
    addhook "WININET$InternetConnectA"
    attach  "WININET$InternetConnectA" "_InternetConnectA_Spoof"
    
    addhook "WININET$InternetOpenA"
    attach  "WININET$InternetOpenA" "_InternetOpenA_Spoof"
    
    addhook "WS2_32$WSARecv"
    attach  "WS2_32$WSARecv" "_WSARecv_Spoof"
    
    addhook "WS2_32$WSASend"
    attach  "WS2_32$WSASend" "_WSASend_Spoof"
    
    addhook "WS2_32$WSAStartup"
    attach  "WS2_32$WSAStartup" "_WSAStartup_Spoof"
    
    addhook "WS2_32$WSASocketA"    
    attach  "WS2_32$WSASocketA" "_WSASocketA_Spoof"
