#pragma once
namespace common 
{
    namespace inter_process
    {
        //需要进程权限PROCESS_DUP_HANDLE
        bool CloseHandleWithProcess(HANDLE process_handle, HANDLE handle_obj);
        //需要进程权限PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION
        bool CloseFileMapWithProcess(HANDLE process_handle, const std::wstring& path);
        
        bool FreelibraryWithProcess_x86(HANDLE process_handle, uint64_t module_baseaddress);

        bool FreelibraryWithProcess_x64(HANDLE process_handle, uint64_t module_baseaddress);
    }
}