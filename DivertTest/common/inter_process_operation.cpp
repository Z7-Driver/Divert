
#include "common/common_head.h"
#include "log/blog.h"
#include "inter_process_operation.h"
#include <sysinfoapi.h>
#include <FunctionHelper.h>
#include <common/common.h>
namespace common
{
    namespace inter_process
    {
        bool CloseHandleWithProcess(HANDLE process_handle, HANDLE handle_obj)
        {
            bool ret = false;
            HANDLE duplicate_handle_obj = NULL;
            do
            {
                if (process_handle) {
                    ret = true;
                    DuplicateHandle(process_handle, handle_obj, GetCurrentProcess(), &duplicate_handle_obj, DUPLICATE_SAME_ACCESS, FALSE, DUPLICATE_CLOSE_SOURCE);
                }
            } while (false);
            if (duplicate_handle_obj)
            {
                CloseHandle(duplicate_handle_obj);
                duplicate_handle_obj = NULL;
            }
            CloseHandle(handle_obj);
            return ret;
        }
        static bool is_64bit_os_ = common::system::isWin64();
        bool GetTargetBaseAddress(HANDLE process_handle, const std::wstring& path,std::vector<uint64_t>& file_map_base_vec)
        {
            BOOL target_wow_64 = FALSE;
            IsWow64Process(process_handle, &target_wow_64);

            // Windows 32bit limit: 0xFFFFFFFF.
            // Windows 64bit limit: 0x7FFFFFFFFFF.
            unsigned long long maxAddress = (is_64bit_os_ && !target_wow_64) ? 0x80000000000 : 0x100000000;
            MEMORY_BASIC_INFORMATION mbi = { 0 }, mbiLast = { 0 };
            for (unsigned long long address = 0; address < maxAddress; address += mbi.RegionSize) {
                if (!VirtualQueryEx(process_handle, (void*)address, &mbi, sizeof(mbi))) break;
                if ((unsigned long long)mbi.AllocationBase + mbi.RegionSize > maxAddress) break;

                if (mbi.Type == MEM_MAPPED) {
                    if (mbiLast.AllocationBase != mbi.AllocationBase) {
                        WCHAR filemap_path[MAX_PATH] = {0};
                        if (0 != GetMappedFileNameW(process_handle, mbi.BaseAddress, filemap_path, MAX_PATH))
                        {
                            std::wstring dosformat_path = L"";
                            common::path::DevicePathToDosPath(filemap_path, dosformat_path);
                            if (_wcsicmp(dosformat_path.c_str(), path.c_str()) == 0)
                            {
                                file_map_base_vec.push_back((uint64_t)mbi.BaseAddress);
                            }
                        }
                        
                    }
                    mbiLast = mbi;
                }
            }
            return file_map_base_vec.size();
        }
        bool RemoteUnmapViewOfFile(HANDLE hProcess, LPVOID lpBaseAddress)
        {
            static HMODULE hKernel32 = LoadLibrary(L"kernel32.dll");
            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "UnmapViewOfFile"), lpBaseAddress, 0, NULL);
            if (!hThread) return FALSE;
            WaitForSingleObject(hThread, 1000);
            DWORD dwRet = 0;
            GetExitCodeThread(hThread, &dwRet);
            CloseHandle(hThread);
            return (dwRet == ERROR_SUCCESS);
        }
        bool CloseFileMapWithProcess(HANDLE process_handle, const std::wstring& path)
        {
            bool ret = false;
            do
            {
                std::vector<uint64_t> file_map_base_vec;
                if (!GetTargetBaseAddress(process_handle, path, file_map_base_vec))
                {
                    break;
                }
                for (auto file_base_address : file_map_base_vec)
                {
                    if (!RemoteUnmapViewOfFile(process_handle, (LPVOID*)file_base_address))
                    {
                        BLOGW(ERRORB) << L"remote unmap file fail,path:"<< path;
                    }
                }
            } while (false);
            return ret;
        }
        bool FreelibraryWithProcess_x64(HANDLE process_handle, uint64_t module_baseaddress)
        {
            return false;
        }
        bool FreelibraryWithProcess_x86(HANDLE process_handle,  uint64_t module_baseaddress)
        {
            static HMODULE hNtDll = LoadLibrary(L"ntdll.dll");
            bool ret = false;
            HANDLE thread_handle = nullptr;
            do
            {
                thread_handle = CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hNtDll, "LdrUnloadDll"), (LPVOID)module_baseaddress, 0, NULL);
                if (thread_handle == nullptr) 
                {
                    BLOGW(ERRORB) << L"CreateRemoteThread fail,errcode:" << GetLastError();
                    break;
                }
                WaitForSingleObject(thread_handle, 1000);
                DWORD thread_ret = 0;
                GetExitCodeThread(thread_handle, &thread_ret);
                ret = (thread_ret == ERROR_SUCCESS);
            } while (false);

            return ret;
        }
    }
}