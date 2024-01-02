#include "common.h"
#include <common/win_crypto.h>
#include <log/blog_manager.h>
namespace common {

    namespace log
    {
        bool init_log(const wchar_t* base_log_name, bool file_enable, bool console_enable)
        {
            //初始化日志库
            wchar_t log_path[MAX_PATH] = {};
            GetModuleFileName(nullptr, log_path, MAX_PATH);
            PathRemoveFileSpec(log_path);
            PathAppend(log_path, L"\\logs");
            CreateDirectoryW(log_path, nullptr);
            blog::BlogOption log_option = {};
            log_option.File.flush_interval = 10; //seconds
            log_option.File.max_log_file_size = 10 * 1024 * 1024; //bytes
            log_option.File.max_log_file_count = 3;
            log_option.File.base_dir = log_path;
            log_option.File.log_file_ext = L"log";
            log_option.File.enable = file_enable;


            //#if defined(_DEBUG)
            log_option.File.print_to_memory = true;
            log_option.File.min_log_level = INT_MAX;
            //#else
            //            log_option.File.print_to_memory = false;
            //            log_option.File.min_log_level = 10;
            //#endif

            log_option.File.base_name = base_log_name;
            log_option.Console.enable = console_enable;
            blog::BLogManager::UpdateBlogOption(log_option);

            return true;
        }
    }
    namespace process
    {
        DWORD ThreadIdToProcessId(DWORD thread_id)
        {
            DWORD process_id = -1;
            HANDLE hThread = (::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, thread_id));
            if (hThread) {
                process_id = ::GetProcessIdOfThread(hThread);
                CloseHandle(hThread);
            }
            return process_id;
        }
        bool IsX86Process(uint32_t process_id)
        {
            bool ret = false;
            if (common::system::isWin64())
            {
                BOOL  wowTgt = FALSE;
                HANDLE process_handle = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process_id);
                if (process_handle)
                {
                    IsWow64Process(process_handle, &wowTgt);
                    if (wowTgt)
                    {
                        ret = true;
                    }
                    CloseHandle(process_handle);
                }

            }
            else
            {
                ret = true;
            }
            return ret;
        }
        bool TerminateProcessByPid(uint32_t process_id)
        {
            HANDLE process_handle = OpenProcess(PROCESS_TERMINATE, FALSE, process_id);
            if (process_handle != nullptr)
            {
                TerminateProcess(process_handle, 1);
                return true;
            }
            return false;
        }
        std::wstring GetProcessPathFromPid(uint32_t process_id)
        {
            HANDLE process_handle = NULL;
            wchar_t file_name[MAX_PATH + 1] = { 0 };
            std::wstring process_path;
            process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
            if (process_handle != NULL) {
                if (GetModuleFileNameExW(process_handle, NULL, file_name, MAX_PATH) > 0) {
                    process_path = file_name;
                }
                CloseHandle(process_handle);
            }
            return process_path;
        }

    }
    namespace file
    {

        bool ForceDeleteFile(const wchar_t* path)
        {

            WCHAR szTmpName[MAX_PATH] = { 0 };
            DWORD dwAtrrib = GetFileAttributes(path);

            if (dwAtrrib == INVALID_FILE_ATTRIBUTES)
            {
                dwAtrrib = FILE_ATTRIBUTE_NORMAL;
            }

            dwAtrrib &= ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);
            SetFileAttributes(path, dwAtrrib);
            srand(static_cast<unsigned int>(time(0)));

            BOOL bRet = DeleteFile(path);
            if (!bRet)
            {
                std::wstring szTmpName = L"";
                szTmpName = common::string::wstrFormat(L"%s.%03d", path, rand() % 1000);
                MoveFileEx(path, szTmpName.c_str(), MOVEFILE_REPLACE_EXISTING);
                MoveFileEx(szTmpName.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
            }
            return bRet;
        }
        bool DirectoryPathIsExist(const wchar_t* path)
        {
            WIN32_FIND_DATA  wfd;
            bool  ret = false;
            HANDLE find_handle = FindFirstFile(path, &wfd);
            if ((find_handle != INVALID_HANDLE_VALUE) && (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                ret = true;
            }
            FindClose(find_handle);
            return ret;
        }
        bool DeleteDirectoryLoop(const wchar_t* dir, bool single_layer)
        {
            uint32_t dir_length = wcsnlen_s(dir, MAX_PATH);
            if (dir[dir_length - 1] == L'\\')
            {
                dir_length--;
            }
            std::wstring orginal_path(dir, dir_length);
            std::wstring find_formatName = orginal_path;

            find_formatName += L"\\*";
            WIN32_FIND_DATA findFileData = {};
            HANDLE hFind = FindFirstFileW(find_formatName.c_str(), &findFileData);
            if (INVALID_HANDLE_VALUE == hFind)
            {
                return true;
            }
            while (true)
            {
                if (findFileData.cFileName[0] != L'.')
                {
                    std::wstring path = orginal_path;
                    path += L"\\";
                    path += findFileData.cFileName;
                    if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    {
                        if (!single_layer)
                        {
                            DeleteDirectoryLoop(path.c_str(), single_layer);
                        }
                        else
                        {
                            ::RemoveDirectory(path.c_str());
                        }


                    }
                    else
                    {
                        DWORD dwAtrrib = GetFileAttributes(path.c_str());

                        if (dwAtrrib == INVALID_FILE_ATTRIBUTES)
                        {
                            dwAtrrib = FILE_ATTRIBUTE_NORMAL;
                        }

                        dwAtrrib &= ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);
                        SetFileAttributes(path.c_str(), dwAtrrib);
                        DeleteFile(path.c_str());
                    }
                }
                if (!FindNextFile(hFind, &findFileData))
                {
                    break;
                }
            }
            ::FindClose(hFind);
            ::RemoveDirectory(dir);
            return !DirectoryPathIsExist(dir);
        }
        bool CreateNewFile(const wchar_t* path)
        {

            wchar_t directory_path[MAX_PATH] = { 0 };
            uint32_t directory_path_len = wcsnlen_s(path, MAX_PATH);
            for (uint32_t i = 0; i < directory_path_len; ++i)
            {
                directory_path[i] = path[i];
                if (directory_path[i] == L'\\' || directory_path[i] == L'/')
                {
                    if (!DirectoryPathIsExist(directory_path))
                    {
                        CreateDirectory(directory_path, NULL);
                    }
                }
            }
            if (PathFileExists(path))
            {
                ForceDeleteFile(path);
            }
            HANDLE file_handle = CreateFileW(path, FILE_GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

            if (file_handle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(file_handle);
                return true;
            }
            return false;
        }
        uint64_t GetFileSize(const wchar_t* path)
        {
            uint64_t ret = 0;
            HANDLE hFile = CreateFile(path, FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (INVALID_HANDLE_VALUE != hFile)
            {
                LARGE_INTEGER file_size = { 0 };
                ::GetFileSizeEx(hFile, &file_size);
                ret = file_size.QuadPart;
                CloseHandle(hFile);
            }
            return ret;
        }
        bool ReadFileData(const wchar_t* path, std::string& data)
        {
#define DEFAULT_FILE_MAXSIZE	(100*1024*1024)
            bool bRet = false;;
            HANDLE hFile = CreateFile(path, FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (INVALID_HANDLE_VALUE != hFile)
            {
                DWORD dwFileSize = ::GetFileSize(hFile, NULL);
                if (dwFileSize > 0 &&
                    dwFileSize < DEFAULT_FILE_MAXSIZE)		// 不支持大于10M的文件读取
                {
                    data.resize(dwFileSize, 0);

                    DWORD dwReadBytes = 0;
                    if (ReadFile(hFile, (char*)data.data(), dwFileSize, &dwReadBytes, NULL) &&
                        dwReadBytes == dwFileSize)
                    {
                        bRet = true;
                    }

                }

                CloseHandle(hFile);
            }
            return bRet;
        }
        bool WriteFileData(const wchar_t* path, const std::string& data)
        {
            if (!PathFileExists(path))
            {
                common::file::CreateNewFile(path);
                if (!PathFileExists(path))
                {
                    return false;
                }
            }

            bool bRet = false;;
            HANDLE file_hanle = CreateFile(path, FILE_GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (INVALID_HANDLE_VALUE != file_hanle)
            {
                bRet = true;
                DWORD dwFileSize = ::GetFileSize(file_hanle, NULL);
                SetFilePointer(file_hanle, dwFileSize, nullptr, FILE_BEGIN);
                DWORD wait_write_data_len = data.length();
                const char* data_ptr = data.c_str();
                DWORD have_write_data_len = 0;
                while (wait_write_data_len > 0)
                {
                    DWORD write_len = 0;
                    WriteFile(file_hanle, (LPCVOID) & (data_ptr[have_write_data_len]), wait_write_data_len, &write_len, NULL);
                    if (write_len == 0)
                    {
                        bRet = false;
                        break;
                    }
                    have_write_data_len += write_len;
                    if (wait_write_data_len > write_len)
                    {
                        wait_write_data_len -= write_len;
                    }
                    else
                    {
                        wait_write_data_len = 0;
                    }
                }
                CloseHandle(file_hanle);
            }
            return bRet;

        }
        bool EnumFiles(const wchar_t* input_directory, const wchar_t* file_format, bool is_query_single_layer, std::vector<std::wstring>& vecFiles)
        {
            uint32_t dir_length = wcsnlen_s(input_directory, MAX_PATH);
            if (input_directory[dir_length - 1] == L'\\')
            {
                dir_length--;
            }
            std::wstring orginal_path(input_directory, dir_length);
            std::wstring find_formatName = orginal_path;

            if (file_format)
            {
                find_formatName += L"\\*.";
                find_formatName += file_format;
            }
            else
            {
                find_formatName += L"\\*";
            }
            WIN32_FIND_DATA findFileData = {};
            HANDLE hFind = FindFirstFileW(find_formatName.c_str(), &findFileData);
            if (INVALID_HANDLE_VALUE == hFind)
            {
                return false;
            }
            while (true)
            {
                if (findFileData.cFileName[0] != L'.')
                {
                    std::wstring path = orginal_path;
                    path += L"\\";
                    path += findFileData.cFileName;
                    if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    {
                        if (!is_query_single_layer)
                        {
                            EnumFiles(path.c_str(), file_format, is_query_single_layer, vecFiles);
                        }
                    }
                    else
                    {
                        vecFiles.push_back(path);
                    }
                }
                if (!FindNextFile(hFind, &findFileData))
                {
                    break;
                }
            }
            ::FindClose(hFind);
            return vecFiles.size() > 0;
        }
        bool GetFirstSigner(const std::wstring& path, std::wstring& signer)
        {
            bool ret = false;
            std::list<common::WinCrypto::SignInfo> sign_info;
            std::wstring process_signer = L"";
            PVOID oldFsRedirection = nullptr;
            if (path.length() > 0)
            {
                //关闭64位重定向
                Wow64DisableWow64FsRedirection(&oldFsRedirection);
                common::WinCrypto::GetEmbedSignInfo(path.c_str(), false, &sign_info);
                Wow64RevertWow64FsRedirection(oldFsRedirection);
                if (sign_info.size() > 0)
                {
                    signer = sign_info.front().signer_name;
                    ret = true;
                }
            }
            return ret;
        }
        bool GetFileVersion(const std::wstring& strPath, std::wstring& strVersion)
        {
            bool ret = false;
            char* pBuf = nullptr;
            do
            {
                VS_FIXEDFILEINFO* pVsInfo;
                unsigned int iFileInfoSize = sizeof(VS_FIXEDFILEINFO);
                int iVerInfoSize = GetFileVersionInfoSize(strPath.c_str(), NULL);
                if (iVerInfoSize != 0) {
                    pBuf = new char[iVerInfoSize];
                    if (nullptr == pBuf) {
                        break;
                    }
                    if (GetFileVersionInfo(strPath.c_str(), 0, iVerInfoSize, pBuf)) {
                        if (VerQueryValue(pBuf, L"\\", (void**)&pVsInfo, &iFileInfoSize)) {
                            strVersion = common::string::wstrFormat(L"%d.%d.%d.%d", HIWORD(pVsInfo->dwFileVersionMS), LOWORD(pVsInfo->dwFileVersionMS), HIWORD(pVsInfo->dwFileVersionLS), LOWORD(pVsInfo->dwFileVersionLS));
                            ret = true;
                        }
                    }

                }
            } while (false);
            if (pBuf)
            {
                delete[] pBuf;
                pBuf = nullptr;
            }
            return ret;
        }


    }
    namespace	string
    {

        std::string SysWideToMultiByte(const std::wstring& wide, uint32_t code_page) {
            int wide_length = static_cast<int>(wide.length());
            if (wide_length == 0)
                return std::string();

            // Compute the length of the buffer we'll need.
            int charcount = WideCharToMultiByte(code_page, 0, wide.data(), wide_length,
                NULL, 0, NULL, NULL);
            if (charcount == 0)
                return std::string();

            std::string mb;
            mb.resize(charcount);
            WideCharToMultiByte(code_page, 0, wide.data(), wide_length,
                &mb[0], charcount, NULL, NULL);

            return mb;
        }
        // Do not assert in this function since it is used by the asssertion code!
        std::string SysWideToUTF8(const std::wstring& wide) {
            return SysWideToMultiByte(wide, CP_UTF8);
        }

        int charToLower(int c)
        {
            int ret = c;
            if (c >= 'A' && c <= 'Z')
            {
                ret += 32;
            }
            return ret;
        }
        void trim(std::wstring& str)
        {
            if (str.empty())
            {
                return;
            }
            str.erase(0, str.find_first_not_of(L' '));
            str.erase(str.find_last_not_of(L' ') + 1);
            return;
        }
        std::wstring replace(std::wstring& str, const std::wstring& src, const std::wstring& dst)
        {
            std::wstring ret = L"";
            size_t last = 0;
            size_t current = str.find(src, last);
            while (current != str.npos)
            {
                ret += str.substr(last, current - last);
                ret += dst;
                last = current + src.length();
                current = str.find(src, last);
            }
            ret += str.substr(last);
            return ret;
        }
        std::wstring DataToHexWstr(char* data, uint32_t len)
        {
            std::wstring out = L"";
            for (size_t i = 0; i < len; i++)
            {
                out += wstrFormat(L"0x%0.2x ", (unsigned char)(data[i]));
                if (i != 0
                    &&
                    (i % 8 == 0))
                {
                    out += L"\r\n";
                }
            }
            return out;
        }
        std::string strFormat(const char* format, ...)
        {
            va_list args;
            va_start(args, format);
            size_t len = std::vsnprintf(NULL, 0, format, args);
            va_end(args);
            std::vector<char> vec(len + 1);
            va_start(args, format);
            std::vsnprintf(&vec[0], len + 1, format, args);
            va_end(args);
            return &vec[0];
        }

        std::wstring wstrFormat(const wchar_t* wfmt, ...)
        {
            va_list args;
            va_start(args, wfmt);
            size_t len = std::vswprintf(NULL, 0, wfmt, args);
            va_end(args);
            std::vector<wchar_t> vec(len + 1);
            va_start(args, wfmt);
            std::vswprintf(&vec[0], len + 1, wfmt, args);
            va_end(args);
            return &vec[0];
        }

        std::vector<std::string> strSplit(const std::string& str, const std::string& split_str, TRIM_STR_FLAG trim_flag, const std::string& str_trim)
        {

            std::vector<std::string> ret_vec;
            size_t start = 0;
            while (start != str.npos) {
                size_t end = str.find_first_of(split_str, start);

                std::string piece;
                if (end == str.npos) {
                    piece = str.substr(start);
                    start = str.npos;
                }
                else {
                    piece = str.substr(start, end - start);
                    start = end + 1;
                }

                if (trim_flag != TRIM_STR_NONE)
                    piece = strTrim(piece, trim_flag, str_trim);

                ret_vec.emplace_back(piece);
            }
            return ret_vec;
        }
        std::vector<std::wstring> wstrSplit(const std::wstring& str, const std::wstring& split_str, TRIM_STR_FLAG trim_flag, const std::wstring& wstr_trim)
        {
            std::vector<std::wstring> ret_vec;
            size_t start = 0;
            while (start != str.npos) {
                size_t end = str.find_first_of(split_str, start);

                std::wstring piece;
                if (end == str.npos) {
                    piece = str.substr(start);
                    start = str.npos;
                }
                else {
                    piece = str.substr(start, end - start);
                    start = end + 1;
                }

                if (trim_flag != TRIM_STR_NONE)
                    piece = wstrTrim(piece, trim_flag, wstr_trim);

                ret_vec.emplace_back(piece);
            }
            return ret_vec;
        }
        std::wstring wstrTrim(const std::wstring& totrim, TRIM_STR_FLAG flag, const std::wstring& whitespace)
        {
            if (totrim.empty())
                return totrim;

            std::wstring tempstr = totrim;
            bool is_delete_zero = false;
            if (tempstr.at(tempstr.length() - 1) == 0)
            {
                is_delete_zero = true;
                tempstr.erase(tempstr.length() - 1);
            }
            if (flag & TRIM_STR_LEADING) {

                while (whitespace.find(tempstr.at(0)) != whitespace.npos)
                {
                    tempstr = tempstr.substr(1);
                }
            }
            if (flag & TRIM_STR_TRAILING) {

                while (whitespace.find(tempstr.at(tempstr.length() - 1)) != whitespace.npos)
                {
                    tempstr.erase(tempstr.length() - 1);
                }
            }
            if (is_delete_zero)
            {
                tempstr += L"\0";
            }
            return tempstr;
        }
        std::string strTrim(const std::string& totrim, TRIM_STR_FLAG flag, const std::string& whitespace)
        {
            if (totrim.empty())
                return totrim;

            std::string tempstr = totrim;
            if (flag & TRIM_STR_LEADING) {
                std::string::size_type headnotof = tempstr.find_first_not_of(whitespace);
                if (headnotof != std::string::npos) {
                    tempstr = tempstr.substr(headnotof);
                }
                else
                {
                    tempstr.clear();
                    return tempstr;
                }
            }
            if (flag & TRIM_STR_TRAILING) {
                std::string::size_type tailnotof = tempstr.find_last_not_of(whitespace);
                if (tailnotof != std::string::npos) {
                    tempstr = tempstr.substr(0, tailnotof + 1);
                }
                else
                {
                    tempstr.clear();
                    return tempstr;
                }
            }

            return tempstr;
        }
        std::wstring strToLower(const std::wstring& str)
        {
            std::wstring res;
            if (str.length() > 0)
            {
                res.resize(str.length());
                std::transform(str.begin(), str.end(), res.begin(), charToLower);
            }

            return res;
        }

        std::string UnicodeToAnsi(const wchar_t* str, int strLen, int codePage)
        {
            std::string res;

            if (str && strLen)
            {
                // 转换为utf8时，一个汉字占三个字节，需要足够的空间
                int bufSize = strLen * 3 + 1;
                CHAR* buf = new CHAR[bufSize];
                if (buf == NULL)
                {
                    return std::string("");
                }
                memset(buf, 0, bufSize);
                WideCharToMultiByte(codePage, 0, str, strLen, buf, bufSize, NULL, NULL);
                res = buf;
                delete[] buf;
            }

            return res;
        }
        std::string UnicodeToAnsi(const std::wstring& str, int codePage)
        {
            std::string res;
            if (str.length() <= 0)
                return std::string("");
            return UnicodeToAnsi(str.c_str(), (int)str.length(), codePage);
        }

        std::wstring AnsiToUnicode(const char* str, int strLen, int codePage)
        {
            std::wstring res;
            if (str && strLen)
            {
                int bufSize = strLen + 1;
                WCHAR* buf = new WCHAR[bufSize];
                if (buf == NULL)
                    return std::wstring(L"");

                memset(buf, 0, bufSize * sizeof(WCHAR));
                MultiByteToWideChar(codePage, 0, str, (int)strLen, buf, bufSize);
                res = buf;
                delete[] buf;
            }

            return res;
        }

        std::wstring SysUTF8ToWide(const std::string& str)
        {

            return AnsiToUnicode(str.c_str(), (int)str.length(), CP_UTF8);
        }
        std::wstring AnsiToUnicode(const std::string& str, int codePage)
        {
            std::wstring res;
            if (str.length() <= 0)
                return std::wstring(L"");

            return AnsiToUnicode(str.c_str(), (int)str.length(), codePage);
        }

        std::string AnsiToUtf8(const std::string& str)
        {
            std::wstring uniStr = AnsiToUnicode(str, CP_ACP);
            std::string res = UnicodeToAnsi(uniStr, CP_UTF8);
            return res;
        }

        std::string Utf8ToAnsi(const std::string& str)
        {
            std::wstring unicodeStr = AnsiToUnicode(str, CP_UTF8);
            std::string ret = UnicodeToAnsi(unicodeStr, CP_ACP);
            return ret;
        }
    }

    namespace misc
    {
        int kCheckJsonNullFlag = 0x00001000;
        bool JsonUnmarshal(const char* data, size_t data_size, nlohmann::json* parsed_json)
        {
            bool parse_err = false;
            try
            {
                nlohmann::detail::input_adapter inadapter(data, data_size);
                *parsed_json = nlohmann::json::parse(std::move(inadapter));

            }
            catch (...)
            {

                parse_err = true;
            }
            return !parse_err;
        }
        bool CheckJson(nlohmann::json& json_to_check, std::vector<std::string>& key_name, std::vector<int>& value_type)
        {
            if (!json_to_check.is_object()) {
                return false;
            }
            size_t key_name_size = key_name.size();
            if (key_name_size != value_type.size()) {
                return false;
            }
            for (size_t i = 0; i < key_name_size; i++)
            {
                auto& name_item = key_name[i];
                auto iter = json_to_check.find(name_item.c_str());
                if (iter == json_to_check.end()) {
                    return false;
                }
                JSON_TYPE json_value_type = (JSON_TYPE)(value_type[i] & ~kCheckJsonNullFlag);
                bool is_check_null = !!(value_type[i] & kCheckJsonNullFlag);
                switch (json_value_type)
                {
                case JSON_TYPE::JSON_TYPE_BOOL:
                    if (!iter->is_boolean()) {
                        return false;
                    }
                    break;
                case JSON_TYPE::JSON_TYPE_INTEGER:
                    if (!iter->is_number_integer()) {
                        return false;
                    }
                    break;
                case JSON_TYPE::JSON_TYPE_STRING:
                    if (!iter->is_string()) {
                        return false;
                    }
                    break;
                case JSON_TYPE::JSON_TYPE_ARRAY:
                    if (!iter->is_array()) {
                        if (is_check_null) {
                            if (iter->is_null()) {
                                return false;
                            }
                        }
                    }
                    break;
                case JSON_TYPE::JSON_TYPE_OBJECT:
                    if (!iter->is_object()) {
                        if (is_check_null) {
                            if (!iter->is_null()) {
                                return false;
                            }
                        }
                        else {
                            return false;
                        }
                    }
                    break;
                default:
                    return false;
                    break;
                }
            }
            return true;
        }
        std::string GetCuttrrentTimeA()
        {
            std::string ret = u8"";
            time_t now = time(0);
            tm ltm = { 0 };
            localtime_s(&ltm, &now);
            ret = common::string::strFormat(u8"%d/%d/%d %0.2d:%0.2d:%0.2d", 1900 + ltm.tm_year, ltm.tm_mon, ltm.tm_mday, ltm.tm_hour, ltm.tm_min, ltm.tm_sec);
            return ret;
        }
        std::wstring GetCuttrrentTimeW()
        {
            std::wstring ret = L"";
            time_t now = time(0);
            tm ltm = { 0 };
            localtime_s(&ltm, &now);
            ret = common::string::wstrFormat(L"%d/%d/%d %0.2d:%0.2d:%0.2d", 1900 + ltm.tm_year, ltm.tm_mon, ltm.tm_mday, ltm.tm_hour, ltm.tm_min, ltm.tm_sec);

            return ret;
        }
        std::wstring idObject2wstr(DWORD idObject)
        {
            std::wstring Ret = L"UnknownidObj";
            switch (idObject)
            {
            case OBJID_SYSMENU:
                Ret = L"OBJID_SYSMENU";
                break;
            case OBJID_TITLEBAR:
                Ret = L"OBJID_TITLEBAR";
                break;
            case OBJID_MENU:
                Ret = L"OBJID_MENU";
                break;
            case OBJID_CLIENT:
                Ret = L"OBJID_CLIENT";
                break;
            case OBJID_VSCROLL:
                Ret = L"OBJID_VSCROLL";
                break;
            case OBJID_HSCROLL:
                Ret = L"OBJID_HSCROLL";
                break;
            case OBJID_SIZEGRIP:
                Ret = L"OBJID_SIZEGRIP";
                break;
            case OBJID_CARET:
                Ret = L"OBJID_CARET";
                break;
            case OBJID_CURSOR:
                Ret = L"OBJID_CURSOR";
                break;
            case OBJID_ALERT:
                Ret = L"OBJID_ALERT";
                break;
            case OBJID_SOUND:
                Ret = L"OBJID_SOUND";
                break;
            case OBJID_QUERYCLASSNAMEIDX:
                Ret = L"OBJID_QUERYCLASSNAMEIDX";
                break;
            case OBJID_NATIVEOM:
                Ret = L"OBJID_NATIVEOM";
                break;
            default:
                break;
            }
            return Ret;
        }
        std::wstring idChild2wstr(DWORD idChild)
        {
            std::wstring Ret = L"UnknownidChild";
            if (CHILDID_SELF == idChild)
            {
                Ret = L"Self";
            }
            else
            {
                Ret = string::wstrFormat(L"0x%X", idChild);
            }
            return Ret;
        }
        uint64_t GetSystemTimeAsUnixTime(uint64_t time_stamp)
        {
            //Get the number of seconds since January 1, 1970 12:00am UTC
            //Code released into public domain; no attribution required.

            constexpr int64_t UNIX_TIME_START = 0x019DB1DED53E8000; //January 1, 1970 (start of Unix epoch) in "ticks"
            constexpr int64_t TICKS_PER_SECOND = 10000000;			//a tick is 100ns

            //Convert ticks since 1/1/1970 into seconds
            return (time_stamp - UNIX_TIME_START) / TICKS_PER_SECOND;
        }
        std::wstring EventID2wstr(DWORD dwEvent)
        {
            std::wstring Ret = L"UnknownEvent";
            switch (dwEvent)
            {
            case EVENT_SYSTEM_SOUND:
                Ret = L"EVENT_SYSTEM_SOUND";
                break;
            case EVENT_SYSTEM_ALERT:
                Ret = L"EVENT_SYSTEM_ALERT";
                break;
            case EVENT_SYSTEM_FOREGROUND:
                Ret = L"EVENT_SYSTEM_FOREGROUND";
                break;
            case EVENT_SYSTEM_MENUSTART:
                Ret = L"EVENT_SYSTEM_MENUSTART";
                break;
            case EVENT_SYSTEM_MENUEND:
                Ret = L"EVENT_SYSTEM_MENUEND";
                break;
            case EVENT_SYSTEM_MENUPOPUPSTART:
                Ret = L"EVENT_SYSTEM_MENUPOPUPSTART";
                break;
            case EVENT_SYSTEM_MENUPOPUPEND:
                Ret = L"EVENT_SYSTEM_MENUPOPUPEND";
                break;
            case EVENT_SYSTEM_CAPTURESTART:
                Ret = L"EVENT_SYSTEM_CAPTURESTART";
                break;
            case EVENT_SYSTEM_CAPTUREEND:
                Ret = L"EVENT_SYSTEM_CAPTUREEND";
                break;
            case EVENT_SYSTEM_MOVESIZESTART:
                Ret = L"EVENT_SYSTEM_MOVESIZESTART";
                break;
            case EVENT_SYSTEM_MOVESIZEEND:
                Ret = L"EVENT_SYSTEM_MOVESIZEEND";
                break;
            case EVENT_SYSTEM_CONTEXTHELPSTART:
                Ret = L"EVENT_SYSTEM_CONTEXTHELPSTART";
                break;
            case EVENT_SYSTEM_CONTEXTHELPEND:
                Ret = L"EVENT_SYSTEM_CONTEXTHELPEND";
                break;
            case EVENT_SYSTEM_DRAGDROPSTART:
                Ret = L"EVENT_SYSTEM_DRAGDROPSTART";
                break;
            case EVENT_SYSTEM_DRAGDROPEND:
                Ret = L"EVENT_SYSTEM_DRAGDROPEND";
                break;
            case EVENT_SYSTEM_DIALOGSTART:
                Ret = L"EVENT_SYSTEM_DIALOGSTART";
                break;
            case EVENT_SYSTEM_DIALOGEND:
                Ret = L"EVENT_SYSTEM_DIALOGEND";
                break;
            case EVENT_SYSTEM_SCROLLINGSTART:
                Ret = L"EVENT_SYSTEM_SCROLLINGSTART";
                break;
            case EVENT_SYSTEM_SCROLLINGEND:
                Ret = L"EVENT_SYSTEM_SCROLLINGEND";
                break;
            case EVENT_SYSTEM_SWITCHSTART:
                Ret = L"EVENT_SYSTEM_SWITCHSTART";
                break;
            case EVENT_SYSTEM_SWITCHEND:
                Ret = L"EVENT_SYSTEM_SWITCHEND";
                break;
            case EVENT_SYSTEM_MINIMIZESTART:
                Ret = L"EVENT_SYSTEM_MINIMIZESTART";
                break;
            case EVENT_SYSTEM_MINIMIZEEND:
                Ret = L"EVENT_SYSTEM_MINIMIZEEND";
                break;
            case EVENT_SYSTEM_DESKTOPSWITCH:
                Ret = L"EVENT_SYSTEM_DESKTOPSWITCH";
                break;
            case EVENT_SYSTEM_SWITCHER_APPGRABBED:
                Ret = L"EVENT_SYSTEM_SWITCHER_APPGRABBED";
                break;
            case EVENT_SYSTEM_SWITCHER_APPOVERTARGET:
                Ret = L"EVENT_SYSTEM_SWITCHER_APPOVERTARGET";
                break;
            case EVENT_SYSTEM_SWITCHER_APPDROPPED:
                Ret = L"EVENT_SYSTEM_SWITCHER_APPDROPPED";
                break;
            case EVENT_SYSTEM_SWITCHER_CANCELLED:
                Ret = L"EVENT_SYSTEM_SWITCHER_CANCELLED";
                break;
            case EVENT_SYSTEM_IME_KEY_NOTIFICATION:
                Ret = L"EVENT_SYSTEM_IME_KEY_NOTIFICATION";
                break;
            case EVENT_SYSTEM_END:
                Ret = L"EVENT_SYSTEM_END";
                break;
            case EVENT_OEM_DEFINED_START:
                Ret = L"EVENT_OEM_DEFINED_START";
                break;
            case EVENT_OEM_DEFINED_END:
                Ret = L"EVENT_OEM_DEFINED_END";
                break;
            case EVENT_UIA_EVENTID_START:
                Ret = L"EVENT_UIA_EVENTID_START";
                break;
            case EVENT_UIA_EVENTID_END:
                Ret = L"EVENT_UIA_EVENTID_END";
                break;
            case EVENT_UIA_PROPID_START:
                Ret = L"EVENT_UIA_PROPID_START";
                break;
            case EVENT_UIA_PROPID_END:
                Ret = L"EVENT_UIA_PROPID_END";
                break;
            case EVENT_CONSOLE_CARET:
                Ret = L"EVENT_CONSOLE_CARET";
                break;
            case EVENT_CONSOLE_UPDATE_REGION:
                Ret = L"EVENT_CONSOLE_UPDATE_REGION";
                break;
            case EVENT_CONSOLE_UPDATE_SIMPLE:
                Ret = L"EVENT_CONSOLE_UPDATE_SIMPLE";
                break;
            case EVENT_CONSOLE_UPDATE_SCROLL:
                Ret = L"EVENT_CONSOLE_UPDATE_SCROLL";
                break;
            case EVENT_CONSOLE_LAYOUT:
                Ret = L"EVENT_CONSOLE_LAYOUT";
                break;
            case EVENT_CONSOLE_START_APPLICATION:
                Ret = L"EVENT_CONSOLE_START_APPLICATION";
                break;
            case EVENT_CONSOLE_END_APPLICATION:
                Ret = L"EVENT_CONSOLE_END_APPLICATION";
                break;
            case EVENT_OBJECT_CREATE:
                Ret = L"EVENT_OBJECT_CREATE";
                break;
            case EVENT_OBJECT_DESTROY:
                Ret = L"EVENT_OBJECT_DESTROY";
                break;
            case EVENT_OBJECT_SHOW:
                Ret = L"EVENT_OBJECT_SHOW";
                break;
            case EVENT_OBJECT_HIDE:
                Ret = L"EVENT_OBJECT_HIDE";
                break;
            case EVENT_OBJECT_REORDER:
                Ret = L"EVENT_OBJECT_REORDER";
                break;
            case EVENT_OBJECT_FOCUS:
                Ret = L"EVENT_OBJECT_FOCUS";
                break;
            case EVENT_OBJECT_SELECTION:
                Ret = L"EVENT_OBJECT_SELECTION";
                break;
            case EVENT_OBJECT_SELECTIONADD:
                Ret = L"EVENT_OBJECT_SELECTIONADD";
                break;
            case EVENT_OBJECT_SELECTIONREMOVE:
                Ret = L"EVENT_OBJECT_SELECTIONREMOVE";
                break;
            case EVENT_OBJECT_SELECTIONWITHIN:
                Ret = L"EVENT_OBJECT_SELECTIONWITHIN";
                break;
            case EVENT_OBJECT_STATECHANGE:
                Ret = L"EVENT_OBJECT_STATECHANGE";
                break;
            case EVENT_OBJECT_LOCATIONCHANGE:
                Ret = L"EVENT_OBJECT_LOCATIONCHANGE";
                break;
            case EVENT_OBJECT_NAMECHANGE:
                Ret = L"EVENT_OBJECT_NAMECHANGE";
                break;
            case EVENT_OBJECT_DESCRIPTIONCHANGE:
                Ret = L"EVENT_OBJECT_DESCRIPTIONCHANGE";
                break;
            case EVENT_OBJECT_VALUECHANGE:
                Ret = L"EVENT_OBJECT_VALUECHANGE";
                break;
            case EVENT_OBJECT_PARENTCHANGE:
                Ret = L"EVENT_OBJECT_PARENTCHANGE";
                break;
            case EVENT_OBJECT_HELPCHANGE:
                Ret = L"EVENT_OBJECT_HELPCHANGE";
                break;
            case EVENT_OBJECT_DEFACTIONCHANGE:
                Ret = L"EVENT_OBJECT_DEFACTIONCHANGE";
                break;
            case EVENT_OBJECT_ACCELERATORCHANGE:
                Ret = L"EVENT_OBJECT_ACCELERATORCHANGE";
                break;

            case EVENT_OBJECT_INVOKED:
                Ret = L"EVENT_OBJECT_INVOKED";
                break;
            case EVENT_OBJECT_TEXTSELECTIONCHANGED:
                Ret = L"EVENT_OBJECT_TEXTSELECTIONCHANGED";
                break;
            case EVENT_OBJECT_CONTENTSCROLLED:
                Ret = L"EVENT_OBJECT_CONTENTSCROLLED";
                break;
            case EVENT_SYSTEM_ARRANGMENTPREVIEW:
                Ret = L"EVENT_SYSTEM_ARRANGMENTPREVIEW";
                break;
            case EVENT_OBJECT_CLOAKED:
                Ret = L"EVENT_OBJECT_CLOAKED";
                break;
            case EVENT_OBJECT_UNCLOAKED:
                Ret = L"EVENT_OBJECT_UNCLOAKED";
                break;
            case EVENT_OBJECT_LIVEREGIONCHANGED:
                Ret = L"EVENT_OBJECT_LIVEREGIONCHANGED";
                break;
            case EVENT_OBJECT_HOSTEDOBJECTSINVALIDATED:
                Ret = L"EVENT_OBJECT_HOSTEDOBJECTSINVALIDATED";
                break;
            case EVENT_OBJECT_DRAGCANCEL:
                Ret = L"EVENT_OBJECT_DRAGCANCEL";
                break;
            case EVENT_OBJECT_DRAGCOMPLETE:
                Ret = L"EVENT_OBJECT_DRAGCOMPLETE";
                break;
            case EVENT_OBJECT_DRAGENTER:
                Ret = L"EVENT_OBJECT_DRAGENTER";
                break;
            case EVENT_OBJECT_DRAGLEAVE:
                Ret = L"EVENT_OBJECT_DRAGLEAVE";
                break;
            case EVENT_OBJECT_DRAGDROPPED:
                Ret = L"EVENT_OBJECT_DRAGDROPPED";
                break;
            case EVENT_OBJECT_IME_SHOW:
                Ret = L"EVENT_OBJECT_IME_SHOW";
                break;
            case EVENT_OBJECT_IME_HIDE:
                Ret = L"EVENT_OBJECT_IME_HIDE";
                break;
            case EVENT_OBJECT_IME_CHANGE:
                Ret = L"EVENT_OBJECT_IME_CHANGE";
                break;
            case EVENT_OBJECT_TEXTEDIT_CONVERSIONTARGETCHANGED:
                Ret = L"EVENT_OBJECT_TEXTEDIT_CONVERSIONTARGETCHANGED";
                break;
            case EVENT_OBJECT_END:
                Ret = L"EVENT_OBJECT_END";
                break;
            case EVENT_AIA_START:
                Ret = L"EVENT_AIA_START";
                break;
            case EVENT_AIA_END:
                Ret = L"EVENT_AIA_END";
                break;
            default:
                Ret = string::wstrFormat(L"%d(UnknownEvent)", dwEvent);
                break;
            }
            return Ret;
        }
        std::wstring guid_to_wstring(const GUID& guid)
        {
            wchar_t test[48] = { 0 };
            StringFromGUID2(guid, test, 48);
            return test;
        }
        std::wstring etwevent_to_wstring(const GUID& guid, uint32_t op_code)
        {
            /* 90cbdc39-4a3e-11d1-84f4-0000f80464e3 */
            static GUID this_FileIoGuid = {
                0x90cbdc39,
                0x4a3e,
                0x11d1,
                0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3
            };
            /* DEF2FE46-7BD6-4b80-bd94-F57FE20D0CE3 */
            static GUID this_StackWalkGuid = {
                0xdef2fe46,
                0x7bd6,
                0x4b80,
                0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0xd, 0xc, 0xe3
            };
            std::wstring ret = L"unknown:opt";
            if (IsEqualGUID(guid, this_FileIoGuid))
            {
                ret = L"file:";
                switch (op_code)
                {
                case 36: // file name rundown
                {
                    ret += L"file_name_rundown";
                    break;
                }
                case 35:// file name delete event
                {
                    ret += L"file_name_delete";
                    break;
                }
                case 32: // file name create event
                {
                    ret += L"file_name_create";
                    break;
                }
                case 64: // File Create
                    ret += L"file_create";

                    break;
                case 66: // File Close
                    ret += L"file_close";
                    break;
                case 67: // File Read
                    ret += L"file_read";

                    break;
                case 68: // File Write
                    ret += L"file_write";
                    break;
                case 69: // Set Information
                    ret += L"file_set_infomation";
                    break;
                case 65: // File Clean Up
                    ret += L"file_clean_up";
                    break;
                case 70: // Delete File
                    ret += L"file_delete";
                    break;
                case 71: // Rename File
                    ret += L"file_rename";
                    break;
                    // case 72: //dir enum
                    // 	HandleDirEnumEvent(record);
                    // 	break;
                case 76:
                    ret += L"file_operator_end";
                    break;
                case 77: //dir notify
                    ret += L"file_directory_notify";
                    break;
                case 80: // rename_path
                    ret += L"file_rename_path";
                    break;
                default:
                    ret += L"unknown";
                    break;
                }

            }
            else if (IsEqualGUID(guid, this_StackWalkGuid))
            {

                ret = L"stack_walk:unknown";
            }

            return ret;
        }
    }
    namespace lock
    {
        AutoLocker::AutoLocker(std::mutex& lock) :
            locker(lock)
        {
            locker.lock();
        }
        AutoLocker::~AutoLocker()
        {
            locker.unlock();
        }
        AutoReadLock::AutoReadLock(std::shared_mutex& lock) :
            locker(lock)
        {
            locker.lock_shared();
        }
        AutoReadLock::~AutoReadLock()
        {
            locker.unlock_shared();
        }
        AutoWriteLock::AutoWriteLock(std::shared_mutex& lock) :
            locker(lock)
        {
            locker.lock();
        }
        AutoWriteLock::~AutoWriteLock()
        {
            locker.unlock();
        }
    }
    namespace path
    {
        const wchar_t* GetCurrentProcessDirectory()
        {
            static wchar_t current_driectory[MAX_PATH] = { 0 };
            if (current_driectory[0] == 0)
            {
                GetModuleFileName(NULL, current_driectory, MAX_PATH);
                PathRemoveFileSpec(current_driectory);
            }
            return current_driectory;
        }
        std::wstring GetDirW(const std::wstring& strPath)
        {
            std::wstring strFileName;
            size_t nPos;

            if ((nPos = strPath.find_last_of(L"\\")) == std::wstring::npos)
            {
                return strPath;
            }
            if (nPos + 1 == strPath.length())
                return strFileName;

            strFileName = strPath.substr(0, nPos);
            return strFileName;
        }
        std::wstring ExpandEnvironment(const std::wstring& strPath)
        {
            if (strPath.find(L'%') != 0)
            {
                return strPath;
            }
            wchar_t szPath[MAX_PATH * 2] = { 0 };
            ::ExpandEnvironmentStringsW(strPath.c_str(), szPath, MAX_PATH * 2);
            if (szPath[0] != 0)
            {
                return szPath;
            }
            return strPath;
        }
        std::wstring GetFileNameW(const std::wstring& strPath)
        {
            std::wstring strFileName;
            size_t nPos;

            if ((nPos = strPath.find_last_of(L"\\")) == std::wstring::npos)
            {
                return strPath;
            }
            if (nPos + 1 == strPath.length())
                return strFileName;

            strFileName = strPath.substr(nPos + 1, strPath.length() - nPos - 1);
            return strFileName;
        }
        static std::unordered_map<uint64_t, uint32_t>   device_path_to_dos_path_map_; //路径格式转换map
        uint64_t hash_code(const wchar_t* key)
        {
            uint64_t h = 0;
            int len = wcslen(key);
            if (h == 0 && len > 0) {
                for (int i = 0; i < len; i++) {
                    h = 31 * h + common::string::charToLower(key[i]);
                }
            }
            return h;
        }
        std::unique_ptr<wchar_t> FormatPath(wchar_t driver_index, const wchar_t* sub_str)
        {
            auto sub_str_len = wcslen(sub_str);
            if (sub_str_len == 0) return nullptr;

            auto dos_path_len = sub_str_len + 3;
            std::unique_ptr<wchar_t> dos_path;
            dos_path.reset(new wchar_t[dos_path_len]);

            if (dos_path != nullptr)
            {
                swprintf_s(dos_path.get(), dos_path_len, L"%c:%s", driver_index + L'a', sub_str);
            }

            // 转小写
            std::transform(dos_path.get(), dos_path.get() + dos_path_len, dos_path.get(), [](wchar_t ch) -> wchar_t {
                if (ch == L'/')
                {
                    return L'\\';
                }
                return common::string::charToLower(ch);
                });

            // 去除尾部的分隔符
            if (dos_path.get()[dos_path_len - 2] == L'\\')
            {
                dos_path.get()[dos_path_len - 2] = 0;
            }
            return dos_path;
        }
        const wchar_t device_name_prex_const[] = L"\\Deivce\\HarddiskVolume";
        std::unique_ptr<wchar_t> DevicePathToDosPathInternal(const wchar_t* device_path)
        {
            auto len = _countof(device_name_prex_const) - 1;
            wchar_t device_path_prex[MAX_PATH] = { 0 };
            const wchar_t* sub_str = device_path;
            bool found = false;
            auto device_path_length = wcslen(device_path);

            for (size_t index = len + 1; index < device_path_length; index++)
            {
                if (device_path[index] == L'/' || device_path[index] == L'\\')
                {
                    wcsncpy(device_path_prex, device_path, index);
                    sub_str += index;
                    found = true;
                    break;
                }
            }

            if (found)
            {
                auto iter = device_path_to_dos_path_map_.find(hash_code(device_path_prex));
                if (iter != device_path_to_dos_path_map_.end())
                {
                    return FormatPath(iter->second, sub_str);
                }
            }
            return nullptr;
        }
        void EnumDosVolumes()
        {
            const int kDriveMappingSize = 1024;
            wchar_t drive_mapping[kDriveMappingSize] = { '\0' };
            if (!::GetLogicalDriveStrings(kDriveMappingSize - 1, drive_mapping)) {
                return;
            }

            std::unordered_map<uint64_t, uint32_t>  device_path_map;
            wchar_t* drive_map_ptr = drive_mapping;
            wchar_t drive[] = L" :";
            while (*drive_map_ptr) {
                drive[0] = drive_map_ptr[0];
                wchar_t device_path_as_string[MAX_PATH + 1] = { 0 };
                if (QueryDosDevice(drive, device_path_as_string, MAX_PATH)) {
                    uint64_t hash_code_temp = hash_code(device_path_as_string);
                    device_path_map[hash_code_temp] = common::string::charToLower(drive[0]) - 'a';
                }
                while (*drive_map_ptr++) {}
            }

            device_path_to_dos_path_map_.swap(device_path_map);
            return;
        }
        std::unique_ptr<wchar_t> DevicePathToDosPathEx(const wchar_t* device_path)
        {
            uint32_t device_path_len = wcslen(device_path);
            if (device_path_len > 2 && device_path[1] == L':')
            {
                std::unique_ptr<wchar_t> dos_path;
                dos_path.reset(new wchar_t[wcslen(device_path) + 1]);
                wcscpy_s(dos_path.get(), device_path_len, device_path);
                return dos_path;
            }
            auto dos_path = DevicePathToDosPathInternal(device_path);
            if (dos_path == nullptr)
            {
                EnumDosVolumes();
                dos_path = DevicePathToDosPathInternal(device_path);
            }
            return dos_path;
        }
        bool DevicePathToDosPath(const std::wstring& device_path, std::wstring& dos_path)
        {
            dos_path = device_path;
            auto dos_path_ptr = DevicePathToDosPathEx(device_path.c_str());
            if (dos_path_ptr == NULL)
            {
                return false;
            }
            dos_path = dos_path_ptr.get();
            return true;
        }
    }
    namespace system
    {
        bool isWin64()
        {
            SYSTEM_INFO info = { { 0 } };
            GetNativeSystemInfo(&info);
            if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
    }

}
