#pragma once
#include "common_head.h"
namespace common {
    namespace log
    {
        bool init_log(const wchar_t* base_log_name, bool file_enable, bool console_enable);
    }
    namespace	string
    {
        enum TRIM_STR_FLAG
        {
            TRIM_STR_NONE = 0,
            TRIM_STR_LEADING = 1,
            TRIM_STR_TRAILING = 2,
            TRIM_STR_ALL = TRIM_STR_LEADING | TRIM_STR_TRAILING,
        };
        std::string strTrim(const std::string& totrim, TRIM_STR_FLAG flag = TRIM_STR_ALL, const std::string& whitespace = " \t\r\n");
        std::wstring wstrTrim(const std::wstring& totrim, TRIM_STR_FLAG flag = TRIM_STR_ALL, const std::wstring& whitespace = L" \t\r\n");
        std::string SysWideToUTF8(const std::wstring& wide);
        std::string strFormat(const char* format, ...);
        std::wstring wstrFormat(const wchar_t* wfmt, ...);
        std::wstring strToLower(const std::wstring& str);

        std::vector<std::wstring> wstrSplit(const std::wstring& str, const std::wstring& split_str, TRIM_STR_FLAG trim_flag = TRIM_STR_ALL, const std::wstring& wstr_trim = L" \t\r\n");
        std::vector<std::string> strSplit(const std::string& str, const std::string& split_str, TRIM_STR_FLAG trim_flag = TRIM_STR_ALL, const std::string& str_trim = u8" \t\r\n");

        int charToLower(int c);
        std::string UnicodeToAnsi(const wchar_t* str, int strLen, int codePage);
        std::string UnicodeToAnsi(const std::wstring& str, int codePage = CP_ACP);

        std::wstring AnsiToUnicode(const char* str, int strLen, int codePage);
        std::wstring AnsiToUnicode(const std::string& str, int codePage = CP_ACP);
        std::wstring SysUTF8ToWide(const std::string& str);

        std::string AnsiToUtf8(const std::string& str);

        std::string Utf8ToAnsi(const std::string& str);
        void trim(std::wstring& str);
        std::wstring replace(std::wstring& str, const std::wstring& src, const std::wstring& dst);

        std::wstring DataToHexWstr(char* data, uint32_t len);
    }
    namespace system
    {
        bool isWin64();
    }
    namespace process
    {
        std::wstring GetProcessPathFromPid(uint32_t process_id);
        bool TerminateProcessByPid(uint32_t process_id);
        DWORD ThreadIdToProcessId(DWORD thread_id);
        bool IsX86Process(uint32_t process_id);
    }

    namespace file
    {
        bool GetFileVersion(const std::wstring& strPath, std::wstring& strVersion);
        bool EnumFiles(const wchar_t* input_directory, const wchar_t* file_format, bool is_query_single_layer, std::vector<std::wstring>& vecFiles);

        bool CreateNewFile(const wchar_t* path);
        bool ForceDeleteFile(const wchar_t* path);
        bool DeleteDirectoryLoop(const wchar_t* path, bool single_layer = false);
        bool DirectoryPathIsExist(const wchar_t* path);
        bool WriteFileData(const wchar_t* path, const std::string& data);
        bool ReadFileData(const wchar_t* path, std::string& data);//不支持大于10M的文件读取
        uint64_t GetFileSize(const wchar_t* path);

        bool GetFirstSigner(const std::wstring& path, std::wstring& signer);
    }
    namespace misc
    {
        enum JSON_TYPE
        {
            JSON_TYPE_NULL = 0,
            JSON_TYPE_BOOL = 1,
            JSON_TYPE_INTEGER = 2,
            JSON_TYPE_STRING = 3,
            JSON_TYPE_ARRAY = 4,
            JSON_TYPE_OBJECT = 5,

        };
        extern int kCheckJsonNullFlag;
        std::wstring EventID2wstr(DWORD event);
        std::wstring idObject2wstr(DWORD idObject);
        std::wstring idChild2wstr(DWORD idChild);
        std::wstring guid_to_wstring(const GUID& guid);
        std::wstring etwevent_to_wstring(const GUID& guid, uint32_t op_code);
        uint64_t GetSystemTimeAsUnixTime(uint64_t time_stamp);
        bool CheckJson(nlohmann::json& json_to_check, std::vector<std::string>& key_name, std::vector<int>& value_type);
        bool JsonUnmarshal(const char* data, size_t data_size, nlohmann::json* parsed_json);
        std::string GetCuttrrentTimeA();
        std::wstring GetCuttrrentTimeW();
    }
    namespace lock
    {
        class AutoLocker
        {
        private:
            std::mutex& locker;
        public:
            AutoLocker(std::mutex& lock);
            ~AutoLocker();

        };
        class AutoReadLock
        {
        private:
            std::shared_mutex& locker;
        public:
            AutoReadLock(std::shared_mutex& lock);
            ~AutoReadLock();

        };
        class AutoWriteLock
        {
        private:
            std::shared_mutex& locker;
        public:
            AutoWriteLock(std::shared_mutex& lock);
            ~AutoWriteLock();

        };
    }
    namespace path
    {
        const wchar_t* GetCurrentProcessDirectory();
        std::wstring GetDirW(const std::wstring& strPath);
        std::wstring GetFileNameW(const std::wstring& strPath);
        std::wstring ExpandEnvironment(const std::wstring& strPath);
        bool DevicePathToDosPath(const std::wstring& device_path, std::wstring& dos_path);
    }

}