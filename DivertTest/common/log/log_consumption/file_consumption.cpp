#include "file_consumption.h"
#include "../blog_manager.h"
#include <sstream>
#include <iomanip>
#include "../blog_instance.h"
#include "../blog.h"

namespace blog
{
	FileConsumption::FileConsumption(const BlogOption& option)
	{
		auto file_option = option.File;
		enable_ = file_option.enable;
		max_log_file_size_ = file_option.max_log_file_size;
		max_log_file_count_ = file_option.max_log_file_count;
		current_log_file_size_ = 0;
		base_dir_ = file_option.base_dir;
		base_name_ = file_option.base_name;
		log_file_ext_ = file_option.log_file_ext;
		log_prefix_ = file_option.prefix;
		print_to_memory_ = file_option.print_to_memory;
		flush_interval_ = file_option.flush_interval;
		min_log_level_ = option.File.min_log_level;

		log_file_handle_ = INVALID_HANDLE_VALUE;
	}

	FileConsumption::~FileConsumption()
	{
		if (log_file_handle_ != nullptr)
		{
			CloseHandle(log_file_handle_);
			log_file_handle_ = INVALID_HANDLE_VALUE;
		}
	}

	void FileConsumption::SetMaxLogFileSize(uint64_t max_size)
	{
		max_log_file_size_ = max_size;
	}

	void FileConsumption::SetLogDir(const wchar_t* dir)
	{
		base_dir_ = dir;
	}

	void FileConsumption::SetLogFileName(const wchar_t* name)
	{
		base_name_ = name;
	}

	void FileConsumption::SetLogExtName(const wchar_t* ext_name)
	{
		log_file_ext_ = ext_name;
	}

	void FileConsumption::Record(const BLogInstance* log_instance)
	{
		if (enable_ == false)
		{
			return;
		}

		if (min_log_level_ < log_instance->GetLevel())
		{
			return;
		}

		auto log_str = log_instance->GetLogStr();
		auto log_time = log_instance->GetTime();

		std::unique_lock<std::mutex> lock(log_mutex);
		
		std::stringstream ss;
		if (log_prefix_.empty() == false)
		{
			ss << '[' << log_prefix_ << "] ";
		}
		ss << std::setw(7) << std::left << LevelToString(log_instance->GetLevel()) << u8' ';

		ss.fill(u8'0');
		ss << std::internal << std::setw(4) << log_time.wYear << u8'/'
			<< std::setw(2) << log_time.wMonth << u8'/'
			<< std::setw(2) << log_time.wDay << u8' '
			<< std::setw(2) << log_time.wHour << u8':'
			<< std::setw(2) << log_time.wMinute << u8':'
			<< std::setw(2) << log_time.wSecond << u8'.'
			<< std::setw(3) << log_time.wMilliseconds << u8' '
			<< UTF16ToUTF8(log_instance->GetSourceFile()) << u8':' << log_instance->GetLine() << u8' '
			<< std::setw(5) << GetCurrentProcessId() << u8':' << std::setw(5) << GetCurrentThreadId() << u8" : "
			<< log_str << u8"\r\n";

		auto result_log_str = ss.str();

		if (log_file_handle_ == INVALID_HANDLE_VALUE)
		{
			if (OpenLogFile() == false)
			{
				return;
			}
		}

		if ((current_log_file_size_ != 0) && (max_log_file_size_ - current_log_file_size_ < (int64_t)result_log_str.size()))
		{
			// 日志满了
			if (max_log_file_size_ > current_log_file_size_)
			{
				LARGE_INTEGER li;
				li.QuadPart = max_log_file_size_;
				SetFilePointerEx(log_file_handle_, li, nullptr, FILE_BEGIN);
				SetEndOfFile(log_file_handle_);
			}

			if (ReopenNewLogFile() == false)
			{
				return;
			}
		}

		if (print_to_memory_ == true)
		{
			OutputDebugStringW(UTF8ToUTF16(result_log_str).c_str());
		}

		auto utf8_log_data = result_log_str;
		DWORD real_write = 0;
		WriteFile(log_file_handle_, utf8_log_data.c_str(), utf8_log_data.size(), &real_write, nullptr);
		current_log_file_size_ += real_write;

		auto now = std::chrono::system_clock::now();
		if (std::chrono::duration_cast<std::chrono::seconds>(now - last_flush_time_).count() > flush_interval_)
		{
			FlushFileBuffers(log_file_handle_);
			last_flush_time_ = now;
		}
	}

	bool FileConsumption::OpenLogFile()
	{
		bool ret = true;
		errno_t err = 0;
		do
		{
			if (log_file_handle_ != INVALID_HANDLE_VALUE)
			{
				break;
			}

			std::wstringstream ss;
			ss << base_dir_ << L"\\" << base_name_ << L"." << log_file_ext_;
			CreateDirectoryW(base_dir_.c_str(), nullptr);

			auto log_file_name = ss.str();

			log_file_handle_ = CreateFileW(
				log_file_name.c_str(),
				GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ,
				nullptr,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);
			
			LARGE_INTEGER li = { 0 };
			if (GetFileSizeEx(log_file_handle_, &li) == FALSE)
			{
				break;
			}

			current_log_file_size_ = li.QuadPart;
			if (current_log_file_size_ == 0)
			{
				// 写入UTF8 BOM
				DWORD real_write = 0;
				WriteFile(log_file_handle_, "\xEF\xBB\xBF", 3, &real_write, nullptr);
			}
			else
			{
				li.QuadPart = 0;
				SetFilePointerEx(log_file_handle_, li, nullptr, FILE_END);
			}
		} while (false);

		return ret;
	}

	bool FileConsumption::ReopenNewLogFile()
	{
		bool ret = true;

		do
		{
			std::wstringstream ss;
			ss << base_dir_ << L"\\" << base_name_ << L"." << log_file_ext_;
			auto log_file_name = ss.str();

			if (log_file_handle_ != INVALID_HANDLE_VALUE)
			{
				CloseHandle(log_file_handle_);
				log_file_handle_ = INVALID_HANDLE_VALUE;
			}

			SYSTEMTIME st = { 0 };
			GetLocalTime(&st);
			ss.str(L"");
			ss.fill(L'0');
			ss << base_dir_ << L"\\" << base_name_ << L"_"
				<< st.wYear
				<< std::setw(2) << st.wMonth
				<< std::setw(2) << st.wDay
				<< L'-'
				<< std::setw(2) << st.wHour
				<< std::setw(2) << st.wMinute
				<< std::setw(2) << st.wSecond
				<< L'.' << log_file_ext_;
			auto log_file_new_name = ss.str();

			MoveFileW(log_file_name.c_str(), log_file_new_name.c_str());

			RemoveOldLogFile();

			ret = OpenLogFile();
		} while (false);

		return ret;
	}

	std::map<uint64_t, std::wstring> FileConsumption::GetAllLogFile()
	{
		// 创建时间，全路径
		std::map<uint64_t, std::wstring> log_map;

		std::wstringstream ss;
		ss << base_dir_ << L"\\" << base_name_ << L"_*";

		HANDLE hFind = INVALID_HANDLE_VALUE;
		WIN32_FIND_DATAW wfd = { 0 };
		do
		{
			hFind = FindFirstFileW(ss.str().c_str(), &wfd);
			if (hFind == INVALID_HANDLE_VALUE)
			{
				break;
			}

			do
			{
				ss.str(L"");
				if ((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
				{
					continue;
				}

				ss << base_dir_ << L"\\" << wfd.cFileName;
				log_map[MakeUint64(wfd.ftLastWriteTime.dwLowDateTime, wfd.ftLastWriteTime.dwHighDateTime)] = ss.str();
			} while (FindNextFileW(hFind, &wfd) == TRUE);
		} while (false);

		if (hFind != INVALID_HANDLE_VALUE)
		{
			FindClose(hFind);
			hFind = INVALID_HANDLE_VALUE;
		}

		return log_map;
	}
	void FileConsumption::RemoveOldLogFile()
	{
		// 删除老旧的日志
		auto log_files = GetAllLogFile();
		for (auto iter = log_files.cbegin(); iter != log_files.cend();)
		{
			if (log_files.size() < max_log_file_count_)
			{
				break;
			}

			DeleteFileW(iter->second.c_str());
			iter = log_files.erase(iter);
		}
	}
}