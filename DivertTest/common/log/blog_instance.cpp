#include "blog_instance.h"
#include "blog_manager.h"
#include <Windows.h>

namespace blog
{
	BLogInstance::BLogInstance(int level, size_t line, const wchar_t* source_file, bool use_widechar) noexcept
	{
		level_ = level;
		use_widechar_ = use_widechar;
		line_ = line;
		GetLocalTime(&st_);

		auto offset = wcsrchr(source_file, L'\\');
		if (offset != nullptr)
		{
			source_file_ = offset + 1;
		}
		else
		{
			source_file_ = source_file;
		}
	}

	BLogInstance::~BLogInstance() noexcept
	{
		BLogManager::fnSendLog(this);
	}

	std::string BLogInstance::GetLogStr() const
	{
		std::string ret;

		if (use_widechar_ == false)
		{
			ret = ss_.str();
		}
		else
		{
			ret = UTF16ToUTF8(wss_.str());
		}
		return ret;
	}

	size_t BLogInstance::GetLine() const noexcept
	{
		return line_;
	}

	const wchar_t* BLogInstance::GetSourceFile() const noexcept
	{
		return source_file_;
	}

	SYSTEMTIME BLogInstance::GetTime() const noexcept
	{
		return st_;
	}

	int BLogInstance::GetLevel() const noexcept
	{
		return level_;
	}

	std::wstringstream& BLogInstance::GetInputUTF16() noexcept
	{
		return wss_;
	}

	std::stringstream& BLogInstance::GetInputUTF8() noexcept
	{
		return ss_;
	}

	std::string BLogInstance::UTF16ToUTF8(const std::wstring& str)
	{
		std::string ret;

		constexpr size_t pre_prepared_buff_size = 1024;
		char pre_prepared_buff[pre_prepared_buff_size];

		char* buff = pre_prepared_buff;
		size_t buff_size = pre_prepared_buff_size;

		do
		{
			auto status = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
			if (status == 0)
			{
				break;
			}

			if (status >= pre_prepared_buff_size)
			{
				buff = (char*)calloc(status + 1, sizeof(wchar_t));
			}
			buff_size = status;

			if (buff == nullptr)
			{
				break;
			}

			status = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, buff, status, nullptr, nullptr);
			if (status == 0)
			{
				break;
			}

			buff[status] = 0;

			ret = buff;
		} while (false);

		if (buff != nullptr && buff != pre_prepared_buff)
		{
			free(buff);
			buff = nullptr;
		}

		return ret;
	}

	std::wstring BLogInstance::UTF8ToUTF16(const std::string& str)
	{
		std::wstring ret;

		constexpr size_t pre_prepared_buff_size = 512;
		wchar_t pre_prepared_buff[pre_prepared_buff_size];

		wchar_t* buff = pre_prepared_buff;
		size_t buff_size = pre_prepared_buff_size;

		do
		{
			auto status = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
			if (status == 0)
			{
				break;
			}

			if (status >= pre_prepared_buff_size)
			{
				buff = (wchar_t*)calloc(status + 1, sizeof(wchar_t));
			}
			buff_size = status;

			if (buff == nullptr)
			{
				break;
			}

			status = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, buff, status);
			if (status == 0)
			{
				break;
			}

			buff[status] = 0;

			ret = buff;
		} while (false);

		if (buff != nullptr && buff != pre_prepared_buff)
		{
			free(buff);
			buff = nullptr;
		}

		return ret;
	}
}