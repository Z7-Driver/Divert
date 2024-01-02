#include "consumption_interface.h"
#include <Windows.h>

std::string blog::IConsumption::UTF16ToUTF8(const std::wstring& str) const
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

std::wstring blog::IConsumption::UTF8ToUTF16(const std::string& str) const
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

std::string blog::IConsumption::LevelToString(int level)
{
	std::string ret;
	switch (level)
	{
	case 0:
		ret = u8"FATAL";
		break;
	case 1:
		ret = u8"ERROR";
		break;
	case 2:
		ret = u8"WARNING";
		break;
	case 3:
		ret = u8"INFO";
		break;
	default:
		ret = u8"INFO_";
		ret += std::to_string(level);
		break;
	}
	return ret;
}

std::string blog::IConsumption::UTF8ToMultiByte(const std::string& str, unsigned code_page) const
{
	auto wstr = UTF8ToUTF16(str);
	return UTF16ToMultiByte(wstr, code_page);
}

std::string blog::IConsumption::UTF16ToMultiByte(const std::wstring& str, unsigned code_page) const
{
	std::string ret;

	constexpr size_t pre_prepared_buff_size = 1024;
	char pre_prepared_buff[pre_prepared_buff_size];

	char* buff = pre_prepared_buff;
	size_t buff_size = pre_prepared_buff_size;

	do
	{
		auto status = WideCharToMultiByte(code_page, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
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

		status = WideCharToMultiByte(code_page, 0, str.c_str(), -1, buff, status, nullptr, nullptr);
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
