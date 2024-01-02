#include "console_consumption.h"
#include "../blog_instance.h"
#include <Windows.h>
#include <iomanip>
#pragma comment(lib, "Ws2_32.lib")

namespace blog
{
	ConsoleConsumption::ConsoleConsumption(const BlogOption& option)
	{
		console_output_cp_ = GetConsoleOutputCP();
	}

	ConsoleConsumption::~ConsoleConsumption()
	{
	}

	void ConsoleConsumption::Record(const BLogInstance* log_instance)
	{

		auto log_str = log_instance->GetLogStr();
		auto log_time = log_instance->GetTime();

		std::stringstream ss;
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

		if (console_output_cp_ != CP_UTF8)
		{
			result_log_str = UTF8ToMultiByte(result_log_str, console_output_cp_);
		}

		printf_s("%s", result_log_str.c_str());
	}
}