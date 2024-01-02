#pragma once
#include "../blog_def.h"

namespace blog
{
	class BLogInstance;

	class IConsumption
	{
	public:
		// 该接口非线程安全
		virtual void Record(const BLogInstance* log_instance) = 0;

		std::string UTF16ToUTF8(const std::wstring& str) const;
		std::wstring UTF8ToUTF16(const std::string& str) const;
		std::string UTF8ToMultiByte(const std::string& str, unsigned code_page) const;
		std::string UTF16ToMultiByte(const std::wstring& str, unsigned code_page) const;
		std::string LevelToString(int level);
		
	};
}