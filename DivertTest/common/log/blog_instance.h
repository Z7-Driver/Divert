#pragma once
#include <sstream>
#include <Windows.h>

namespace blog
{
	class BLogInstance
	{
	public:
		BLogInstance(int level, size_t line, const wchar_t* source_file, bool use_widechar) noexcept;
		~BLogInstance() noexcept;

		// 返回UTF8编码字符串
		std::string GetLogStr() const;
		size_t GetLine() const noexcept;
		const wchar_t* GetSourceFile() const noexcept;
		SYSTEMTIME GetTime() const noexcept;
		int GetLevel() const noexcept;

		std::wstringstream& GetInputUTF16() noexcept;
		std::stringstream& GetInputUTF8() noexcept;
	public:
		static std::string UTF16ToUTF8(const std::wstring& str);
		static std::wstring UTF8ToUTF16(const std::string& str);
	private:
		bool use_widechar_;
		std::wstringstream wss_;
		std::stringstream ss_;

		size_t line_;
		const wchar_t* source_file_;
		SYSTEMTIME st_;
		int level_;
	};
}