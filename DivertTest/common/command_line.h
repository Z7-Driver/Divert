#pragma once

namespace common {
	namespace misc
	{
		class CommandLine
		{


		public:
			CommandLine();
			~CommandLine();
			bool SetCmd(const std::wstring& cmd);
			const std::wstring& GetMainOperation();
			int64_t GetCmdIntValue(const std::wstring& key, int64_t default_value);
			std::wstring GetCmdWstrValue(const std::wstring& key, const std::wstring& default_value);
			std::string GetCmdStrValue(const std::wstring& key, const std::string& default_value);

		private:
			std::wstring main_;
			std::map<std::wstring, std::wstring> cmd_map_;
		};
	}
}



