#include "common_head.h"
#include "command_line.h"
#include <log/blog.h>
#include "common.h"
namespace common {
	namespace misc
	{
		CommandLine::CommandLine()
		{
			main_.clear();
			cmd_map_.clear();
		}

		CommandLine::~CommandLine()
		{
		}
		bool CommandLine::SetCmd(const std::wstring& cmd)
		{
			BLOGW(INFO) << L"收到命令:" << cmd;
			bool ret = false;
			main_.clear();
			cmd_map_.clear();

			do
			{
				auto main_ops = cmd.find(L" ");
				if (main_ops == cmd.npos)
				{
					break;
				}
				main_ = cmd.substr(0, main_ops);
				if (main_.length() == 0)
				{
					BLOGW(ERRORB) << L"无效主命令";
					break;
				}
				if (main_ops == cmd.length())
				{
					ret = true;
					break;
				}
				main_ops++;
				std::wstring primary_cmd = cmd.substr(main_ops);
				std::vector<std::wstring> vec_cmd = common::string::wstrSplit(primary_cmd, L" ");
				std::wstring key = L"", value = L"";
				for (size_t index_cmd = 0; index_cmd < vec_cmd.size(); index_cmd++)
				{
					if (vec_cmd[index_cmd].length() == 0)
					{
						continue;
					}
					if (vec_cmd[index_cmd][0] == L'/')
					{
						key = vec_cmd[index_cmd];
						continue;
					}
					if (key.length() > 0)
					{
						value = vec_cmd[index_cmd];
						cmd_map_.emplace(std::pair<std::wstring, std::wstring>(key, value));
						key.clear();
						value.clear();
					}
				}
				ret = true;
			} while (false);
			return ret;
		}
		const std::wstring& CommandLine::GetMainOperation()
		{
			return main_;
		}
		int64_t CommandLine::GetCmdIntValue(const std::wstring& key, int64_t default_value)
		{
			int64_t ret = default_value;
			auto iter = cmd_map_.find(key);
			if (iter != cmd_map_.end())
			{
				std::wstring value = iter->second;
				ret = std::stoi(value);
			}
			return ret;
		}
		std::wstring CommandLine::GetCmdWstrValue(const std::wstring& key, const std::wstring& default_value)
		{
			std::wstring ret = default_value;
			auto iter = cmd_map_.find(key);
			if (iter != cmd_map_.end())
			{
				ret = iter->second;
			}
			return ret;

		}

		std::string CommandLine::GetCmdStrValue(const std::wstring& key, const std::string& default_value)
		{
			std::string ret = default_value;
			auto iter = cmd_map_.find(key);
			if (iter != cmd_map_.end())
			{
				ret = common::string::SysWideToUTF8(iter->second);
			}
			return ret;
		}
	}
}