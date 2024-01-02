#pragma once
#include <stdint.h>
#include <string>

namespace blog
{

	enum class BLogLevel
	{
		FATAL = 0,
		ERRORB,
		WARNING,
		INFO
	};

	enum class BlogType
	{
		// 水印
		WATERMARK,
		// DLP
		DLP,
		// Kill
		KILL,
	};

	struct _BlogOption
	{
		// 区分水印 or DLP
		BlogType Type;
		struct _File
		{
			// 是否启用
			bool enable;
			// 是否打印到内存
			bool print_to_memory;
			// 日志文件最多有几个
			uint32_t max_log_file_count;
			// 最大日志文件大小
			uint64_t max_log_file_size;
			// 日志所在路径
			std::wstring base_dir;
			// 日志名
			std::wstring base_name;
			// 日志扩展
			std::wstring log_file_ext;
			// 前缀
			std::string prefix;
			// 日志刷写进文件的间隔
			int64_t flush_interval;
			// 处理的日志等级
			int min_log_level;
		}File;

		struct _Tcp
		{
			bool enable;
			std::wstring event_name;
			std::wstring share_memory_name;
		}Tcp;

		struct _Console
		{
			bool enable;
		}Console;
	};
	using BlogOption = struct _BlogOption;
}
