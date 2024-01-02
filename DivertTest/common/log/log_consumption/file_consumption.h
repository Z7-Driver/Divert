#pragma once
#include "consumption_interface.h"
#include <cstdio>
#include <cstdint>
#include <string>
#include <mutex>
#include <chrono>
#include <Windows.h>
#include <map>

namespace blog
{
	class FileConsumption : public IConsumption
	{
	public:
		FileConsumption(const BlogOption& option);
		~FileConsumption();

		void SetMaxLogFileSize(uint64_t max_size = UINT64_MAX);
		void SetLogDir(const wchar_t* dir);
		void SetLogFileName(const wchar_t* name);
		void SetLogExtName(const wchar_t* ext_name);
	public:
		// 通过 IConsumption 继承
		virtual void Record(const BLogInstance* log_instance) override;

	private:
		// 以追加模式打开一个日志文件
		bool OpenLogFile();
		// 将日志文件关闭，重命名，新建一个日志文件
		bool ReopenNewLogFile();

		// 获取当前的所有日志文件
		std::map<uint64_t, std::wstring> GetAllLogFile();

		void RemoveOldLogFile();

		constexpr uint64_t MakeUint64(uint32_t low, uint32_t high)
		{
			return ((uint64_t)high) << 32 | (uint64_t)low;
		}
	private:
		// 日志文件句柄
		HANDLE log_file_handle_;
		// 日志文件操作与配置操作的锁
		std::mutex log_mutex;

		bool enable_;
		// 最大日志文件大小
		int64_t max_log_file_size_;
		// 当前日志文件大小
		int64_t current_log_file_size_;
		// 路径
		std::wstring base_dir_;
		// 日志文件名
		std::wstring base_name_;
		// 日志扩展名
		std::wstring log_file_ext_;
		// LOG前缀
		std::string log_prefix_;
		// 最小日志等级
		int min_log_level_;
		// 打印到内存
		bool print_to_memory_;
		// 最大日志数量
		size_t max_log_file_count_;

		// 磁盘刷新间隔 单位秒
		int64_t flush_interval_;
		// 上次写数据时间
		std::chrono::time_point<std::chrono::system_clock> last_flush_time_;
	};
}