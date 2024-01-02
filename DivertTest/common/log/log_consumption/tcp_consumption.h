#pragma once
#include "consumption_interface.h"
#include <queue>
#include "../blog.h"
#include <winsock.h>

namespace blog
{
	enum class TCPConfigVersion : uint32_t
	{
		V_1 = 1,
	};

	struct _TCPConfig_1_0
	{
		// 当前版本
		TCPConfigVersion version;
		// 要连接的端口
		uint32_t port;
	};
	using TCPConfig = struct _TCPConfig_1_0;

	struct _LogData
	{
		uint32_t size;
		int32_t level;
		uint32_t line;
		uint32_t process_id;
		uint32_t thread_id;
		SYSTEMTIME system_time;
		wchar_t source_file[256];
		wchar_t log_data[1];
	};
	using LogData = struct _LogData;

	

	class TCPConsumption : public IConsumption
	{
	public:
		TCPConsumption(const BlogOption& option);
		~TCPConsumption();

	public:
		// 通过 IConsumption 继承
		virtual void Record(const BLogInstance* log_instance) override;

		size_t GetLogQueueSize();
		bool IsExiting();
	private:
		bool WaitConsumer();
		bool ConnectToConsumer();
		
		void ClearLogQueue();
		void SendLogToConsumer();
		static void fnCommicationThread(TCPConsumption* consumption);

		void CloseConnect();
		bool IsConnected() const noexcept;

		void RecreateShareInfo();
	private:
		std::wstring base_event_name_;
		std::wstring base_share_memory_name_;

		blog::BlogType type_;
		// 通知有外部程序的event
		HANDLE event_handle_;
		// 共享内存句柄
		HANDLE share_memory_handle_;
		// 共享内存指针
		void* share_memory_ptr_;

		bool need_exit_;
		std::thread commication_thread_;
		// 通信套接字，UDP IPv4
		std::atomic<SOCKET> s_;

		std::mutex log_data_mutex_;
		std::condition_variable log_data_cv_;
		std::queue<std::shared_ptr<uint8_t[]>> log_data_queue_;
	};
}