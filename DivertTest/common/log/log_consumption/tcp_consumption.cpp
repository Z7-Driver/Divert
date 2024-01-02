#include <Ws2tcpip.h>
#include "tcp_consumption.h"
#include <algorithm>
#include "../blog_instance.h"


namespace blog
{

	TCPConsumption::TCPConsumption(const BlogOption& option)
	{
		type_ = option.Type;

		need_exit_ = false;
		s_ = INVALID_SOCKET;
		event_handle_ = nullptr;
		share_memory_handle_ = nullptr;
		share_memory_ptr_ = nullptr;

		base_event_name_ = option.Tcp.event_name;
		base_share_memory_name_ = option.Tcp.share_memory_name;
		RecreateShareInfo();

		commication_thread_ = std::thread(fnCommicationThread, this);
	}

	TCPConsumption::~TCPConsumption()
	{
		need_exit_ = true;

		CloseConnect();

		if (event_handle_ != nullptr)
		{
			CloseHandle(event_handle_);
			event_handle_ = nullptr;
		}

		log_data_cv_.notify_all();
		if (commication_thread_.joinable() == true)
		{
			commication_thread_.join();
		}

		if (share_memory_ptr_ != nullptr)
		{
			UnmapViewOfFile(share_memory_ptr_);
			share_memory_ptr_ = nullptr;
		}

		if (share_memory_handle_ != nullptr)
		{
			CloseHandle(share_memory_handle_);
			share_memory_handle_ = nullptr;
		}
	}

	void TCPConsumption::Record(const BLogInstance* log_instance)
	{
		if (share_memory_ptr_ == nullptr)
		{
			return;
		}

		if (s_.load() == INVALID_SOCKET)
		{
			return;
		}

		auto log_str = UTF8ToUTF16(log_instance->GetLogStr());

		size_t log_data_size = sizeof(LogData) + log_str.size() * sizeof(wchar_t);
		auto buff = new uint8_t[log_data_size];
		std::shared_ptr<uint8_t[]> buff_ptr(buff);

		memset(buff, 0, log_data_size);

		LogData* log_data = (LogData*)buff;
		log_data->size = (uint32_t)log_data_size;
		log_data->level = log_instance->GetLevel();
		log_data->line = log_instance->GetLine();
		log_data->system_time = log_instance->GetTime();
		log_data->process_id = GetCurrentProcessId();
		log_data->thread_id = GetCurrentThreadId();
		wcscpy_s(log_data->source_file, log_instance->GetSourceFile());
		wcscpy_s(log_data->log_data, log_str.size() + 1, log_str.c_str());

		std::unique_lock<std::mutex> lock(log_data_mutex_);
		// 如果积压log太多，说明发送出了问题，就不要继续插入
		if (log_data_queue_.size() < 0xFFFFFF)
		{
			log_data_queue_.push(buff_ptr);
		}
		log_data_cv_.notify_one();
	}

	bool TCPConsumption::WaitConsumer()
	{
		bool ret = true;

		if (WaitForSingleObject(event_handle_, 5000) != WAIT_OBJECT_0)
		{
			ret = false;
		}

		return ret;
	}

	bool TCPConsumption::ConnectToConsumer()
	{
		bool ret = false;

		do
		{
			if (share_memory_handle_ == nullptr)
			{
				std::this_thread::sleep_for(std::chrono::seconds(5));
				break;
			}

			TCPConfig* config = (TCPConfig*)share_memory_ptr_;
			if (config->version < TCPConfigVersion::V_1)
			{
				break;
			}

			sockaddr_in addr = { 0 };
			addr.sin_family = AF_INET;
			addr.sin_port = htons(config->port);
			inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

			s_.store(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
			if (s_ == INVALID_SOCKET)
			{
				break;
			}

			DWORD timeout = 1000;
			setsockopt(s_, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
			auto status = connect(s_, (const sockaddr*)&addr, sizeof(addr));
			if (status == SOCKET_ERROR)
			{
				if (event_handle_ != nullptr)
				{
					ResetEvent(event_handle_);
				}
				break;
			}

			ret = true;
		} while (false);

		return ret;
	}

	size_t TCPConsumption::GetLogQueueSize()
	{
		return log_data_queue_.size();
	}

	bool TCPConsumption::IsExiting()
	{
		return need_exit_;
	}

	void TCPConsumption::ClearLogQueue()
	{
		std::unique_lock<std::mutex> lock(log_data_mutex_);
		while (log_data_queue_.empty() == false)
		{
			log_data_queue_.pop();
		}
	}

	void TCPConsumption::SendLogToConsumer()
	{
		while (true)
		{
			std::unique_lock<std::mutex> lock(log_data_mutex_);
			log_data_cv_.wait(lock, [this]() -> bool {
				if (this->GetLogQueueSize() != 0 || this->IsExiting() == true)
				{
					return true;
				}
				else
				{
					return false;
				}
				});

			// 确保数据发送完毕再退出
			if (need_exit_ == true && log_data_queue_.size() == 0)
			{
				break;
			}

			auto data = log_data_queue_.front();
			log_data_queue_.pop();
			lock.unlock();

			LogData* log_data = (LogData*)data.get();
			auto status = send(s_.load(), (const char*)log_data, log_data->size, 0);
			if (status <= 0)
			{
				break;
			}
		}
	}

	void TCPConsumption::fnCommicationThread(TCPConsumption* consumption)
	{
		while (true)
		{
			if (consumption->need_exit_ == true)
			{
				break;
			}

			if (consumption->event_handle_ == nullptr)
			{
				break;
			}

			consumption->CloseConnect();
			consumption->ClearLogQueue();
			if (consumption->WaitConsumer() == false)
			{
				continue;
			}

			if (consumption->ConnectToConsumer() == false)
			{
				continue;
			}

			consumption->SendLogToConsumer();
		}
	}

	void TCPConsumption::CloseConnect()
	{
		auto old_s = s_.exchange(INVALID_SOCKET);
		if (old_s != INVALID_SOCKET)
		{
			closesocket(old_s);
		}
	}

	bool TCPConsumption::IsConnected() const noexcept
	{
		return s_.load() != INVALID_SOCKET;
	}

	void TCPConsumption::RecreateShareInfo()
	{
		const auto& event_name = base_event_name_;
		const auto& share_memory_name = base_share_memory_name_;

		if (event_handle_ != nullptr)
		{
			CloseHandle(event_handle_);
			event_handle_ = nullptr;
		}

		event_handle_ = CreateEventW(nullptr, TRUE, FALSE, event_name.c_str());

		if (share_memory_ptr_ != nullptr)
		{
			UnmapViewOfFile(share_memory_ptr_);
			share_memory_ptr_ = nullptr;
		}

		if (share_memory_handle_ != nullptr)
		{
			CloseHandle(share_memory_handle_);
			share_memory_handle_ = nullptr;
		}

		share_memory_handle_ = CreateFileMappingW(
			INVALID_HANDLE_VALUE,
			nullptr,
			PAGE_READWRITE,
			0,
			max(1024u, sizeof(TCPConfig)),
			share_memory_name.c_str());
		if (share_memory_handle_ != nullptr)
		{
			share_memory_ptr_ = MapViewOfFile(
				share_memory_handle_,
				FILE_MAP_ALL_ACCESS,
				0,
				0,
				max(1024u, sizeof(TCPConfig)));
		}
	}
}
