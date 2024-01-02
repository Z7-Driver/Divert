#include "blog_manager.h"
#include "log_consumption/file_consumption.h"
#include "log_consumption/tcp_consumption.h"
#include "log_consumption/console_consumption.h"

namespace blog
{
	BLogManager::BLogManager()
	{

	}

	BLogManager::~BLogManager()
	{
		std::unique_lock<std::shared_mutex> lock(consumer_lock_);
		consumer_.clear();
	}

	BLogManager* BLogManager::GetInstance() noexcept
	{
		static BLogManager manager;
		return &manager;
	}

	void BLogManager::UpdateBlogOption(const BlogOption& option)
	{
		auto manager = BLogManager::GetInstance();
		manager->blog_option_ = option;

		std::shared_lock<std::shared_mutex> lock(manager->consumer_lock_);

		// 移除所有日志，重新构建
		manager->consumer_.clear();

		if (option.File.enable == true)
		{
			manager->consumer_.push_back(std::make_shared<FileConsumption>(option));
		}
		
		if (option.Tcp.enable == true)
		{
			manager->consumer_.push_back(std::make_shared<TCPConsumption>(option));
		}
		if (option.Console.enable == true)
		{
			manager->consumer_.push_back(std::make_shared<ConsoleConsumption>(option));
		}
	}

	void BLogManager::fnSendLog(const BLogInstance* log_instance)
	{
		auto manager = BLogManager::GetInstance();

		std::shared_lock<std::shared_mutex> lock(manager->consumer_lock_);
		for (const auto& consumer_item : manager->consumer_)
		{
			consumer_item->Record(log_instance);
		}
	}
}