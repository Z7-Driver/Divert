#pragma once
#include <Windows.h>
#include <cstdio>
#include <vector>
#include <memory>
#include <cstdint>
#include <string>
#include <shared_mutex>
#include "log_consumption/consumption_interface.h"

namespace blog
{
	
	class BLogInstance;
	// 整个生命周期唯一
	class BLogManager
	{
	private:
		BLogManager();
		BLogManager(const BLogManager&) = delete;
		BLogManager(BLogManager&&) = delete;
		~BLogManager();
	public:
		static BLogManager* GetInstance() noexcept;

		static void UpdateBlogOption(const BlogOption& option);
	public:
		static void fnSendLog(const BLogInstance* log_instance);

	private:
		// 影响log的选项
		BlogOption blog_option_;
		// 日志消费者
		std::vector<std::shared_ptr<IConsumption>> consumer_;
		// 
		std::shared_mutex consumer_lock_;
	};
}