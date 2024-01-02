#pragma once

#include "consumption_interface.h"

namespace blog
{
	class ConsoleConsumption : public IConsumption
	{
	public:
		ConsoleConsumption(const BlogOption& option);
		~ConsoleConsumption();

	public:
		// 通过 IConsumption 继承
		virtual void Record(const BLogInstance* log_instance) override;

	private:
		// 控制台编码
		unsigned console_output_cp_;
	};
}