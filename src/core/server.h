#pragma once

#include "types.h"
#include "config.h"
#include <memory>
#include <thread>
#include <atomic>

namespace httplib
{
	class Server;
}

namespace core
{
	class BridgeServer
	{
	public:
		BridgeServer(const Config& config);
		~BridgeServer();

		bool start();
		void stop();
		u16 getPort() const { return m_port; }

	private:
		void setupRoutes();

		Config m_config;
		u16 m_port = 0;
		std::unique_ptr<httplib::Server> m_server;
		std::thread m_thread;
		std::atomic<bool> m_running{false};
	};
}
