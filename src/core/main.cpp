#include "config.h"
#include "server.h"
#include "diary.h"
#include <spdlog/spdlog.h>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

static std::atomic<bool> g_shutdownRequested{false};

static void signalHandler(int)
{
	g_shutdownRequested = true;
}

int main(int argc, char* argv[])
{
	(void)argc;
	(void)argv;
	std::signal(SIGINT, signalHandler);
	std::signal(SIGTERM, signalHandler);

	spdlog::set_pattern("[%H:%M:%S] [%^%l%$] %v");
	spdlog::info("starting IDA-certiBridge core daemon...");

	auto config = core::Config::load("config.toml");
	core::BridgeServer server(config);

	if (!server.start())
	{
		spdlog::critical("could not start server");
		return 1;
	}

	core::DiaryManager::instance().save(config.outputMarkdown, config.outputJson);

	while (!g_shutdownRequested)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}

	spdlog::info("stopping server...");
	server.stop();
	return 0;
}
