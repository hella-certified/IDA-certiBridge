#pragma once

#include "types.h"
#include <string>

namespace core
{
	struct Config
	{
		std::string portablePath;
		std::string pluginsPath;

		std::string host = "127.0.0.1";
		u16 basePort = 13371;
		u16 maxPort = 13390;

		std::string outputMarkdown = "DIARY.md";
		std::string outputJson = "diary.json";

		static Config load(const std::string& configPath = "config.toml");
	};
}
