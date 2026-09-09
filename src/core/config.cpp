#include "config.h"
#include <toml++/toml.hpp>
#include <fstream>

namespace core
{
	Config Config::load(const std::string& configPath)
	{
		Config cfg;
		std::ifstream file(configPath);
		if (!file.is_open())
		{
			return cfg;
		}

		try
		{
			auto tbl = toml::parse(file);
			if (auto ida = tbl["ida"])
			{
				cfg.portablePath = ida["portablePath"].value_or("");
				cfg.pluginsPath = ida["pluginsPath"].value_or("");
			}
			if (auto bridge = tbl["bridge"])
			{
				cfg.host = bridge["host"].value_or("127.0.0.1");
				cfg.basePort = static_cast<u16>(bridge["basePort"].value_or(13371));
				cfg.maxPort = static_cast<u16>(bridge["maxPort"].value_or(13390));
			}
			if (auto diary = tbl["diary"])
			{
				cfg.outputMarkdown = diary["outputMarkdown"].value_or("DIARY.md");
				cfg.outputJson = diary["outputJson"].value_or("diary.json");
			}
		}
		catch (...)
		{
		}

		return cfg;
	}
}
