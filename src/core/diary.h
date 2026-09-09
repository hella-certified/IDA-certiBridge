#pragma once

#include "types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace core
{
	struct DumpInfo
	{
		std::string id;
		std::string filename;
		std::string idbPath;
		std::string architecture;
		std::string imageBase;
		std::string md5;
		bool hexRaysAvailable = false;
		std::string analysisStatus = "ready";
		u16 port = 0;
		std::string lastSeen;

		nlohmann::json toJson() const;
		static DumpInfo fromJson(const nlohmann::json& j);
	};

	class DiaryManager
	{
	public:
		static DiaryManager& instance();

		void registerDump(const DumpInfo& info);
		void unregisterDump(const std::string& id);
		std::vector<DumpInfo> getActiveDumps() const;

		void save(const std::string& mdPath, const std::string& jsonPath);

	private:
		DiaryManager() = default;
		mutable std::mutex m_mutex;
		std::unordered_map<std::string, DumpInfo> m_dumps;

		std::string generateMarkdown() const;
		std::string generateJson() const;
	};
}
