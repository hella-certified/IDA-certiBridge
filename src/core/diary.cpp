#include "diary.h"
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>

namespace core
{
	static std::string getCurrentIsoTime()
	{
		auto now = std::chrono::system_clock::now();
		auto inTime = std::chrono::system_clock::to_time_t(now);
		std::stringstream ss;
		ss << std::put_time(std::localtime(&inTime), "%Y-%m-%d %H:%M:%S");
		return ss.str();
	}

	nlohmann::json DumpInfo::toJson() const
	{
		return {
			{"id", id},
			{"filename", filename},
			{"idbPath", idbPath},
			{"architecture", architecture},
			{"imageBase", imageBase},
			{"md5", md5},
			{"hexRaysAvailable", hexRaysAvailable},
			{"analysisStatus", analysisStatus},
			{"port", port},
			{"lastSeen", lastSeen}
		};
	}

	DumpInfo DumpInfo::fromJson(const nlohmann::json& j)
	{
		DumpInfo info;
		info.id = j.value("id", "");
		info.filename = j.value("filename", "");
		info.idbPath = j.value("idbPath", "");
		info.architecture = j.value("architecture", "x86_64");
		info.imageBase = j.value("imageBase", "0x0");
		info.md5 = j.value("md5", "");
		info.hexRaysAvailable = j.value("hexRaysAvailable", false);
		info.analysisStatus = j.value("analysisStatus", "ready");
		info.port = static_cast<u16>(j.value("port", 0));
		info.lastSeen = j.value("lastSeen", getCurrentIsoTime());
		return info;
	}

	DiaryManager& DiaryManager::instance()
	{
		static DiaryManager s_instance;
		return s_instance;
	}

	void DiaryManager::registerDump(const DumpInfo& info)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		auto entry = info;
		entry.lastSeen = getCurrentIsoTime();
		m_dumps[entry.id.empty() ? entry.filename : entry.id] = entry;
	}

	void DiaryManager::unregisterDump(const std::string& id)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_dumps.erase(id);
	}

	std::vector<DumpInfo> DiaryManager::getActiveDumps() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		std::vector<DumpInfo> list;
		list.reserve(m_dumps.size());
		for (const auto& [_, dump] : m_dumps)
		{
			list.push_back(dump);
		}
		return list;
	}

	std::string DiaryManager::generateMarkdown() const
	{
		std::stringstream ss;
		ss << "# IDA Pro Binary Diary\n\n";
		ss << "Live registry of loaded binary dumps and active IDA sessions.\n";
		ss << "Last updated: `" << getCurrentIsoTime() << "`\n\n";

		if (m_dumps.empty())
		{
			ss << "> No active IDA dumps currently open.\n";
			return ss.str();
		}

		ss << "| Target / File | Port | Image Base | Arch | Hex-Rays | Status | Database Path |\n";
		ss << "|---|---|---|---|---|---|---|\n";

		for (const auto& [_, d] : m_dumps)
		{
			ss << "| **" << d.filename << "** | `" << d.port << "` | `" << d.imageBase << "` | "
			   << d.architecture << " | " << (d.hexRaysAvailable ? "Active" : "Unavailable") << " | "
			   << d.analysisStatus << " | `" << d.idbPath << "` |\n";
		}

		ss << "\n## Quick Decompile Reference\n\n";
		ss << "To query decompilation on any active dump:\n";
		ss << "```bash\n";
		ss << "# via runner\n";
		ss << "cargo run --manifest-path tools/runner/Cargo.toml -- decompile 0x...\n";
		ss << "# via curl\n";
		for (const auto& [_, d] : m_dumps)
		{
			if (d.port > 0)
			{
				ss << "curl -s \"http://127.0.0.1:" << d.port << "/api/decompile?ea=" << d.imageBase << "\"\n";
				break;
			}
		}
		ss << "```\n";

		return ss.str();
	}

	std::string DiaryManager::generateJson() const
	{
		nlohmann::json root = nlohmann::json::array();
		for (const auto& [_, d] : m_dumps)
		{
			root.push_back(d.toJson());
		}
		return root.dump(2);
	}

	void DiaryManager::save(const std::string& mdPath, const std::string& jsonPath)
	{
		std::lock_guard<std::mutex> lock(m_mutex);

		// sync markdown diary
		if (!mdPath.empty())
		{
			std::ofstream mdFile(mdPath);
			if (mdFile.is_open())
			{
				mdFile << generateMarkdown();
			}
		}

		// sync machine-readable json diary
		if (!jsonPath.empty())
		{
			std::ofstream jsonFile(jsonPath);
			if (jsonFile.is_open())
			{
				jsonFile << generateJson();
			}
		}
	}
}
