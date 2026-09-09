#include "server.h"
#include "diary.h"
#include "sigscanner.h"
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

namespace core
{
	BridgeServer::BridgeServer(const Config& config)
		: m_config(config)
		, m_port(config.basePort)
		, m_server(std::make_unique<httplib::Server>())
	{
		setupRoutes();
	}

	BridgeServer::~BridgeServer()
	{
		stop();
	}

	void BridgeServer::setupRoutes()
	{
		m_server->Get("/api/status", [this](const httplib::Request&, httplib::Response& res)
		{
			nlohmann::json body = {
				{"status", "online"},
				{"version", "1.0.0"},
				{"port", m_port},
				{"activeDumps", DiaryManager::instance().getActiveDumps().size()}
			};
			res.set_content(body.dump(), "application/json");
		});

		m_server->Get("/api/dumps", [](const httplib::Request&, httplib::Response& res)
		{
			nlohmann::json arr = nlohmann::json::array();
			for (const auto& d : DiaryManager::instance().getActiveDumps())
			{
				arr.push_back(d.toJson());
			}
			res.set_content(arr.dump(2), "application/json");
		});

		m_server->Post("/api/dump/register", [this](const httplib::Request& req, httplib::Response& res)
		{
			try
			{
				auto j = nlohmann::json::parse(req.body);
				auto info = DumpInfo::fromJson(j);
				DiaryManager::instance().registerDump(info);
				DiaryManager::instance().save(m_config.outputMarkdown, m_config.outputJson);
				spdlog::info("registered dump: {} on port {}", info.filename, info.port);
				res.set_content("{\"status\":\"ok\"}", "application/json");
			}
			catch (const std::exception& e)
			{
				res.status = 400;
				res.set_content(nlohmann::json{{"error", e.what()}}.dump(), "application/json");
			}
		});

		m_server->Post("/api/dump/unregister", [this](const httplib::Request& req, httplib::Response& res)
		{
			try
			{
				auto j = nlohmann::json::parse(req.body);
				std::string id = j.value("id", "");
				DiaryManager::instance().unregisterDump(id);
				DiaryManager::instance().save(m_config.outputMarkdown, m_config.outputJson);
				res.set_content("{\"status\":\"ok\"}", "application/json");
			}
			catch (const std::exception& e)
			{
				res.status = 400;
				res.set_content(nlohmann::json{{"error", e.what()}}.dump(), "application/json");
			}
		});

		m_server->Get("/api/decompile", [](const httplib::Request& req, httplib::Response& res)
		{
			std::string ea = req.get_param_value("ea");
			if (ea.empty())
			{
				res.status = 400;
				res.set_content("{\"error\":\"missing ea param\"}", "application/json");
				return;
			}

			// proxy query to the first active dump if available
			auto dumps = DiaryManager::instance().getActiveDumps();
			if (dumps.empty() || dumps[0].port == 0)
			{
				res.status = 503;
				res.set_content("{\"error\":\"no active ida instance available\"}", "application/json");
				return;
			}

			u16 idaPort = dumps[0].port;
			httplib::Client cli("127.0.0.1", idaPort);
			cli.set_connection_timeout(5, 0);
			cli.set_read_timeout(10, 0);

			if (auto idaRes = cli.Get(("/api/decompile?ea=" + ea).c_str()))
			{
				res.status = idaRes->status;
				res.set_content(idaRes->body, idaRes->get_header_value("Content-Type").c_str());
			}
			else
			{
				res.status = 502;
				res.set_content("{\"error\":\"failed to reach ida plugin\"}", "application/json");
			}
		});

		m_server->Post("/api/sig/scan", [](const httplib::Request& req, httplib::Response& res)
		{
			try
			{
				auto j = nlohmann::json::parse(req.body);
				std::string pattern = j.value("pattern", "");
				std::string hexData = j.value("bytes", "");
				uint64_t baseEa = 0;
				if (j.contains("baseEa"))
				{
					if (j["baseEa"].is_number())
					{
						baseEa = j["baseEa"].get<uint64_t>();
					}
					else if (j["baseEa"].is_string())
					{
						std::string s = j["baseEa"].get<std::string>();
						baseEa = std::stoull(s, nullptr, 0);
					}
				}

				int ripOffset = j.value("ripOffset", -1);
				int insnLen = j.value("insnLen", -1);

				std::vector<uint8_t> byteBuf;
				for (size_t i = 0; i + 1 < hexData.size(); i += 2)
				{
					while (i < hexData.size() && (hexData[i] == ' ' || hexData[i] == ','))
					{
						++i;
					}
					if (i + 1 >= hexData.size())
					{
						break;
					}
					byteBuf.push_back(static_cast<uint8_t>(std::stoul(hexData.substr(i, 2), nullptr, 16)));
				}

				auto matches = SigScanner::scan(byteBuf.data(), byteBuf.size(), baseEa, pattern, ripOffset, insnLen);
				nlohmann::json matchArr = nlohmann::json::array();
				for (const auto& m : matches)
				{
					nlohmann::json item = {
						{"ea", fmt::format("0x{:x}", m.ea)},
						{"offset", m.offset}
					};
					if (ripOffset >= 0 && insnLen > 0)
					{
						item["disp32"] = m.disp32;
						item["ripTarget"] = fmt::format("0x{:x}", m.ripTarget);
					}
					matchArr.push_back(item);
				}

				nlohmann::json respBody = {
					{"success", true},
					{"pattern", pattern},
					{"matchCount", matches.size()},
					{"matches", matchArr}
				};
				res.set_content(respBody.dump(), "application/json");
			}
			catch (const std::exception& e)
			{
				res.status = 400;
				res.set_content(nlohmann::json{{"success", false}, {"error", e.what()}}.dump(), "application/json");
			}
		});
	}

	bool BridgeServer::start()
	{
		if (m_running)
		{
			return true;
		}

		for (u16 p = m_config.basePort; p <= m_config.maxPort; ++p)
		{
			if (m_server->bind_to_port(m_config.host.c_str(), p))
			{
				m_port = p;
				m_running = true;
				m_thread = std::thread([this]()
				{
					m_server->listen_after_bind();
				});
				spdlog::info("certiBridge server listening on http://{}:{}", m_config.host, m_port);
				return true;
			}
		}

		spdlog::error("failed to bind to any port in range {}-{}", m_config.basePort, m_config.maxPort);
		return false;
	}

	void BridgeServer::stop()
	{
		if (!m_running)
		{
			return;
		}
		m_running = false;
		if (m_server)
		{
			m_server->stop();
		}
		if (m_thread.joinable())
		{
			m_thread.join();
		}
	}
}
