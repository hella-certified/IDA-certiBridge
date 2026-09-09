#include "sigscanner.h"
#include <sstream>
#include <cstring>
#include <algorithm>

namespace core
{
	std::vector<uint8_t> SigScanner::parsePattern(const std::string& patternStr, std::vector<uint8_t>& mask)
	{
		std::vector<uint8_t> patternBytes;
		mask.clear();

		std::istringstream stream(patternStr);
		std::string token;

		while (stream >> token)
		{
			if (token == "?" || token == "??")
			{
				patternBytes.push_back(0x00);
				mask.push_back(0x00);
			}
			else
			{
				try
				{
					auto val = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
					patternBytes.push_back(val);
					mask.push_back(0xFF);
				}
				catch (...)
				{
					patternBytes.push_back(0x00);
					mask.push_back(0x00);
				}
			}
		}

		return patternBytes;
	}

	uint64_t SigScanner::resolveRip(uint64_t matchEa, int ripOffset, int insnLen, int32_t disp32)
	{
		(void)ripOffset;
		return matchEa + static_cast<uint64_t>(insnLen) + static_cast<int64_t>(disp32);
	}

	std::vector<SigMatch> SigScanner::scan(
		const uint8_t* data,
		size_t dataSize,
		uint64_t baseEa,
		const std::string& patternStr,
		int ripOffset,
		int insnLen,
		size_t maxMatches
	)
	{
		std::vector<SigMatch> matches;
		if (!data || dataSize == 0)
		{
			return matches;
		}

		std::vector<uint8_t> mask;
		auto pat = parsePattern(patternStr, mask);
		if (pat.empty() || pat.size() > dataSize)
		{
			return matches;
		}

		const size_t patSize = pat.size();
		const size_t endPos = dataSize - patSize;

		for (size_t i = 0; i <= endPos && matches.size() < maxMatches; ++i)
		{
			bool found = true;
			for (size_t j = 0; j < patSize; ++j)
			{
				if (mask[j] == 0xFF && data[i + j] != pat[j])
				{
					found = false;
					break;
				}
			}

			if (found)
			{
				SigMatch m;
				m.offset = i;
				m.ea = baseEa + i;

				if (ripOffset >= 0 && insnLen > 0 && (i + static_cast<size_t>(ripOffset) + 4) <= dataSize)
				{
					int32_t disp = 0;
					std::memcpy(&disp, data + i + ripOffset, sizeof(int32_t));
					m.disp32 = disp;
					m.ripTarget = resolveRip(m.ea, ripOffset, insnLen, disp);
				}

				matches.push_back(m);
			}
		}

		return matches;
	}
}
