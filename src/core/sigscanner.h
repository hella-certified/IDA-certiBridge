#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace core
{
	struct SigMatch
	{
		uint64_t ea{0};
		size_t offset{0};
		int32_t disp32{0};
		uint64_t ripTarget{0};
	};

	class SigScanner
	{
	public:
		static std::vector<uint8_t> parsePattern(const std::string& patternStr, std::vector<uint8_t>& mask);

		static std::vector<SigMatch> scan(
			const uint8_t* data,
			size_t dataSize,
			uint64_t baseEa,
			const std::string& patternStr,
			int ripOffset = -1,
			int insnLen = -1,
			size_t maxMatches = 50
		);

		static uint64_t resolveRip(uint64_t matchEa, int ripOffset, int insnLen, int32_t disp32);
	};
}
