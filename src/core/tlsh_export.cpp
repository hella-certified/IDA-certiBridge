#include <tlsh.h>
#include <cstring>
#include <vector>

#ifdef _WIN32
#define EXPORT_API __declspec(dllexport)
#else
#define EXPORT_API __attribute__((visibility("default")))
#endif

extern "C"
{
	EXPORT_API int tlshHashBytes(const unsigned char* data, unsigned int len, char* outBuffer, unsigned int bufferLen)
	{
		if (!data || len == 0 || !outBuffer || bufferLen < 72)
		{
			return -1;
		}

		std::vector<unsigned char> padded;
		const unsigned char* hashInput = data;
		unsigned int inputLen = len;

		if (len < 50)
		{
			padded.reserve(50);
			while (padded.size() < 50)
			{
				for (unsigned int i = 0; i < len && padded.size() < 50; ++i)
				{
					padded.push_back(data[i]);
				}
			}
			hashInput = padded.data();
			inputLen = static_cast<unsigned int>(padded.size());
		}

		Tlsh tlsh;
		tlsh.update(hashInput, inputLen);
		tlsh.final();

		const char* hashStr = tlsh.getHash();
		if (!hashStr || std::strlen(hashStr) == 0)
		{
			return -2;
		}

		std::strncpy(outBuffer, hashStr, bufferLen - 1);
		outBuffer[bufferLen - 1] = '\0';
		return 0;
	}

	EXPORT_API int tlshCompare(const char* hash1, const char* hash2)
	{
		if (!hash1 || !hash2)
		{
			return -1;
		}

		Tlsh t1;
		Tlsh t2;
		if (t1.fromTlshStr(hash1) != 0)
		{
			return -2;
		}
		if (t2.fromTlshStr(hash2) != 0)
		{
			return -3;
		}

		return t1.totalDiff(&t2);
	}
}
