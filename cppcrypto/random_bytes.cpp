/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "random_bytes.h"
#include "portability.h"
#include <fstream>
#include <stdexcept>

#ifdef __CYGWIN__
#include <Windows.h
#endif
#if defined(__FreeBSD__) || defined(__linux__)
#include <sys/random.h>
#endif

namespace cppcrypto
{

	void gen_random_bytes(char* buffer, size_t buflen)
	{
		gen_random_bytes(reinterpret_cast<unsigned char*>(buffer), buflen);
	}

	void gen_random_bytes(unsigned char* buffer, size_t buflen)
	{
#if defined(WIN32) || defined(__CYGWIN__)
		NTSTATUS s = BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, (PUCHAR)buffer, static_cast<ULONG>(buflen), 0);
		if (s)
			throw std::runtime_error("Cannot acquire crypto context!");
		return;

		HCRYPTPROV prov = 0;

		if (!CryptAcquireContext(&prov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		{
			Sleep(500);
			if (!CryptAcquireContext(&prov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
				throw std::runtime_error("Cannot acquire crypto context!");
		}

		if (!CryptGenRandom(prov, static_cast<DWORD>(buflen), buffer))
		{
			CryptReleaseContext(prov, 0);
			throw std::runtime_error("Cannot generate random bytes!");
		}

		if (!CryptReleaseContext(prov, 0))
			throw std::runtime_error("Cannot release crypto context!");
#elif defined(__FreeBSD__) || defined(__linux__)
		int nread;
		do
		{
			size_t sz = std::min(buflen, static_cast<size_t>(256));
			do
			{
				nread = getrandom(buffer, sz, 0);
			}
			while (nread < 0 && (errno == EINTR || errno == EAGAIN));
			if (nread != static_cast<int>(sz))
				throw std::runtime_error("Cannot acquire random bytes.");
			buflen -= sz;
			buffer += sz;
		}
		while (buflen > 0);
#else
		std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary);
		urandom.read((std::ifstream::char_type*)buffer, buflen);
		urandom.close();
#endif
	}

}

