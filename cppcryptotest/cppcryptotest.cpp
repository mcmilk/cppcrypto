/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "stdafx.h"
#include "perftimer.h"
#include <sys/stat.h>
#include <string>
#include <algorithm>
#include <sstream>
#include <numeric>
#include <thread>
#include <future>
#include <set>

#include "compatibility.h"
#include "rc6.h"

#define CPPCRYPTO_DEBUG

using namespace cppcrypto; //FIXME remove this using

void hex2array(const std::string& hex, std::basic_string<unsigned char>& array)
{
	array.resize(hex.size() / 2);
	const char* pos = hex.c_str();
	for (size_t count = 0; count < hex.size() / 2; count++) {
		sscanf_s(pos, "%2hhx", &array[0] + count);
		pos += 2;
	}
}


long long file_size(const wchar_t* pathname)
{
	struct _stat64 st_stat;

	return _wstat64(pathname, &st_stat) ? -1 : st_stat.st_size;
}

bool file_exists(const wchar_t* path)
{
	struct _stat64 st_stat;

	return !_wstat64(path, &st_stat);
}

inline std::wstring& rtrim(std::wstring& str, const wchar_t* chars = _T(" \t\r\n"))
{
	return str.erase(str.find_last_not_of(chars) + 1);
}

bool is_directory(const wchar_t* path)
{
	std::wstring spath(path);
	struct _stat64 st_stat;

	rtrim(spath, _T("/\\"));

	if (spath.length() > 1 && *spath.rbegin() == _T(':'))
		spath += _T('/');

	return !_wstat64(spath.c_str(), &st_stat) && (st_stat.st_mode & S_IFDIR);
}

void perftest(std::map<std::wstring, std::unique_ptr<crypto_hash>>& hashes, long iterations, std::wstring filename, size_t outputsize)
{
	perftimer timer;

	if (!file_exists(filename.c_str())) {
		std::wcerr << filename << _T(": No such file or directory") << std::endl;
		return;
	}
	if (is_directory(filename.c_str())) {
		std::wcerr << filename << _T(": Is a directory") << std::endl;
		return;
	}

	long long fileSize = file_size(filename.c_str());

	if (fileSize > 20000000000)
	{
		std::cerr << "File is too big.\n";
		return;
	}

	char* message = new char[static_cast<size_t>(fileSize)];

	std::ifstream file;
	file.open(filename, std::ios::in | std::ios::binary);
	if (!file)
		return;

	if (!file.read(message, fileSize))
		return;

	file.close();
	unsigned char hash[128];

	for (auto it = hashes.begin(); it != hashes.end(); ++it)
	{
		if (it->second->hashsize() != outputsize)
			continue;
		std::wcout << std::setfill(_T(' ')) << std::setw(14) << it->first << _T(" ");

		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			it->second->hash_string(message, static_cast<size_t>(fileSize), hash);
		}
		double seconds = timer.elapsed();
		std::wcout << std::fixed << std::setprecision(5) << seconds << _T(" (") << std::setprecision(2)
			<< (static_cast<double>(fileSize) / 1024.0 / 1024.0 * static_cast<double>(iterations) / seconds) << _T(" MB/s) ");
		for (size_t i = 0; i < (it->second->hashsize() + 7) / 8; i++)
			std::wcout << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)hash[i];
		std::wcout << std::endl;
	}
}

void bcperftest(std::map<std::wstring, std::unique_ptr<block_cipher>>& ciphers, long iterations, std::wstring filename)
{
	perftimer timer;

	if (!file_exists(filename.c_str())) {
		std::wcerr << filename << _T(": No such file or directory") << std::endl;
		return;
	}
	if (is_directory(filename.c_str())) {
		std::wcerr << filename << _T(": Is a directory") << std::endl;
		return;
	}

	long long fileSize = file_size(filename.c_str());

	if (fileSize > 20000000000)
	{
		std::cerr << "File is too big.\n";
		return;
	}

	char* message = new char[static_cast<size_t>(fileSize)];

	std::ifstream file;
	file.open(filename, std::ios::in | std::ios::binary);
	if (!file)
		return;

	if (!file.read(message, fileSize))
		return;

	file.close();
	size_t bufsize = static_cast<size_t>(fileSize + 1024 * 2);
	unsigned char* ct = new unsigned char[static_cast<size_t>(bufsize)];
	unsigned char* pt = new unsigned char[static_cast<size_t>(bufsize)];
	unsigned char key[1024];
	unsigned char iv[1025];
	unsigned char* next = ct;
	gen_random_bytes(key, sizeof(key));
	gen_random_bytes(iv, sizeof(iv));
	std::wcout << _T("Cipher\t\tCBC encrypt\t\tCBC decrypt\t\tCTR encrypt\t\tCTR decrypt") << std::endl;
	for (auto it = ciphers.begin(); it != ciphers.end(); ++it)
	{
		memset(ct, 0, bufsize);
		memset(pt, 0, bufsize);
		std::wcout << it->first << _T(" ");
		cbc cbc(*it->second);
		ctr ctr(*it->second);
		timer.reset();
		size_t resultlen;
		for (long i = 0; i < iterations; i++)
		{
			cbc.init(key, it->second->keysize() / 8, iv, it->second->blocksize() / 8, block_cipher::encryption);
			next = ct;
			cbc.encrypt_update((unsigned char*)message, static_cast<size_t>(fileSize), ct, resultlen);
			next += resultlen;
			cbc.encrypt_final(next, resultlen);
		}
		next += resultlen;
		double seconds = timer.elapsed();
		std::wcout << std::fixed << std::setprecision(5) << seconds << _T(" (") << std::setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s) ");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream ofile(filename + _T(".") + it->first + _T(".cbc.encrypted"), ios::out | ios::binary);
		ofile.write((const char*)ct, next - ct);
#endif

		unsigned char* next2 = pt;
		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			cbc.init(key, it->second->keysize() / 8, iv, it->second->blocksize() / 8, block_cipher::decryption);
			next2 = pt;
			cbc.decrypt_update((unsigned char*)ct, next - ct, next2, resultlen);
			next2 += resultlen;
			cbc.decrypt_final(next2, resultlen);
		}
		next2 += resultlen;
		seconds = timer.elapsed();
		std::wcout << std::fixed << std::setprecision(5) << seconds << _T(" (") << std::setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s)");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream odfile(filename + _T(".") + it->first + _T(".cbc.decrypted"), ios::out | ios::binary);
		odfile.write((const char*)pt, next2 - pt);
#endif

		if (memcmp(pt, message, static_cast<size_t>(fileSize)))
			std::wcout << _T(" ERROR");
		if (fileSize != next2 - pt)
			std::wcout << _T(" SZMISMATCH");

		memset(ct, 0, bufsize);
		memset(pt, 0, bufsize);
		std::wcout << _T(" ");
		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			ctr.init(key, it->second->keysize() / 8, iv, it->second->blocksize() / 8);
			ctr.encrypt((unsigned char*)message, static_cast<size_t>(fileSize), ct);
		}
		seconds = timer.elapsed();
		std::wcout << std::fixed << std::setprecision(5) << seconds << _T(" (") << std::setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s) ");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream octrfile(filename + _T(".") + it->first + _T(".ctr.encrypted"), ios::out | ios::binary);
		octrfile.write((const char*)ct, fileSize);
#endif

		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			ctr.init(key, it->second->keysize() / 8, iv, it->second->blocksize() / 8);
			ctr.decrypt((unsigned char*)ct, static_cast<size_t>(fileSize), pt);
		}
		seconds = timer.elapsed();
		std::wcout << std::fixed << std::setprecision(5) << seconds << _T(" (") << std::setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s)");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream odctrfile(filename + _T(".") + it->first + _T(".ctr.decrypted"), ios::out | ios::binary);
		odctrfile.write((const char*)pt, fileSize);
#endif

		if (memcmp(pt, message, static_cast<size_t>(fileSize)))
			std::wcout << _T(" ERROR");

		std::wcout << _T(" ");

		std::wcout << std::endl;
	}

	delete[] ct;
	delete[] pt;
}

void perftest(std::map<std::wstring, std::unique_ptr<crypto_hash>>& hashes, long iterations, std::wstring filename)
{
	std::array<size_t, 7> output_sizes{ 128, 160, 224, 256, 384, 512, 1024 };

	for (size_t outputsize : output_sizes)
	{
		std::wcout << _T("\nHashes with output size ") << std::dec << outputsize << _T("bits:") << std::endl;
		perftest(hashes, iterations, filename, outputsize);
	}
}

void aeadperftest(std::map<std::wstring, std::unique_ptr<aead>>& ciphers, long iterations, std::wstring filename)
{
	perftimer timer;

	if (!file_exists(filename.c_str())) {
		std::wcerr << filename << _T(": No such file or directory") << std::endl;
		return;
	}
	if (is_directory(filename.c_str())) {
		std::wcerr << filename << _T(": Is a directory") << std::endl;
		return;
	}

	long long fileSize = file_size(filename.c_str());

	if (fileSize > 20000000000)
	{
		std::cerr << "File is too big.\n";
		return;
	}

	char* message = new char[static_cast<size_t>(fileSize)];

	std::ifstream file;
	file.open(filename, std::ios::in | std::ios::binary);
	if (!file)
		return;

	if (!file.read(message, fileSize))
		return;

	file.close();
	std::string ct, pt;
	unsigned char key[1024];
	unsigned char ad[1024];
	gen_random_bytes(key, sizeof(key));
	gen_random_bytes(ad, sizeof(ad));

	std::wcout << _T("Cipher\t\tAEAD encrypt\t\tAEAD decrypt") << std::endl;
	for (auto it = ciphers.begin(); it != ciphers.end(); ++it)
	{
		std::wcout << it->first << _T(" ");
		ct.resize(static_cast<size_t>(fileSize) + it->second->tag_bytes() + it->second->iv_bytes());
		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			it->second->set_key(key, it->second->key_bytes());
			it->second->encrypt(reinterpret_cast<unsigned char*>(message), static_cast<size_t>(fileSize), ad, sizeof(ad), reinterpret_cast<unsigned char*>(&ct[0]), ct.length());
		}
		double seconds = timer.elapsed();
		std::wcout << std::fixed << std::setprecision(5) << seconds << _T(" (") << std::setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s) ");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream ofile(filename + _T(".") + it->first + _T(".aead.encrypted"), ios::out | ios::binary);
		ofile.write(ct.data(), ct.length());
#endif

		pt.resize(static_cast<size_t>(ct.length()) - it->second->tag_bytes() - it->second->iv_bytes());
		timer.reset();
		bool res = true;
		for (long i = 0; i < iterations; i++)
		{
			it->second->set_key(key, it->second->key_bytes());
			res = it->second->decrypt(reinterpret_cast<const unsigned char*>(ct.data()), ct.length(), ad, sizeof(ad), reinterpret_cast<unsigned char*>(&pt[0]), pt.length());
		}
		seconds = timer.elapsed();
		std::wcout << std::fixed << std::setprecision(5) << seconds << _T(" (") << std::setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s)");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream odfile(filename + _T(".") + it->first + _T(".aead.decrypted"), ios::out | ios::binary);
		odfile.write(pt.data(), pt.length());
#endif

		if (memcmp(pt.data(), message, static_cast<size_t>(fileSize)))
			std::wcout << _T(" ERROR");
		if (static_cast<size_t>(fileSize) != pt.size())
			std::wcout << _T(" SZMISMATCH");
		if (!res)
			std::wcout << _T(" WRONGTAG");

		std::wcout << _T(" ");

		std::wcout << std::endl;
	}
}

void scperftest(std::map<std::wstring, std::unique_ptr<stream_cipher>>& ciphers, long iterations, std::wstring filename)
{
	perftimer timer;

	if (!file_exists(filename.c_str())) {
		std::wcerr << filename << _T(": No such file or directory") << std::endl;
		return;
	}
	if (is_directory(filename.c_str())) {
		std::wcerr << filename << _T(": Is a directory") << std::endl;
		return;
	}

	long long fileSize = file_size(filename.c_str());

	if (fileSize > 20000000000)
	{
		std::cerr << "File is too big.\n";
		return;
	}

	char* message = new char[static_cast<size_t>(fileSize)];

	std::ifstream file;
	file.open(filename, std::ios::in | std::ios::binary);
	if (!file)
		return;

	if (!file.read(message, fileSize))
		return;

	file.close();
	size_t bufsize = static_cast<size_t>(fileSize + 1024 * 2);
	unsigned char* ct = new unsigned char[bufsize];
	unsigned char* pt = new unsigned char[bufsize];
	unsigned char key[1024];
	unsigned char iv[1024];
	gen_random_bytes(key, sizeof(key));
	gen_random_bytes(iv, sizeof(iv));

	std::wcout << _T("Cipher\t\tEncrypt\t\tDecrypt") << std::endl;
	for (auto it = ciphers.begin(); it != ciphers.end(); ++it)
	{
		std::wcout << it->first << _T(" ");
		stream_cipher* sc = it->second->clone();
		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			sc->init(key, it->second->keysize() / 8, iv, it->second->ivsize() / 8);
			sc->encrypt((unsigned char*)message, static_cast<size_t>(fileSize), ct);
		}
		double seconds = timer.elapsed();
		std::wcout << std::fixed << std::setprecision(5) << seconds << _T(" (") << std::setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s) ");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream octrfile(filename + _T(".") + it->first + _T(".encrypted"), ios::out | ios::binary);
		octrfile.write((const char*)ct, fileSize);
#endif
		memset(pt, 0, bufsize);
		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			sc->init(key, it->second->keysize() / 8, iv, it->second->ivsize() / 8);
			sc->decrypt((unsigned char*)ct, static_cast<size_t>(fileSize), pt);
		}
		seconds = timer.elapsed();
		std::wcout << std::fixed << std::setprecision(5) << seconds << _T(" (") << std::setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s)");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream odctrfile(filename + _T(".") + it->first + _T(".decrypted"), ios::out | ios::binary);
		odctrfile.write((const char*)pt, fileSize);
#endif

		if (memcmp(pt, message, static_cast<size_t>(fileSize)))
			std::wcout << _T(" ERROR");

		std::wcout << std::endl;
		delete sc;
	}
	delete[] ct;
	delete[] pt;
}


std::pair<uint32_t, uint32_t> test_argon(const std::wstring& name, const std::wstring& filename)
{
	std::ifstream file(filename, std::ios::in | std::ios::binary);
	std::string line;
	std::basic_string<unsigned char> pwd, salt, secret, ad, tag, pwdhash;
	uint32_t pwdlen = 0, saltlen = 0, secretlen = 0, adlen = 0, taglen = 32;
	uint32_t memory = 32, iterations = 3, parallelism = 4;
	uint32_t count = 0, failed = 0, success = 0;
	std::regex eq(R"((\w+)\s*=\s*(\w*))");
	while (std::getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		std::smatch sm;
		if (std::regex_match(line, sm, eq))
		{
			std::string second = sm.str(2);
			if (sm.str(1) == "PWD")
			{
				hex2array(second, pwd);
				pwdlen = static_cast<uint32_t>(pwd.length());
			}
			if (sm.str(1) == "SALT")
			{
				hex2array(second, salt);
				saltlen = static_cast<uint32_t>(salt.length());
			}
			if (sm.str(1) == "SECRET")
			{
				hex2array(second, secret);
				secretlen = static_cast<uint32_t>(secret.length());
			}
			if (sm.str(1) == "AD")
			{
				hex2array(second, ad);
				adlen = static_cast<uint32_t>(ad.length());
			}
			if (sm.str(1) == "MEMORY")
				memory = std::stoul(second);
			if (sm.str(1) == "ITERATIONS")
				iterations = std::stoul(second);
			if (sm.str(1) == "PARALLELISM")
				parallelism = std::stoul(second);
			if (sm.str(1) == "TAG")
			{
				bool error = false;
				hex2array(second, tag);
				taglen = static_cast<uint32_t>(tag.length());
				pwdhash.resize(tag.length());
				argon2::type argon_type;
				if (name == _T("argon2d"))
					argon_type = argon2::type::argon2d;
				else if (name == _T("argon2i"))
					argon_type = argon2::type::argon2i;
				else if (name == _T("argon2id"))
					argon_type = argon2::type::argon2id;
				else
					throw std::runtime_error("unsupported argon2 type");

				argon2(argon_type, parallelism, memory, iterations).derive_key(!pwd.empty() ? reinterpret_cast<const char*>(pwd.data()) : nullptr, pwdlen, !salt.empty() ? salt.data() : nullptr, saltlen, &pwdhash[0], taglen, !ad.empty() ? ad.data() : nullptr, adlen, !secret.empty() ? secret.data() : nullptr, secretlen);
					
				if (memcmp(pwdhash.data(), tag.data(), second.length() / 2))
				{
					std::wcerr << _T("Error for test ") << std::dec << count << std::endl;
					std::wcerr << _T("password was: ");
					for (size_t i = 0; i < pwdlen; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pwd[i];
					std::wcerr << _T("\nsalt was: ");
					for (size_t i = 0; i < saltlen; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)salt[i];
					std::wcerr << _T("\nsecret was: ");
					for (size_t i = 0; i < secretlen; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)secret[i];
					std::wcerr << _T("\nad was: ");
					for (size_t i = 0; i < adlen; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ad[i];
					std::wcerr << std::endl << "memory: " << std::dec << memory << ", iterations: " << iterations << ", parallelism: " << parallelism;
					std::wcerr << "\nexpected is: ";
					for (size_t i = 0; i < taglen; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)tag[i];
					std::wcerr << "\nactual is: ";
					for (size_t i = 0; i < taglen; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pwdhash[i];
					std::wcerr << std::endl;
					error = true;
				}
				count++;
				if (error)
					failed++;
				else
					success++;
			}

		}
	}
	std::wcout << name << _T(": ");
	if (success)
		std::wcout << (success) << _T("/") << count << _T(" OK");
	if (failed && success)
		std::wcout << _T(", ");
	if (failed)
		std::wcout << failed << _T("/") << count << _T(" FAILED");
	if (!success && !failed)
		std::wcout << _T("No tests found");
	std::wcout << std::endl;
	return std::make_pair(success, failed);
}


std::pair<uint32_t, uint32_t>  test_pbkdf2(const crypto_hash& hash, const std::wstring& name, const std::wstring& filename)
{
	std::ifstream file(filename, std::ios::in | std::ios::binary);
	std::string line;
	std::basic_string<unsigned char> pwd, salt, tag, pwdhash;
	uint64_t iterations = 3;
	uint32_t count = 0, failed = 0, success = 0;
	std::regex eq(R"((\w+)\s*=\s*(\w*))");
	while (std::getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		if (line.empty())
			continue;
		std::smatch sm;
		if (std::regex_match(line, sm, eq))
		{
			std::string second = sm.str(2);
			if (sm.str(1) == "PWD")
				hex2array(second, pwd);
			if (sm.str(1) == "SALT")
				hex2array(second, salt);
			if (sm.str(1) == "ITERATIONS")
				iterations = std::stoull(second);
			if (sm.str(1) == "TAG")
			{
				bool error = false;
				hex2array(second, tag);
				pwdhash.resize(tag.length());

				pbkdf2(hash, static_cast<size_t>(iterations)).derive_key(!pwd.empty() ? pwd.data() : nullptr, pwd.length(), !salt.empty() ? salt.data() : nullptr, salt.length(), &pwdhash[0], pwdhash.length());

				if (memcmp(pwdhash.data(), tag.data(), second.length() / 2))
				{
					std::wcerr << _T("Error for test ") << std::dec << count << std::endl;
					std::wcerr << _T("password was: ");
					for (size_t i = 0; i < pwd.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pwd[i];
					std::wcerr << _T("\nsalt was: ");
					for (size_t i = 0; i < salt.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)salt[i];
					std::wcerr << std::endl << "iterations: " << std::dec << iterations;
					std::wcerr << "\nexpected is: ";
					for (size_t i = 0; i < tag.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)tag[i];
					std::wcerr << "\nactual is: ";
					for (size_t i = 0; i < pwdhash.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pwdhash[i];
					std::wcerr << std::endl;
					error = true;
				}
				count++;
				if (error)
					failed++;
				else
					success++;
			}

		}
	}
	std::wcout << name << _T(": ");
	if (success)
		std::wcout << (success) << _T("/") << count << _T(" OK");
	if (failed && success)
		std::wcout << _T(", ");
	if (failed)
		std::wcout << failed << _T("/") << count << _T(" FAILED");
	if (!success && !failed)
		std::wcout << _T("No tests found");
	std::wcout << std::endl;
	return std::make_pair(success, failed);
}

std::pair<uint32_t, uint32_t>  test_hkdf(const crypto_hash& hash, const std::wstring& name, const std::wstring& filename)
{
	std::ifstream file(filename, std::ios::in | std::ios::binary);
	std::string line;
	std::basic_string<unsigned char> ikm, salt, info, okm, keyhash;
	bool result_valid = true;
	uint32_t count = 0, failed = 0, success = 0;
	while (std::getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		if (line.empty())
			continue;
		size_t eqpos = line.find("=");
		if (eqpos == line.npos)
			continue;
		std::string key = line.substr(0, eqpos);
		key.erase(key.find_last_not_of(" \t") + 1);
		std::string value;
	       	if (eqpos != line.size() - 1)
			value = line.substr(eqpos + 1);
		value.erase(0, value.find_first_not_of(" \t"));
		if (!key.empty())
		{
			std::string second = value;
			if (key == "IKM")
				hex2array(second, ikm);
			if (key == "PRK")
				hex2array(second, ikm);
			if (key == "SALT")
				hex2array(second, salt);
			if (key == "INFO")
				hex2array(second, info);
			if (key == "RESULT_TYPE")
				result_valid = second != "invalid";
			if (key == "OKM")
			{
				bool error = false;
				bool exception_thrown = false;
				hex2array(second, okm);
				keyhash.resize(okm.length());
				std::fill(keyhash.begin(), keyhash.end(), '\x00');

				try
				{
					if (name.find(_T("expand")) != name.npos)
						hkdf(hash).expand(!ikm.empty() ? ikm.data() : nullptr, ikm.size(), !info.empty() ? info.data() : nullptr, info.length(), &keyhash[0], keyhash.size());
					else
						hkdf(hash).extract_and_expand(!salt.empty() ? salt.data() : nullptr, salt.length(), !info.empty() ? info.data() : nullptr, info.length(), !ikm.empty() ? ikm.data() : nullptr, ikm.size(), &keyhash[0], keyhash.size());
					exception_thrown = !!memcmp(keyhash.data(), okm.data(), okm.size());
				}
				catch (std::exception&)
				{
					exception_thrown = true;
				}

				if (result_valid == exception_thrown)
				{
					std::wcerr << _T("Error for test ") << std::dec << count << std::endl;
					if (name.find(_T("expand")) != name.npos)
						std::wcerr << _T("prk was: ");
					else
						std::wcerr << _T("ikm was: ");
					for (size_t i = 0; i < ikm.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ikm[i];
					std::wcerr << _T("\nsalt was: ");
					for (size_t i = 0; i < salt.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)salt[i];
					std::wcerr << _T("\ninfo was: ");
					for (size_t i = 0; i < info.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)info[i];
					std::wcerr << std::endl << "result_type: " << std::dec << std::boolalpha << result_valid;
					if (result_valid)
					{
						std::wcerr << "\nexpected is: ";
						for (size_t i = 0; i < okm.length(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)okm[i];
						std::wcerr << "\nactual is: ";
						for (size_t i = 0; i < keyhash.length(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)keyhash[i];
					}
					else
						std::wcerr << "\nexpected exception";
					std::wcerr << std::endl;
					error = true;
				}
				count++;
				if (error)
					failed++;
				else
					success++;
			}

		}
	}
	std::wcout << name << _T(": ");
	if (success)
		std::wcout << (success) << _T("/") << count << _T(" OK");
	if (failed && success)
		std::wcout << _T(", ");
	if (failed)
		std::wcout << failed << _T("/") << count << _T(" FAILED");
	if (!success && !failed)
		std::wcout << _T("No tests found");
	std::wcout << std::endl;
	return std::make_pair(success, failed);
}

std::pair<uint32_t, uint32_t>  test_scrypt(const std::wstring& name, const std::wstring& filename)
{
	std::ifstream file(filename, std::ios::in | std::ios::binary);
	std::string line;
	std::basic_string<unsigned char> pwd, salt, tag, pwdhash;
	size_t N = 16384, r = 8, p = 8;
	uint32_t count = 0, failed = 0, success = 0;
	std::regex eq(R"((\w+)\s*=\s*(\w*))");
	while (std::getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		std::smatch sm;
		if (std::regex_match(line, sm, eq))
		{
			std::string second = sm.str(2);
			if (sm.str(1) == "PWD")
			{
				hex2array(second, pwd);
		}
			if (sm.str(1) == "SALT")
			{
				hex2array(second, salt);
			}
			if (sm.str(1) == "COST")
				N = std::stoul(second);
			if (sm.str(1) == "BS")
				r = std::stoul(second);
			if (sm.str(1) == "PARALLELISM")
				p = std::stoul(second);
			if (sm.str(1) == "TAG")
			{
				bool error = false;
				hex2array(second, tag);
				pwdhash.resize(tag.length());

				scrypt(sha256(), N, r, p).derive_key(!pwd.empty() ? pwd.data() : nullptr, pwd.length(), !salt.empty() ? salt.data() : nullptr, salt.length(), &pwdhash[0], pwdhash.length());

				if (memcmp(pwdhash.data(), tag.data(), second.length() / 2))
				{
					std::wcerr << _T("Error for test ") << std::dec << count << std::endl;
					std::wcerr << _T("password was: ");
					for (size_t i = 0; i < pwd.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pwd[i];
					std::wcerr << _T("\nsalt was: ");
					for (size_t i = 0; i < salt.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)salt[i];
				std::wcerr << std::endl << "N: " << std::dec << N << ", r: " << r << ", p: " << p;
					std::wcerr << "\nexpected is: ";
					for (size_t i = 0; i < tag.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)tag[i];
					std::wcerr << "\nactual is: ";
					for (size_t i = 0; i < pwdhash.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pwdhash[i];
					std::wcerr << std::endl;
					error = true;
				}
				count++;
				if (error)
					failed++;
				else
					success++;
			}

		}
	}
	std::wcout << name << _T(": ");
	if (success)
		std::wcout << (success) << _T("/") << count << _T(" OK");
	if (failed && success)
		std::wcout << _T(", ");
	if (failed)
		std::wcout << failed << _T("/") << count << _T(" FAILED");
	if (!success && !failed)
		std::wcout << _T("No tests found");
	std::wcout << std::endl;
	return std::make_pair(success, failed);
}

std::pair<uint32_t, uint32_t>  test_hmac(const crypto_mac& mac, const std::wstring& name, const std::wstring& filename)
{
	std::ifstream file(filename, std::ios::in | std::ios::binary);
	std::string line;
	std::basic_string<unsigned char> key, msg, tag, res;
	bool result_valid = true;
	uint32_t count = 0, failed = 0, success = 0;
	std::regex eq(R"((\w+)\s*=\s*(\w*))");
	while (std::getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		if (line.empty())
			continue;
		std::smatch sm;
		if (std::regex_match(line, sm, eq))
		{
			std::string second = sm.str(2);
			if (sm.str(1) == "KEY")
				hex2array(second, key);
			if (sm.str(1) == "MSG")
				hex2array(second, msg);
			if (sm.str(1) == "RESULT_TYPE")
				result_valid = second != "invalid";
			if (sm.str(1) == "TAG")
			{
				bool error = false;
				bool exception_thrown = false;
				hex2array(second, tag);
				res.resize(tag.length());
				std::fill(res.begin(), res.end(), '\x00');
				auto h = std::unique_ptr<crypto_mac>(mac.clone());

				try
				{
					h->mac_string(!key.empty() ? key.data() : nullptr, key.length(), !msg.empty() ? msg.data() : nullptr, msg.length(), &res[0], res.length());
					exception_thrown = !!memcmp(res.data(), tag.data(), res.size());
				}
				catch (std::exception&)
				{
					exception_thrown = true;
				}

				if (result_valid == exception_thrown)
				{
					std::wcerr << _T("Error for test ") << std::dec << count << std::endl;
					std::wcerr << _T("key was: ");
					for (size_t i = 0; i < key.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)key[i];
					std::wcerr << _T("\nmsg was: ");
					for (size_t i = 0; i < msg.length(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)msg[i];
					std::wcerr << std::endl << "result_type: " << std::dec << std::boolalpha << result_valid;
					if (result_valid)
					{
						std::wcerr << "\nexpected is: ";
						for (size_t i = 0; i < tag.length(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)tag[i];
						std::wcerr << "\nactual is: ";
						for (size_t i = 0; i < res.length(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)res[i];
					}
					else
						std::wcerr << "\nexpected exception";
					std::wcerr << std::endl;
					error = true;
				}
				count++;
				if (error)
					failed++;
				else
					success++;
			}

		}
	}
	std::wcout << name << _T(": ");
	if (success)
		std::wcout << (success) << _T("/") << count << _T(" OK");
	if (failed && success)
		std::wcout << _T(", ");
	if (failed)
		std::wcout << failed << _T("/") << count << _T(" FAILED");
	if (!success && !failed)
		std::wcout << _T("No tests found");
	std::wcout << std::endl;
	return std::make_pair(success, failed);
}



std::unique_ptr<crypto_hash> get_hash_by_name(const std::wstring& algorithm)
{
	if (algorithm == _T("sha1"))
		return std::unique_ptr<crypto_hash>(new sha1);
	else if (algorithm == _T("sha224"))
		return std::unique_ptr<crypto_hash>(new sha224);
	else if (algorithm == _T("sha256"))
		return std::unique_ptr<crypto_hash>(new sha256);
	else if (algorithm == _T("sha384"))
		return std::unique_ptr<crypto_hash>(new sha384);
	else if (algorithm == _T("sha512"))
		return std::unique_ptr<crypto_hash>(new sha512);

	return nullptr;
}

std::pair<uint32_t, uint32_t> test_vector(const std::wstring& name, const block_cipher& cipher, const std::wstring& filename)
{
	std::ifstream file(filename, std::ios::in | std::ios::binary);
	std::string line;
	std::basic_string<unsigned char> key, pt, ct, res, tweak;
	uint32_t count = 0, failed = 0, success = 0, repeat = 1;
	bool tweakable = false;
	std::regex eq(R"((\w+)\s*=\s*(\w+))");
	while (std::getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		std::smatch sm;
		if (std::regex_match(line, sm, eq))
		{
			std::string second = sm.str(2);
			if (sm.str(1) == "PT")
				hex2array(second, pt);
			if (sm.str(1) == "KEY")
				hex2array(second, key);
			if (sm.str(1) == "REPEAT")
				repeat = stol(second);
			if (sm.str(1) == "TWEAK")
			{
				hex2array(second, tweak);
				tweakable = true;
			}
			if (sm.str(1) == "CT")
			{
				bool error = false;
				hex2array(second, ct);
				res.resize(ct.size());
				auto bc = std::unique_ptr<block_cipher>(cipher.clone());
				bc->init(key.data(), bc->encryption);

				if (tweakable)
				{
					tweakable_block_cipher* tc = dynamic_cast<tweakable_block_cipher*>(bc.get());
					if (tc)
						tc->set_tweak(tweak.data());
				}

				for (size_t i = 0; i < pt.size(); i += bc->blocksize() / 8)
				{
					bc->encrypt_block(pt.data() + i, &res[i]);
					for (unsigned int k = 1; k < repeat; k++)
						bc->encrypt_block(res.data() + i, &res[i]);
				}
				if (memcmp(ct.data(), res.data(), second.length() / 2))
				{
					std::cerr << "Error for test " << count << " (encryption)" << std::endl;
#define CPPCRYPTO_DEBUG
#ifdef CPPCRYPTO_DEBUG
					std::wcerr << _T("key was: ");
					for (size_t i = 0; i < bc->keysize() / 8; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)key[i];
					std::wcerr << _T("\nPT was: ");
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pt[i];
					std::wcerr << _T("\nCT is: ");
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)res[i];
					std::wcerr << _T("\nexpected is: ");
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ct[i];
					std::wcerr << _T("\n");
#endif
					error = true;
				}
				std::fill(res.begin(), res.end(), 0);
				bc->init(key.data(), bc->decryption);

				if (tweakable)
				{
					tweakable_block_cipher* tc = dynamic_cast<tweakable_block_cipher*>(bc.get());
					if (tc)
						tc->set_tweak(tweak.data());
					tweakable = false;
				}
				for (size_t i = 0; i < ct.size(); i += bc->blocksize() / 8)
				{
					for (unsigned int k = 1; k < repeat; k++)
						bc->decrypt_block(ct.data() + i, &ct[i]);
					bc->decrypt_block(ct.data() + i, &res[i]);
				}
				if (memcmp(pt.data(), res.data(), second.length() / 2))
				{
					std::cerr << "Error for test " << count << " (decryption)" << std::endl;
#ifdef CPPCRYPTO_DEBUG
					std::wcerr << _T("key was: ");
					for (size_t i = 0; i < bc->keysize() / 8; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)key[i];
					std::wcerr << _T("\nCT was: ");
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ct[i];
					std::wcerr << _T("\nPT is: ");
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)res[i];
					std::wcerr << _T("\nexpected is: ");
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pt[i];
					std::wcerr << _T("\n");
#endif
					error = true;
				}
				count++;
				if (error)
					failed++;
				else
					success++;
			}

		}
	}
	std::wcout << name << _T(": ");
	if (success)
		std::wcout << (success) << _T("/") << count << _T(" OK");
	if (failed && success)
		std::wcout << _T(", ");
	if (failed)
		std::wcout << failed << _T("/") << count << _T(" FAILED");
	if (!success && !failed)
		std::wcout << _T("No tests found");
	std::wcout << std::endl;
	return std::make_pair(success, failed);
}

std::pair<uint32_t, uint32_t> test_vector(const std::wstring& name, const crypto_hash& c, const std::wstring& filename)
{
	auto ch = std::unique_ptr<crypto_hash>(c.clone());
	std::ifstream file(filename, std::ios::in | std::ios::binary);
	std::string line;
	std::basic_string<unsigned char> md, res;
	std::basic_string<unsigned char> msg;
	uint32_t count = 0, failed = 0, success = 0;
	std::regex eq(R"((\w+)\s*=\s*(\w*))");
	while (std::getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		std::smatch sm;
		if (std::regex_match(line, sm, eq))
		{
			std::string second = sm.str(2);
			if (sm.str(1) == "Msg")
			{
				hex2array(second, msg);
			}
			if (sm.str(1) == "MD")
			{
				hex2array(second, md);
				res.resize(md.size());
				ch->hash_string(!msg.empty() ? &msg[0] : nullptr, msg.size(), &res[0]);
				if (memcmp(md.data(), res.data(), second.length() / 2))
				{
					std::cerr << "Error for test " << count << std::endl;
#define CPPCRYPTO_DEBUG
#ifdef CPPCRYPTO_DEBUG
					std::wcerr << _T("Message was: ");
					for (size_t i = 0; i < msg.size(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)msg[i];
					std::wcerr << _T("\nHash was: ");
					for (size_t i = 0; i < ch->hashsize() / 8; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)res[i];
					std::wcerr << _T("\nexpected is: ");
					for (size_t i = 0; i < second.length() / 2; i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)md[i];
					std::wcerr << _T("\n");
#endif
					failed++;
				}
				else success++;
				count++;
			}

		}
	}
	std::wcout << name << _T(": ");
	if (success)
		std::wcout << (success) << _T("/") << count << _T(" OK");
	if (failed && success)
		std::wcout << _T(", ");
	if (failed)
		std::wcout << failed << _T("/") << count << _T(" FAILED");
	if (!success && !failed)
		std::wcout << _T("No tests found");
	std::wcout << std::endl;
	return std::make_pair(success, failed);
}

std::pair<uint32_t, uint32_t> test_vector(const std::wstring& name, const stream_cipher& cipher, const std::wstring& filename)
{

	auto ch = std::unique_ptr<stream_cipher>(cipher.clone());
	std::ifstream file(filename, std::ios::in | std::ios::binary);
	std::string line;
	std::basic_string<unsigned char> key, iv, xord, pt, ct;
	std::vector<unsigned char> res;
	uint64_t seek = 0;
	uint32_t count = 0, failed = 0, success = 0;
	std::regex eq(R"((\w+)\s*=\s*(\w*))");
	while (std::getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		std::smatch sm;
		if (std::regex_match(line, sm, eq))
		{
			std::string second = sm.str(2);
			if (sm.str(1) == "PT")
			{
				hex2array(second, pt);
				res.resize(pt.length());
			}
			if (sm.str(1) == "PTZERO")
			{
				long size = stol(second);
				pt.resize(size);
				res.resize(size);
				memset(&pt[0], 0, size);
			}
			if (sm.str(1) == "KEY")
			{
				hex2array(second, key);
			}
			if (sm.str(1) == "IV")
			{
				hex2array(second, iv);
			}
			if (sm.str(1) == "SEEK")
			{
				seek = std::stoull(second.c_str());
			}
			if (sm.str(1) == "CT" || sm.str(1) == "XOR")
			{
				bool isxor = sm.str(1) == "XOR";
				bool error = false;
				hex2array(second, ct);
				ch->init(key.data(), key.size(), iv.data(), iv.size());
				if (seek)
				{
					if (auto seekable = dynamic_cast<cppcrypto::seekable*>(ch.get()))
						seekable->seek(seek);
					else
					{

						std::vector<unsigned char> bufin(1024 * 1024 * 16), bufout(1024 * 1024 * 16);
						memset(&bufin[0], 0, bufin.size());
						memset(&bufout[0], 0, bufout.size());
						uint64_t rem = seek;
						int dotcount = 0;
						while (rem > 0)
						{
							uint64_t part = std::min(rem, static_cast<uint64_t>(bufin.size()));
							ch->encrypt(bufin.data(), static_cast<size_t>(part), &bufout[0]);
							rem -= part;
							if (++dotcount == 1024)
							{
								std::cout << "." << std::flush;
								dotcount = 0;
							}
						}
					}
				}
				if (isxor)
				{
					xord.resize(ct.size());
					memset(&xord[0], 0, xord.size());
					for (size_t b = 0; b < pt.length(); b += ct.size())
					{
						ch->encrypt(&pt[b], ct.size(), &res[b]);
						for (size_t i = 0; i < ct.size(); i++)
							xord[i] ^= res[b + i];
					}
					if (memcmp(&ct[0], &xord[0], ct.size()))
					{
						std::cerr << "Error for test " << std::dec << count << " (encryption)" << std::endl;
						std::cerr << "key was : ";
						for (size_t i = 0; i < key.length(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)key[i];
						std::wcerr << _T("\nIV was: ");
						for (size_t i = 0; i < iv.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)iv[i];
						std::wcerr << _T("\nPT was: ");
						for (size_t i = 0; i < pt.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pt[i];
						std::wcerr << _T("\nXOR is: ");
						for (size_t i = 0; i < 64; i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)xord[i];
						std::wcerr << _T("\nexpected is: ");
						for (size_t i = 0; i < ct.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ct[i];
						std::wcerr << _T("\n");
						error = true;
					}
				}
				else
				{
					ch->encrypt(&pt[0], pt.size(), !res.empty() ? &res[0] : nullptr);
					if ((!res.empty() || !pt.empty() || !ct.empty()) && memcmp(&ct[0], &res[0], pt.size()))
					{
						std::cerr << "Error for test " << std::dec << count << " (encryption)" << std::endl;
#define CPPCRYPTO_DEBUG
#ifdef CPPCRYPTO_DEBUG
						std::wcerr << _T("key was: ");
						for (size_t i = 0; i < key.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)key[i];
						std::wcerr << _T("\nIV was: ");
						for (size_t i = 0; i < iv.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)iv[i];
						std::wcerr << _T("\nPT was: ");
						for (size_t i = 0; i < pt.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pt[i];
						std::wcerr << _T("\nCT is: ");
						for (size_t i = 0; i < res.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)res[i];
						std::wcerr << _T("\nexpected is: ");
						for (size_t i = 0; i < ct.length(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ct[i];
						std::wcerr << _T("\n");
#endif
						error = true;
					}
				}
				ch->init(key.data(), key.size(), iv.data(), iv.size());
				if (seek)
				{
					if (auto seekable = dynamic_cast<cppcrypto::seekable*>(ch.get()))
						seekable->seek(seek);
					else
					{
						std::vector<unsigned char> bufin(1024 * 1024 * 16), bufout(1024 * 1024 * 16);
						memset(&bufin[0], 0, bufin.size());
						memset(&bufout[0], 0, bufout.size());
						uint64_t rem = seek;
						int dotcount = 0;
						while (rem > 0)
						{
							uint64_t part = std::min(rem, static_cast<uint64_t>(bufin.size()));
							ch->decrypt(bufin.data(), static_cast<size_t>(part), &bufout[0]);
							rem -= part;
							if (++dotcount == 1024)
							{
								std::cout << "." << std::flush;
								dotcount = 0;
							}
						}
					}
				}
				if (isxor)
				{
					std::vector<unsigned char> res2(res);
					ch->decrypt(&res2[0], pt.size(), &res[0]);
				}
				else
					ch->decrypt(&ct[0], second.size() / 2, !res.empty() ? &res[0] : nullptr);
				if ((!res.empty() || !pt.empty() || !ct.empty()) && memcmp(&pt[0], &res[0], pt.size()))
				{
					std::cerr << "Error for test " << count << " (decryption)" << std::endl;
#ifdef CPPCRYPTO_DEBUG
					std::wcerr << _T("key was: ");
					for (size_t i = 0; i < key.size(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)key[i];
					std::wcerr << _T("\nIV was: ");
					for (size_t i = 0; i < iv.size(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)iv[i];
					std::wcerr <<_T("\nCT was: ");
					for (size_t i = 0; i < ct.size(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ct[i];
					std::wcerr << _T("\nPT is: ");
					for (size_t i = 0; i < res.size(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)res[i];
					std::wcerr << _T("\nexpected is: ");
					for (size_t i = 0; i < pt.size(); i++)
						std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pt[i];
					std::wcerr << _T("\n");
#endif
					error = true;
				}

				count++;
				if (error)
					failed++;
				else
					success++;
			}

		}
	}
	std::wcout << name << _T(": ");
	if (success)
		std::wcout << (success) << _T("/") << std::dec << count << _T(" OK");
	if (failed && success)
		std::wcout << _T(", ");
	if (failed)
		std::wcout << failed << _T("/") << std::dec << count << _T(" FAILED");
	if (!success && !failed)
		std::wcout << _T("No tests found");
	std::wcout << std::endl;

	return std::make_pair(success, failed);
}

std::pair<uint32_t, uint32_t> test_cbc(const std::wstring& name, const block_cipher& cipher, const std::wstring& filename)
{

	std::ifstream file(filename, std::ios::in | std::ios::binary);
	std::string line;
	std::basic_string<unsigned char> key, iv, xord, pt, ct;
	std::vector<unsigned char> res;
	uint32_t count = 0, failed = 0, success = 0;
	bool result_valid = true;
	std::regex eq(R"((\w+)\s*=\s*(\w*))");
	while (std::getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		std::smatch sm;
		if (std::regex_match(line, sm, eq))
		{
			std::string second = sm.str(2);
			if (sm.str(1) == "RESULT_TYPE")
				result_valid = second != "invalid";
			if (sm.str(1) == "PT")
			{
				hex2array(second, pt);
			}
			if (sm.str(1) == "PTZERO")
			{
				long size = stol(second);
				pt.resize(size);
				memset(&pt[0], 0, size);
			}
			if (sm.str(1) == "KEY")
			{
				hex2array(second, key);
			}
			if (sm.str(1) == "IV")
			{
				hex2array(second, iv);
			}
			if (sm.str(1) == "CT")
			{
				bool error = false;
				hex2array(second, ct);
				bool exception_thrown = false;
				res.clear();
				{
					cbc ch(cipher);
					ch.init(key.data(), key.size(), iv.data(), iv.size(), cipher.encryption);
					ch.encrypt_update(!pt.empty() ? &pt[0] : nullptr, pt.size(), res);
					ch.encrypt_final(res);
					exception_thrown = res.size() != ct.size() || ((!res.empty() || !ct.empty()) && memcmp(&ct[0], &res[0], ct.size()));

					if (exception_thrown == result_valid)
					{
						std::cerr << "Error for test " << std::dec << count << " (encryption)" << std::endl;
#define CPPCRYPTO_DEBUG
#ifdef CPPCRYPTO_DEBUG
						std::wcerr << _T("key was: ");
						for (size_t i = 0; i < key.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)key[i];
						std::wcerr << _T("\nIV was: ");
						for (size_t i = 0; i < iv.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)iv[i];
						std::wcerr << _T("\nPT was: ");
						for (size_t i = 0; i < pt.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pt[i];
						std::wcerr << std::endl << "result_type: " << std::dec << std::boolalpha << result_valid;
						std::wcerr << _T("\nactual CT is: ");
						for (size_t i = 0; i < res.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)res[i];
						std::wcerr << _T("\nexpected CT is: ");
						for (size_t i = 0; i < ct.length(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ct[i];
						std::wcerr << _T("\n");
#endif
						error = true;
					}
				}
				res.clear();
				{
					cbc ch(cipher);
					ch.init(key.data(), key.size(), iv.data(), iv.size(), cipher.decryption);
					try
					{
						ch.decrypt_update(&ct[0], second.size() / 2, res);
						ch.decrypt_final(res);
						exception_thrown = res.size() != pt.size() || ((!res.empty() || !pt.empty()) && memcmp(&pt[0], &res[0], pt.size()));
					}
					catch (std::exception&)
					{
						exception_thrown = true;
					}

					if (exception_thrown == result_valid)
					{
						std::cerr << "Error for test " << count << " (decryption)" << std::endl;
#ifdef CPPCRYPTO_DEBUG
						std::wcerr << _T("key was: ");
						for (size_t i = 0; i < key.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)key[i];
						std::wcerr << _T("\nIV was: ");
						for (size_t i = 0; i < iv.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)iv[i];
						std::wcerr << _T("\nCT was: ");
						for (size_t i = 0; i < ct.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ct[i];
						std::wcerr << std::endl << "result_type: " << std::dec << std::boolalpha << result_valid;
						std::wcerr << _T("\nactual PT is: ");
						for (size_t i = 0; i < res.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)res[i];
						std::wcerr << _T("\nexpected PT is: ");
						for (size_t i = 0; i < pt.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pt[i];
						std::wcerr << _T("\n");
#endif
						error = true;
					}
				}

				count++;
				if (error)
					failed++;
				else
					success++;
			}

		}
	}
	std::wcout << name << _T(": ");
	if (success)
		std::wcout << (success) << _T("/") << std::dec << count << _T(" OK");
	if (failed && success)
		std::wcout << _T(", ");
	if (failed)
		std::wcout << failed << _T("/") << std::dec << count << _T(" FAILED");
	if (!success && !failed)
		std::wcout << _T("No tests found");
	std::wcout << std::endl;

	return std::make_pair(success, failed);
}

std::pair<uint32_t, uint32_t> test_aead(const std::wstring& name, const aead& cipher, const std::wstring& filename)
{

	std::ifstream file(filename, std::ios::in | std::ios::binary);
	std::string line;
	std::basic_string<unsigned char> key, iv, pt, ct, ad;
	std::vector<unsigned char> res;
	uint32_t count = 0, failed = 0, success = 0;
	bool result_valid = true;
	std::regex eq(R"((\w+)\s*=\s*(\w*))");
	while (std::getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		std::smatch sm;
		if (std::regex_match(line, sm, eq))
		{
			std::string second = sm.str(2);
			if (sm.str(1) == "RESULT_TYPE")
				result_valid = second != "invalid";
			if (sm.str(1) == "PT")
			{
				hex2array(second, pt);
			}
			if (sm.str(1) == "PTZERO")
			{
				long size = stol(second);
				pt.resize(size);
				memset(&pt[0], 0, size);
			}
			if (sm.str(1) == "KEY")
			{
				hex2array(second, key);
			}
			if (sm.str(1) == "IV")
			{
				hex2array(second, iv);
			}
			if (sm.str(1) == "AD")
			{
				hex2array(second, ad);
			}
			if (sm.str(1) == "CT")
			{
				bool error = false;
				hex2array(second, ct);
				res.resize(ct.size());
				size_t tagsize = ct.size() - pt.size();
				std::fill(res.begin(), res.end(), 0);
				bool exception_thrown = false;
				{
					auto ch = std::unique_ptr<aead>(cipher.clone());
					try
					{
						if (ch->tag_bytes() != tagsize)
							ch->set_tagsize_in_bits(tagsize * 8);
						ch->set_key(key.data(), key.size());
						ch->encrypt_with_explicit_iv(!pt.empty() ? &pt[0] : nullptr, pt.size(), !ad.empty() ? &ad[0] : nullptr, ad.size(),
							!iv.empty() ? &iv[0] : nullptr, iv.size(),
							&res[0], res.size());
						exception_thrown = (!res.empty() || !ct.empty()) && memcmp(&ct[0], &res[0], ct.size());
					}
					catch (std::exception&)
					{
						exception_thrown = true;
					}

					if (exception_thrown == result_valid)
					{
						std::cerr << "Error for test " << std::dec << count << " (encryption)" << std::endl;
#define CPPCRYPTO_DEBUG
#ifdef CPPCRYPTO_DEBUG
						std::wcerr << _T("key was: ");
						for (size_t i = 0; i < key.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)key[i];
						std::wcerr << _T("\nIV was: ");
						for (size_t i = 0; i < iv.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)iv[i];
						std::wcerr << _T("\nPT was: ");
						for (size_t i = 0; i < pt.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pt[i];
						std::wcerr << _T("\nAD was: ");
						for (size_t i = 0; i < ad.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ad[i];
						std::wcerr << std::endl << "result_type: " << std::dec << std::boolalpha << result_valid;
						std::wcerr << _T("\nactual CT is: ");
						for (size_t i = 0; i < res.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)res[i];
						std::wcerr << _T("\nexpected CT is: ");
						for (size_t i = 0; i < ct.length(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ct[i];
						std::wcerr << _T("\n");
#endif
						error = true;
					}
				}
				res.clear();
				{
					auto ch = std::unique_ptr<aead>(cipher.clone());
					res.resize(pt.size());
					std::fill(res.begin(), res.end(), 0);
					try
					{
						if (ch->tag_bytes() != tagsize)
							ch->set_tagsize_in_bits(tagsize * 8);
						ch->set_key(key.data(), key.size());
						bool success = ch->decrypt_with_explicit_iv(!ct.empty() ? &ct[0] : nullptr, ct.size(), !ad.empty() ? &ad[0] : nullptr, ad.size(),
							!iv.empty() ? &iv[0] : nullptr, iv.size(),
							!res.empty() ? &res[0] : nullptr, res.size());
						exception_thrown = !success || ((!res.empty() || !pt.empty()) && memcmp(&pt[0], &res[0], pt.size()));
					}
					catch (std::exception&)
					{
						exception_thrown = true;
					}

					if (exception_thrown == result_valid)
					{
						std::cerr << "Error for test " << count << " (decryption)" << std::endl;
#ifdef CPPCRYPTO_DEBUG
						std::wcerr << _T("key was: ");
						for (size_t i = 0; i < key.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)key[i];
						std::wcerr << _T("\nIV was: ");
						for (size_t i = 0; i < iv.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)iv[i];
						std::wcerr << _T("\nAD was: ");
						for (size_t i = 0; i < ad.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ad[i];
						std::wcerr << _T("\nCT was: ");
						for (size_t i = 0; i < ct.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)ct[i];
						std::wcerr << std::endl << "result_type: " << std::dec << std::boolalpha << result_valid;
						std::wcerr << _T("\nactual PT is: ");
						for (size_t i = 0; i < res.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)res[i];
						std::wcerr << _T("\nexpected PT is: ");
						for (size_t i = 0; i < pt.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)pt[i];
						std::wcerr << _T("\n");
#endif
						error = true;
					}
				}

				count++;
				if (error)
					failed++;
				else
					success++;
			}

		}
	}
	std::wcout << name << _T(": ");
	if (success)
		std::wcout << (success) << _T("/") << std::dec << count << _T(" OK");
	if (failed && success)
		std::wcout << _T(", ");
	if (failed)
		std::wcout << failed << _T("/") << std::dec << count << _T(" FAILED");
	if (!success && !failed)
		std::wcout << _T("No tests found");
	std::wcout << std::endl;

	return std::make_pair(success, failed);
}

std::pair<uint32_t, uint32_t> validate_ocb(const std::wstring& name, const std::wstring& filename)
{
	std::ifstream file(filename, std::ios::in | std::ios::binary);
	std::string line;
	std::basic_string<unsigned char> key, tag;
	uint32_t count = 0, failed = 0, success = 0;
	std::regex eq(R"(([^=]+)\s*=\s*(\w*))");
	while (std::getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		std::smatch sm;
		if (std::regex_match(line, sm, eq))
		{
			std::string second = sm.str(2);
			if (sm.str(1) == "KEY")
			{
				hex2array(second, key);
			}
			if (sm.str(1).find("VALIDATE") == 0)
			{
				bool error = false;
				hex2array(second, tag);
				size_t tagsize = tag.size();
				std::string first = sm.str(1);
				std::regex val(R"(VALIDATE.(\d+)(,(\d+),(\d+))?.*)");
				std::smatch valmatch;
				std::vector<unsigned char> realct(tagsize, 0);
				if (!std::regex_match(first, valmatch, val))
					continue;
				long blocksize = stol(valmatch.str(1));
				bool aes = valmatch[2].matched;
				long keysize = aes ? stol(valmatch.str(3)) : 128;

				bool exception_thrown = false;
				{
					std::unique_ptr<cppcrypto::aead> ch;
					if (aes)
					{
						switch (keysize)
						{
						case 128:
							ch.reset(new aead_ocb(rijndael128_128()));
							break;
						case 192:
							ch.reset(new aead_ocb(rijndael128_192()));
							break;
						case 256:
							ch.reset(new aead_ocb(rijndael128_256()));
							break;
						}
					}
					else
					{
						switch (blocksize)
						{
						case 128:
							ch.reset(new aead_ocb(rc6_16_16<128>()));
							break;
						case 160:
							ch.reset(new aead_ocb(rc6_16_16<160>()));
							break;
						case 192:
							ch.reset(new aead_ocb(rc6_16_16<192>()));
							break;
						case 224:
							ch.reset(new aead_ocb(rc6_16_16<224>()));
							break;
						case 256:
							ch.reset(new aead_ocb(rc6_16_16<256>()));
							break;
						case 512:
							ch.reset(new aead_ocb(rc6_16_16<512>()));
							break;
						case 1024:
							ch.reset(new aead_ocb(rc6_16_16<1024>()));
							break;
						}
					}

					try
					{
						if (ch->tag_bytes() != tagsize)
							ch->set_tagsize_in_bits(tagsize * 8);
						ch->set_key(key.data(), key.size());

						std::vector<unsigned char> ct(16256 + 48 * ch->tag_bytes() * 8, 0);
						unsigned char s[8 * 128];
						if (!aes)
							std::iota(s, s + sizeof(s), 0);
						else
							std::fill(s, s + sizeof(s), 0);
						unsigned char iv[12];
						memset(iv, 0, sizeof(iv));
						uint16_t* nonce = reinterpret_cast<uint16_t*>(iv + (aes ? 10 : 0));
						unsigned char* out = &ct[0];
						size_t iv_len = aes ? 12 : 2;

						for (size_t i = 0; i < 128; i++)
						{
							*nonce = swap_uint16(static_cast<uint16_t>(3 * i + 1));
							ch->encrypt_with_explicit_iv(s, i, s, i, iv, iv_len, out, i + ch->tag_bytes());
							out += i + ch->tag_bytes();
							*nonce = swap_uint16(static_cast<uint16_t>(3 * i + 2));
							ch->encrypt_with_explicit_iv(s, i, s, 0, iv, iv_len, out, i + ch->tag_bytes());
							out += i + ch->tag_bytes();
							*nonce = swap_uint16(static_cast<uint16_t>(3 * i + 3));
							ch->encrypt_with_explicit_iv(s, 0, s, i, iv, iv_len, out, ch->tag_bytes());
							out += ch->tag_bytes();
						}
						*nonce = swap_uint16(385);
						ch->encrypt_with_explicit_iv(ct.data(), 0, ct.data(), out - &ct[0], iv, iv_len, &realct[0], ch->tag_bytes());

						exception_thrown = memcmp(&realct[0], &tag[0], realct.size()) != 0;
					}
					catch (std::exception&)
					{
						exception_thrown = true;
					}

					if (exception_thrown)
					{
						std::cerr << "Error for test " << std::dec << count << " (validation)" << std::endl;
#define CPPCRYPTO_DEBUG
#ifdef CPPCRYPTO_DEBUG
						std::wcerr << _T("key was: ");
						for (size_t i = 0; i < key.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)key[i];
						std::wcerr << _T("\nactual tag is: ");
						for (size_t i = 0; i < realct.size(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)realct[i];
						std::wcerr << _T("\nexpected tag is: ");
						for (size_t i = 0; i < tag.length(); i++)
							std::wcerr << std::setfill(_T('0')) << std::setw(2) << std::hex << (unsigned int)tag[i];
						std::wcerr << _T("\n");
#endif
						error = true;
					}
				}

				count++;
				if (error)
					failed++;
				else
					success++;
			}

		}
	}
	std::wcout << name << _T(": ");
	if (success)
		std::wcout << (success) << _T("/") << std::dec << count << _T(" OK");
	if (failed && success)
		std::wcout << _T(", ");
	if (failed)
		std::wcout << failed << _T("/") << std::dec << count << _T(" FAILED");
	if (!success && !failed)
		std::wcout << _T("No tests found");
	std::wcout << std::endl;

	return std::make_pair(success, failed);
}

int test_all()
{
	uint32_t total_failed = 0, total_success = 0;
	std::pair<uint32_t, uint32_t> res { 0, 0 };

	res = test_vector(_T("anubis128"), anubis128(), _T("block_cipher/anubis128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("anubis160"), anubis160(), _T("block_cipher/anubis160.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("anubis192"), anubis192(), _T("block_cipher/anubis192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("anubis224"), anubis224(), _T("block_cipher/anubis224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("anubis256"), anubis256(), _T("block_cipher/anubis256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("anubis288"), anubis288(), _T("block_cipher/anubis288.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("anubis320"), anubis320(), _T("block_cipher/anubis320.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("aria128"), aria128(), _T("block_cipher/aria128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("aria192"), aria192(), _T("block_cipher/aria192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("aria256"), aria256(), _T("block_cipher/aria256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("camellia128"), camellia128(), _T("block_cipher/camellia128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("camellia192"), camellia192(), _T("block_cipher/camellia192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("camellia256"), camellia256(), _T("block_cipher/camellia256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("cast6_128"), cast6_128(), _T("block_cipher/cast6_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("cast6_192"), cast6_192(), _T("block_cipher/cast6_192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("cast6_256"), cast6_256(), _T("block_cipher/cast6_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("kalyna128_128"), kalyna128_128(), _T("block_cipher/kalyna128_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("kalyna128_256"), kalyna128_256(), _T("block_cipher/kalyna128_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("kalyna256_256"), kalyna256_256(), _T("block_cipher/kalyna256_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("kalyna256_512"), kalyna256_512(), _T("block_cipher/kalyna256_512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("kalyna512_512"), kalyna512_512(), _T("block_cipher/kalyna512_512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("kuznyechik"), kuznyechik(), _T("block_cipher/kuznyechik.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("mars128"), mars128(), _T("block_cipher/mars128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("mars160"), mars160(), _T("block_cipher/mars160.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("mars192"), mars192(), _T("block_cipher/mars192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("mars224"), mars224(), _T("block_cipher/mars224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("mars256"), mars256(), _T("block_cipher/mars256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("mars288"), mars288(), _T("block_cipher/mars288.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("mars320"), mars320(), _T("block_cipher/mars320.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("mars352"), mars352(), _T("block_cipher/mars352.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("mars384"), mars384(), _T("block_cipher/mars384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("mars416"), mars416(), _T("block_cipher/mars416.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("mars448"), mars448(), _T("block_cipher/mars448.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael128_128"), rijndael128_128(), _T("block_cipher/rijndael128_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael128_160"), rijndael128_160(), _T("block_cipher/rijndael128_160.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael128_192"), rijndael128_192(), _T("block_cipher/rijndael128_192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael128_224"), rijndael128_224(), _T("block_cipher/rijndael128_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael128_256"), rijndael128_256(), _T("block_cipher/rijndael128_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael160_128"), rijndael160_128(), _T("block_cipher/rijndael160_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael160_160"), rijndael160_160(), _T("block_cipher/rijndael160_160.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael160_192"), rijndael160_192(), _T("block_cipher/rijndael160_192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael160_224"), rijndael160_224(), _T("block_cipher/rijndael160_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael160_256"), rijndael160_256(), _T("block_cipher/rijndael160_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael192_128"), rijndael192_128(), _T("block_cipher/rijndael192_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael192_160"), rijndael192_160(), _T("block_cipher/rijndael192_160.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael192_192"), rijndael192_192(), _T("block_cipher/rijndael192_192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael192_224"), rijndael192_224(), _T("block_cipher/rijndael192_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael192_256"), rijndael192_256(), _T("block_cipher/rijndael192_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael224_128"), rijndael224_128(), _T("block_cipher/rijndael224_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael224_160"), rijndael224_160(), _T("block_cipher/rijndael224_160.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael224_192"), rijndael224_192(), _T("block_cipher/rijndael224_192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael224_224"), rijndael224_224(), _T("block_cipher/rijndael224_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael224_256"), rijndael224_256(), _T("block_cipher/rijndael224_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael256_128"), rijndael256_128(), _T("block_cipher/rijndael256_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael256_160"), rijndael256_160(), _T("block_cipher/rijndael256_160.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael256_192"), rijndael256_192(), _T("block_cipher/rijndael256_192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael256_224"), rijndael256_224(), _T("block_cipher/rijndael256_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("rijndael256_256"), rijndael256_256(), _T("block_cipher/rijndael256_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("serpent128"), serpent128(), _T("block_cipher/serpent128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("serpent192"), serpent192(), _T("block_cipher/serpent192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("serpent256"), serpent256(), _T("block_cipher/serpent256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("simon128_128"), simon128_128(), _T("block_cipher/simon128_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("simon128_192"), simon128_192(), _T("block_cipher/simon128_192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("simon128_256"), simon128_256(), _T("block_cipher/simon128_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sm4"), sm4(), _T("block_cipher/sm4.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("speck128_128"), speck128_128(), _T("block_cipher/speck128_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("speck128_192"), speck128_192(), _T("block_cipher/speck128_192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("speck128_256"), speck128_256(), _T("block_cipher/speck128_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("threefish256_256"), threefish256_256(), _T("block_cipher/threefish256_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("threefish512_512"), threefish512_512(), _T("block_cipher/threefish512_512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("threefish1024_1024"), threefish1024_1024(), _T("block_cipher/threefish1024_1024.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("twofish128"), twofish128(), _T("block_cipher/twofish128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("twofish192"), twofish192(), _T("block_cipher/twofish192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("twofish256"), twofish256(), _T("block_cipher/twofish256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("hc-128"), hc128(), _T("stream_cipher/hc-128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("hc-256"), hc256(), _T("stream_cipher/hc-256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("salsa20-12-128"), salsa20_12_128(), _T("stream_cipher/salsa20-12-128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("salsa20-12-256"), salsa20_12_256(), _T("stream_cipher/salsa20-12-256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("salsa20-128"), salsa20_128(), _T("stream_cipher/salsa20-20-128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("salsa20-256"), salsa20_256(), _T("stream_cipher/salsa20-20-256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("xsalsa20-256"), xsalsa20_256(), _T("stream_cipher/xsalsa20-256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("chacha12-128"), chacha12_128(), _T("stream_cipher/chacha12-128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("chacha12-256"), chacha12_256(), _T("stream_cipher/chacha12-256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("chacha20-128"), chacha20_128(), _T("stream_cipher/chacha20-128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("chacha20-256"), chacha20_256(), _T("stream_cipher/chacha20-256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("xchacha12-256"), xchacha12_256(), _T("stream_cipher/xchacha12-256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("xchacha20-256"), xchacha20_256(), _T("stream_cipher/xchacha20-256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake/224"), blake(224), _T("hash/blake224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake/256"), blake(256), _T("hash/blake256.txt"));
	total_success += res.first;
	total_failed += res.second;

	// FIXME pass salt not in the constructor, but via method; merge test vectors
	unsigned char blakesalt[32];
	std::iota(blakesalt, blakesalt + sizeof(blakesalt), 0);

	res = test_vector(_T("blake/256salt"), blake(256, blakesalt, 16), _T("hash/blake256salt.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake/384"), blake(384), _T("hash/blake384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake/384salt"), blake(384, blakesalt, 32), _T("hash/blake384salt.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake/512"), blake(512), _T("hash/blake512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake2s/128"), blake2s(128), _T("hash/blake2s_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake2s/160"), blake2s(160), _T("hash/blake2s_160.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake2s/224"), blake2s(224), _T("hash/blake2s_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake2s/256"), blake2s(256), _T("hash/blake2s_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake2b/128"), blake2b(128), _T("hash/blake2b_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake2b/160"), blake2b(160), _T("hash/blake2b_160.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake2b/224"), blake2b(224), _T("hash/blake2b_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake2b/256"), blake2b(256), _T("hash/blake2b_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake2b/384"), blake2b(384), _T("hash/blake2b_384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("blake2b/512"), blake2b(512), _T("hash/blake2b_512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("cshake256/512"), shake256(512, "", "Email Signature"), _T("hash/cshake256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("echo/224"), echo(224), _T("hash/echo224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("echo/256"), echo(256), _T("hash/echo256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("echo/384"), echo(384), _T("hash/echo384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("echo/512"), echo(512), _T("hash/echo512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("esch/256"), esch(256), _T("hash/esch256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("esch/384"), esch(384), _T("hash/esch384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("groestl/224"), groestl(224), _T("hash/groestl224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("groestl/256"), groestl(256), _T("hash/groestl256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("groestl/384"), groestl(384), _T("hash/groestl384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("groestl/512"), groestl(512), _T("hash/groestl512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("jh/224"), jh(224), _T("hash/jh224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("jh/256"), jh(256), _T("hash/jh256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("jh/384"), jh(384), _T("hash/jh384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("jh/512"), jh(512), _T("hash/jh512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("kupyna/256"), kupyna(256), _T("hash/kupyna256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("kupyna/512"), kupyna(512), _T("hash/kupyna512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("md5"), md5(), _T("hash/md5.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sha1"), sha1(), _T("hash/sha1.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sha224"), sha224(), _T("hash/sha224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sha256"), sha256(), _T("hash/sha256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sha384"), sha384(), _T("hash/sha384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sha512"), sha512(), _T("hash/sha512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sha512/224"), sha512(224), _T("hash/sha512_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sha512/256"), sha512(256), _T("hash/sha512_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sha3/224"), sha3(224), _T("hash/sha3_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sha3/256"), sha3(256), _T("hash/sha3_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sha3/384"), sha3(384), _T("hash/sha3_384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sha3/512"), sha3(512), _T("hash/sha3_512.txt"));
	total_success += res.first;
	total_failed += res.second;

	// FIXME test vectors from digestpp, size as parameter, different output sizes
	res = test_vector(_T("shake128/1120"), shake128(1120), _T("hash/shake128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("shake256/4096"), shake256(4096), _T("hash/shake256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein256/128"), skein256(128), _T("hash/skein256_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein256/160"), skein256(160), _T("hash/skein256_160.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein256/224"), skein256(224), _T("hash/skein256_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein256/256"), skein256(256), _T("hash/skein256_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein256/2056"), skein256(2056), _T("hash/skein256_2056.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein512/128"), skein512(128), _T("hash/skein512_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein512/160"), skein512(160), _T("hash/skein512_160.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein512/224"), skein512(224), _T("hash/skein512_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein512/256"), skein512(256), _T("hash/skein512_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein512/384"), skein512(384), _T("hash/skein512_384.txt"));
	total_success += res.first;
	total_failed += res.second;

	// FIXME uncomment test of skein with personalization and make sure it passes
	// FIXME also add tests from digestpp test.cc (parametrized skein, etc) to test vectors
	// FIXME move parametrized tests from separate txt files to regular txt files
	res = test_vector(_T("skein512/512"), skein512(512), _T("hash/skein512_512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein512/2056"), skein512(2056), _T("hash/skein512_2056.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein1024/256"), skein1024(256), _T("hash/skein1024_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein1024/384"), skein1024(384), _T("hash/skein1024_384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein1024/512"), skein1024(512), _T("hash/skein1024_512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein1024/1024"), skein1024(1024), _T("hash/skein1024_1024.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("skein1024/2056"), skein1024(2056), _T("hash/skein1024_2056.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("sm3"), sm3(), _T("hash/sm3.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("streebog/256"), streebog(256), _T("hash/streebog256.txt"));
	total_success += res.first;
	total_failed += res.second;
	
	res = test_vector(_T("streebog/512"), streebog(512), _T("hash/streebog512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("whirlpool"), whirlpool(), _T("hash/whirlpool.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(hmac(sha224()), _T("hmac-sha224"), _T("mac/hmac_sha224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(hmac(sha256()), _T("hmac-sha256"), _T("mac/hmac_sha256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(hmac(sha384()), _T("hmac-sha384"), _T("mac/hmac_sha384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(hmac(sha512()), _T("hmac-sha512"), _T("mac/hmac_sha512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(hmac(sha512(256)), _T("hmac-sha512/256"), _T("mac/hmac_sha512-256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(hmac(sha1()), _T("hmac-sha1"), _T("mac/hmac_sha1.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(hmac(md5()), _T("hmac-md5"), _T("mac/hmac_md5.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(hmac(sha3(224)), _T("hmac-sha3/224"), _T("mac/hmac_sha3_224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(hmac(sha3(256)), _T("hmac-sha3/256"), _T("mac/hmac_sha3_256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(hmac(sha3(384)), _T("hmac-sha3/384"), _T("mac/hmac_sha3_384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(hmac(sha3(512)), _T("hmac-sha3/512"), _T("mac/hmac_sha3_512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hmac(poly1305(), _T("poly1305"), _T("mac/poly1305.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_cbc(_T("aes-128-cbc"), rijndael128_128(), _T("modes/aescbc128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_cbc(_T("aes-192-cbc"), rijndael128_192(), _T("modes/aescbc192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_cbc(_T("aes-256-cbc"), rijndael128_256(), _T("modes/aescbc256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_cbc(_T("aria-256-cbc"), aria256(), _T("modes/ariacbc256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("aes-128-ctr"), ctr(rijndael128_128()), _T("modes/aesctr128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("aes-192-ctr"), ctr(rijndael128_192()), _T("modes/aesctr192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("aes-256-ctr"), ctr(rijndael128_256()), _T("modes/aesctr256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("aria-128-ctr"), ctr(aria128()), _T("modes/ariactr128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_vector(_T("serpent-256-ctr"), ctr(serpent256()), _T("modes/serpentctr256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("aes-128-gcm"), aead_gcm(rijndael128_128()), _T("aead/gcm-aes128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("aes-192-gcm"), aead_gcm(rijndael128_192()), _T("aead/gcm-aes192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("aes-256-gcm"), aead_gcm(rijndael128_256()), _T("aead/gcm-aes256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("aria-128-gcm"), aead_gcm(aria128()), _T("aead/gcm-aria128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("aria-256-gcm"), aead_gcm(aria256()), _T("aead/gcm-aria256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("camellia-128-gcm"), aead_gcm(camellia128()), _T("aead/gcm-camellia128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("camellia-192-gcm"), aead_gcm(camellia192()), _T("aead/gcm-camellia192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("camellia-256-gcm"), aead_gcm(camellia256()), _T("aead/gcm-camellia256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("aes-128-ocb"), aead_ocb(rijndael128_128()), _T("aead/ocb-aes128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("rc6-64/16/16-ocb"), aead_ocb(rc6_16_16<256>()), _T("aead/ocb-rc6_256_16_16.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("rijndael-160/128-ocb"), aead_ocb(rijndael160_128()), _T("aead/ocb-rijndael160_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("rijndael-192/128-ocb"), aead_ocb(rijndael192_128()), _T("aead/ocb-rijndael192_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("rijndael-224/128-ocb"), aead_ocb(rijndael224_128()), _T("aead/ocb-rijndael224_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("rijndael-256/128-ocb"), aead_ocb(rijndael256_128()), _T("aead/ocb-rijndael256_128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("kalyna-512/512-ocb"), aead_ocb(kalyna512_512()), _T("aead/ocb-kalyna512_512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("threefish-512/512-ocb"), aead_ocb(threefish512_512()), _T("aead/ocb-threefish512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("threefish-1024/1024-ocb"), aead_ocb(threefish1024_1024()), _T("aead/ocb-threefish1024.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = validate_ocb(_T("aes-ocb-validate"), _T("aead/ocb-validate-aes.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = validate_ocb(_T("rc6-ocb-validate"), _T("aead/ocb-validate-rc6.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("ietf-chacha20-poly1305"), aead_ietf_chacha_poly(), _T("aead/ietf-chacha-poly.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("ietf-xchacha20-poly1305"), aead_ietf_chacha_poly(xchacha20_256()), _T("aead/ietf-xchacha-poly.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("schwaemm256_128"), schwaemm(schwaemm::variant::schwaemm256_128), _T("aead/schwaemm256-128.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("schwaemm256_256"), schwaemm(schwaemm::variant::schwaemm256_256), _T("aead/schwaemm256-256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_aead(_T("schwaemm192_192"), schwaemm(schwaemm::variant::schwaemm192_192), _T("aead/schwaemm192-192.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hkdf(sha256(), _T("hkdf_expand_sha256"), _T("kdf/hkdf_expand_sha256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hkdf(sha384(), _T("hkdf_expand_sha384"), _T("kdf/hkdf_expand_sha384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hkdf(sha512(), _T("hkdf_expand_sha512"), _T("kdf/hkdf_expand_sha512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hkdf(sha256(), _T("hkdf_sha256"), _T("kdf/hkdf_sha256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hkdf(sha384(), _T("hkdf_sha384"), _T("kdf/hkdf_sha384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hkdf(sha512(), _T("hkdf_sha512"), _T("kdf/hkdf_sha512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_hkdf(sha1(), _T("hkdf_sha1"), _T("kdf/hkdf_sha1.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_pbkdf2(sha224(), _T("pbkdf2-hmac-sha224"), _T("kdf/pbkdf2-hmac-sha224.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_pbkdf2(sha256(), _T("pbkdf2-hmac-sha256"), _T("kdf/pbkdf2-hmac-sha256.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_pbkdf2(sha384(), _T("pbkdf2-hmac-sha384"), _T("kdf/pbkdf2-hmac-sha384.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_pbkdf2(sha512(), _T("pbkdf2-hmac-sha512"), _T("kdf/pbkdf2-hmac-sha512.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_pbkdf2(sha1(), _T("pbkdf2-hmac-sha1"), _T("kdf/pbkdf2-hmac-sha1.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_scrypt(_T("scrypt"), _T("kdf/scrypt.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_argon(_T("argon2i"), _T("kdf/argon2i.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_argon(_T("argon2d"), _T("kdf/argon2d.txt"));
	total_success += res.first;
	total_failed += res.second;

	res = test_argon(_T("argon2id"), _T("kdf/argon2id.txt"));
	total_success += res.first;
	total_failed += res.second;


	std::cerr << "TOTAL TESTS PASSED: " << total_success << ", TOTAL TESTS FAILED: " << total_failed << std::endl;
	return total_failed == 0 ? 1 : 0;
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc == 2 && std::wstring(argv[1]) == _T("all"))
		return test_all();

	std::map<std::wstring, std::unique_ptr<block_cipher>> block_ciphers;

	block_ciphers.emplace(std::make_pair(_T("aes128"), std::unique_ptr<block_cipher>(new rijndael128_128)));
	block_ciphers.emplace(std::make_pair(_T("rijndael128-160"), std::unique_ptr<block_cipher>(new rijndael128_160)));
	block_ciphers.emplace(std::make_pair(_T("aes192"), std::unique_ptr<block_cipher>(new rijndael128_192)));
	block_ciphers.emplace(std::make_pair(_T("rijndael128-224"), std::unique_ptr<block_cipher>(new rijndael128_224)));
	block_ciphers.emplace(std::make_pair(_T("aes256"), std::unique_ptr<block_cipher>(new rijndael128_256)));
	block_ciphers.emplace(std::make_pair(_T("rijndael256-256"), std::unique_ptr<block_cipher>(new rijndael256_256)));
	block_ciphers.emplace(std::make_pair(_T("rijndael256-128"), std::unique_ptr<block_cipher>(new rijndael256_128)));
	block_ciphers.emplace(std::make_pair(_T("rijndael256-224"), std::unique_ptr<block_cipher>(new rijndael256_224)));
	block_ciphers.emplace(std::make_pair(_T("rijndael256-160"), std::unique_ptr<block_cipher>(new rijndael256_160)));
	block_ciphers.emplace(std::make_pair(_T("rijndael256-192"), std::unique_ptr<block_cipher>(new rijndael256_192)));

	block_ciphers.emplace(std::make_pair(_T("anubis128"), std::unique_ptr<block_cipher>(new anubis128)));
	block_ciphers.emplace(std::make_pair(_T("anubis160"), std::unique_ptr<block_cipher>(new anubis160)));
	block_ciphers.emplace(std::make_pair(_T("anubis192"), std::unique_ptr<block_cipher>(new anubis192)));
	block_ciphers.emplace(std::make_pair(_T("anubis224"), std::unique_ptr<block_cipher>(new anubis224)));
	block_ciphers.emplace(std::make_pair(_T("anubis256"), std::unique_ptr<block_cipher>(new anubis256)));
	block_ciphers.emplace(std::make_pair(_T("anubis288"), std::unique_ptr<block_cipher>(new anubis288)));
	block_ciphers.emplace(std::make_pair(_T("anubis320"), std::unique_ptr<block_cipher>(new anubis320)));

	block_ciphers.emplace(std::make_pair(_T("rijndael192-128"), std::unique_ptr<block_cipher>(new rijndael192_128)));
	block_ciphers.emplace(std::make_pair(_T("rijndael192-160"), std::unique_ptr<block_cipher>(new rijndael192_160)));
	block_ciphers.emplace(std::make_pair(_T("rijndael192-192"), std::unique_ptr<block_cipher>(new rijndael192_192)));
	block_ciphers.emplace(std::make_pair(_T("rijndael192-224"), std::unique_ptr<block_cipher>(new rijndael192_224)));
	block_ciphers.emplace(std::make_pair(_T("rijndael192-256"), std::unique_ptr<block_cipher>(new rijndael192_256)));

	block_ciphers.emplace(std::make_pair(_T("twofish128"), std::unique_ptr<block_cipher>(new twofish128)));
	block_ciphers.emplace(std::make_pair(_T("twofish192"), std::unique_ptr<block_cipher>(new twofish192)));
	block_ciphers.emplace(std::make_pair(_T("twofish256"), std::unique_ptr<block_cipher>(new twofish256)));

	block_ciphers.emplace(std::make_pair(_T("serpent256"), std::unique_ptr<block_cipher>(new serpent256)));
	block_ciphers.emplace(std::make_pair(_T("serpent128"), std::unique_ptr<block_cipher>(new serpent128)));
	block_ciphers.emplace(std::make_pair(_T("serpent192"), std::unique_ptr<block_cipher>(new serpent192)));

	block_ciphers.emplace(std::make_pair(_T("cast6_256"), std::unique_ptr<block_cipher>(new cast6_256)));
	block_ciphers.emplace(std::make_pair(_T("cast6_224"), std::unique_ptr<block_cipher>(new cast6_224)));
	block_ciphers.emplace(std::make_pair(_T("cast6_192"), std::unique_ptr<block_cipher>(new cast6_192)));
	block_ciphers.emplace(std::make_pair(_T("cast6_160"), std::unique_ptr<block_cipher>(new cast6_160)));
	block_ciphers.emplace(std::make_pair(_T("cast6_128"), std::unique_ptr<block_cipher>(new cast6_128)));

	block_ciphers.emplace(std::make_pair(_T("rijndael160-128"), std::unique_ptr<block_cipher>(new rijndael160_128)));
	block_ciphers.emplace(std::make_pair(_T("rijndael160-160"), std::unique_ptr<block_cipher>(new rijndael160_160)));
	block_ciphers.emplace(std::make_pair(_T("rijndael160-192"), std::unique_ptr<block_cipher>(new rijndael160_192)));
	block_ciphers.emplace(std::make_pair(_T("rijndael160-224"), std::unique_ptr<block_cipher>(new rijndael160_224)));
	block_ciphers.emplace(std::make_pair(_T("rijndael160-256"), std::unique_ptr<block_cipher>(new rijndael160_256)));
	block_ciphers.emplace(std::make_pair(_T("rijndael224-128"), std::unique_ptr<block_cipher>(new rijndael224_128)));
	block_ciphers.emplace(std::make_pair(_T("rijndael224-160"), std::unique_ptr<block_cipher>(new rijndael224_160)));
	block_ciphers.emplace(std::make_pair(_T("rijndael224-192"), std::unique_ptr<block_cipher>(new rijndael224_192)));
	block_ciphers.emplace(std::make_pair(_T("rijndael224-224"), std::unique_ptr<block_cipher>(new rijndael224_224)));
	block_ciphers.emplace(std::make_pair(_T("rijndael224-256"), std::unique_ptr<block_cipher>(new rijndael224_256)));

	block_ciphers.emplace(std::make_pair(_T("camellia128"), std::unique_ptr<block_cipher>(new camellia128)));
	block_ciphers.emplace(std::make_pair(_T("camellia256"), std::unique_ptr<block_cipher>(new camellia256)));
	block_ciphers.emplace(std::make_pair(_T("camellia192"), std::unique_ptr<block_cipher>(new camellia192)));
	block_ciphers.emplace(std::make_pair(_T("kalyna512-512"), std::unique_ptr<block_cipher>(new kalyna512_512)));
	block_ciphers.emplace(std::make_pair(_T("kalyna256-512"), std::unique_ptr<block_cipher>(new kalyna256_512)));
	block_ciphers.emplace(std::make_pair(_T("kalyna256-256"), std::unique_ptr<block_cipher>(new kalyna256_256)));
	block_ciphers.emplace(std::make_pair(_T("kalyna128-256"), std::unique_ptr<block_cipher>(new kalyna128_256)));
	block_ciphers.emplace(std::make_pair(_T("kalyna128-128"), std::unique_ptr<block_cipher>(new kalyna128_128)));

	block_ciphers.emplace(std::make_pair(_T("aria128"), std::unique_ptr<block_cipher>(new aria128)));
	block_ciphers.emplace(std::make_pair(_T("aria256"), std::unique_ptr<block_cipher>(new aria256)));
	block_ciphers.emplace(std::make_pair(_T("aria192"), std::unique_ptr<block_cipher>(new aria192)));

	block_ciphers.emplace(std::make_pair(_T("kuznyechik"), std::unique_ptr<block_cipher>(new kuznyechik)));
	block_ciphers.emplace(std::make_pair(_T("sm4"), std::unique_ptr<block_cipher>(new sm4)));
	block_ciphers.emplace(std::make_pair(_T("mars448"), std::unique_ptr<block_cipher>(new mars448)));
	block_ciphers.emplace(std::make_pair(_T("mars192"), std::unique_ptr<block_cipher>(new mars192)));
	block_ciphers.emplace(std::make_pair(_T("mars256"), std::unique_ptr<block_cipher>(new mars256)));
	block_ciphers.emplace(std::make_pair(_T("mars320"), std::unique_ptr<block_cipher>(new mars320)));
	block_ciphers.emplace(std::make_pair(_T("mars128"), std::unique_ptr<block_cipher>(new mars128)));
	block_ciphers.emplace(std::make_pair(_T("mars160"), std::unique_ptr<block_cipher>(new mars160)));
	block_ciphers.emplace(std::make_pair(_T("mars224"), std::unique_ptr<block_cipher>(new mars224)));
	block_ciphers.emplace(std::make_pair(_T("mars288"), std::unique_ptr<block_cipher>(new mars288)));
	block_ciphers.emplace(std::make_pair(_T("mars352"), std::unique_ptr<block_cipher>(new mars352)));
	block_ciphers.emplace(std::make_pair(_T("mars384"), std::unique_ptr<block_cipher>(new mars384)));
	block_ciphers.emplace(std::make_pair(_T("mars416"), std::unique_ptr<block_cipher>(new mars416)));

	block_ciphers.emplace(std::make_pair(_T("threefish512_512"), std::unique_ptr<block_cipher>(new threefish512_512)));
	block_ciphers.emplace(std::make_pair(_T("threefish1024_1024"), std::unique_ptr<block_cipher>(new threefish1024_1024)));
	block_ciphers.emplace(std::make_pair(_T("threefish256_256"), std::unique_ptr<block_cipher>(new threefish256_256)));

	block_ciphers.emplace(std::make_pair(_T("simon128_128"), std::unique_ptr<block_cipher>(new simon128_128)));
	block_ciphers.emplace(std::make_pair(_T("simon128_192"), std::unique_ptr<block_cipher>(new simon128_192)));
	block_ciphers.emplace(std::make_pair(_T("simon128_256"), std::unique_ptr<block_cipher>(new simon128_256)));

	block_ciphers.emplace(std::make_pair(_T("speck128_128"), std::unique_ptr<block_cipher>(new speck128_128)));
	block_ciphers.emplace(std::make_pair(_T("speck128_192"), std::unique_ptr<block_cipher>(new speck128_192)));
	block_ciphers.emplace(std::make_pair(_T("speck128_256"), std::unique_ptr<block_cipher>(new speck128_256)));

	std::map<std::wstring, std::unique_ptr<stream_cipher>> stream_ciphers;

	stream_ciphers.emplace(std::make_pair(_T("salsa20_256"), std::unique_ptr<stream_cipher>(new salsa20_256)));
	stream_ciphers.emplace(std::make_pair(_T("salsa20_128"), std::unique_ptr<stream_cipher>(new salsa20_128)));
	stream_ciphers.emplace(std::make_pair(_T("hc256"), std::unique_ptr<stream_cipher>(new hc256)));
	stream_ciphers.emplace(std::make_pair(_T("xsalsa20_256"), std::unique_ptr<stream_cipher>(new xsalsa20_256)));
	stream_ciphers.emplace(std::make_pair(_T("xsalsa20_128"), std::unique_ptr<stream_cipher>(new xsalsa20_128)));
	stream_ciphers.emplace(std::make_pair(_T("hc128"), std::unique_ptr<stream_cipher>(new hc128)));
	stream_ciphers.emplace(std::make_pair(_T("salsa20_12_256"), std::unique_ptr<stream_cipher>(new salsa20_12_256)));
	stream_ciphers.emplace(std::make_pair(_T("salsa20_12_128"), std::unique_ptr<stream_cipher>(new salsa20_12_128)));
	stream_ciphers.emplace(std::make_pair(_T("xsalsa20_12_256"), std::unique_ptr<stream_cipher>(new xsalsa20_12_256)));
	stream_ciphers.emplace(std::make_pair(_T("xsalsa20_12_128"), std::unique_ptr<stream_cipher>(new xsalsa20_12_128)));
	stream_ciphers.emplace(std::make_pair(_T("chacha20_256"), std::unique_ptr<stream_cipher>(new chacha20_256)));
	stream_ciphers.emplace(std::make_pair(_T("chacha20_128"), std::unique_ptr<stream_cipher>(new chacha20_128)));
	stream_ciphers.emplace(std::make_pair(_T("xchacha20_256"), std::unique_ptr<stream_cipher>(new xchacha20_256)));
	stream_ciphers.emplace(std::make_pair(_T("xchacha20_128"), std::unique_ptr<stream_cipher>(new xchacha20_128)));
	stream_ciphers.emplace(std::make_pair(_T("chacha12_256"), std::unique_ptr<stream_cipher>(new chacha12_256)));
	stream_ciphers.emplace(std::make_pair(_T("chacha12_128"), std::unique_ptr<stream_cipher>(new chacha12_128)));
	stream_ciphers.emplace(std::make_pair(_T("xchacha12_256"), std::unique_ptr<stream_cipher>(new xchacha12_256)));
	stream_ciphers.emplace(std::make_pair(_T("xchacha12_128"), std::unique_ptr<stream_cipher>(new xchacha12_128)));

	std::map<std::wstring, std::unique_ptr<crypto_hash>> hashes;
	hashes.emplace(std::make_pair(_T("sha256"), std::unique_ptr<crypto_hash>(new sha256)));
	hashes.emplace(std::make_pair(_T("groestl/256"), std::unique_ptr<crypto_hash>(new groestl(256))));
	hashes.emplace(std::make_pair(_T("blake/256"), std::unique_ptr<crypto_hash>(new blake(256))));

	hashes.emplace(std::make_pair(_T("groestl/512"), std::unique_ptr<crypto_hash>(new groestl(512))));
	hashes.emplace(std::make_pair(_T("sha512"), std::unique_ptr<crypto_hash>(new sha512)));
	hashes.emplace(std::make_pair(_T("sha512/256"), std::unique_ptr<crypto_hash>(new sha512(256))));
	hashes.emplace(std::make_pair(_T("sha512/224"), std::unique_ptr<crypto_hash>(new sha512(224))));
	hashes.emplace(std::make_pair(_T("sha384"), std::unique_ptr<crypto_hash>(new sha384)));
	hashes.emplace(std::make_pair(_T("groestl/384"), std::unique_ptr<crypto_hash>(new groestl(384))));
	hashes.emplace(std::make_pair(_T("groestl/224"), std::unique_ptr<crypto_hash>(new groestl(224))));

	hashes.emplace(std::make_pair(_T("skein512/256"), std::unique_ptr<crypto_hash>(new skein512(256))));
	hashes.emplace(std::make_pair(_T("skein512/512"), std::unique_ptr<crypto_hash>(new skein512(512))));
	hashes.emplace(std::make_pair(_T("blake/512"), std::unique_ptr<crypto_hash>(new blake(512))));
	hashes.emplace(std::make_pair(_T("blake/384"), std::unique_ptr<crypto_hash>(new blake(384))));
	hashes.emplace(std::make_pair(_T("blake/224"), std::unique_ptr<crypto_hash>(new blake(224))));
	hashes.emplace(std::make_pair(_T("skein512/384"), std::unique_ptr<crypto_hash>(new skein512(384))));
	hashes.emplace(std::make_pair(_T("skein512/224"), std::unique_ptr<crypto_hash>(new skein512(224))));

	hashes.emplace(std::make_pair(_T("skein256/256"), std::unique_ptr<crypto_hash>(new skein256(256))));
	hashes.emplace(std::make_pair(_T("skein256/224"), std::unique_ptr<crypto_hash>(new skein256(224))));
	hashes.emplace(std::make_pair(_T("skein1024/1024"), std::unique_ptr<crypto_hash>(new skein1024(1024))));
	hashes.emplace(std::make_pair(_T("skein1024/512"), std::unique_ptr<crypto_hash>(new skein1024(512))));
	hashes.emplace(std::make_pair(_T("skein1024/384"), std::unique_ptr<crypto_hash>(new skein1024(384))));
	hashes.emplace(std::make_pair(_T("sha224"), std::unique_ptr<crypto_hash>(new sha224)));

	hashes.emplace(std::make_pair(_T("whirlpool"), std::unique_ptr<crypto_hash>(new whirlpool)));
	hashes.emplace(std::make_pair(_T("kupyna/256"), std::unique_ptr<crypto_hash>(new kupyna(256))));
	hashes.emplace(std::make_pair(_T("kupyna/512"), std::unique_ptr<crypto_hash>(new kupyna(512))));
	hashes.emplace(std::make_pair(_T("skein512/128"), std::unique_ptr<crypto_hash>(new skein512(128))));
	hashes.emplace(std::make_pair(_T("skein512/160"), std::unique_ptr<crypto_hash>(new skein512(160))));
	hashes.emplace(std::make_pair(_T("skein256/128"), std::unique_ptr<crypto_hash>(new skein256(128))));
	hashes.emplace(std::make_pair(_T("skein256/160"), std::unique_ptr<crypto_hash>(new skein256(160))));
	hashes.emplace(std::make_pair(_T("skein1024/256"), std::unique_ptr<crypto_hash>(new skein1024(256))));

	hashes.emplace(std::make_pair(_T("sha3/512"), std::unique_ptr<crypto_hash>(new sha3(512))));
	hashes.emplace(std::make_pair(_T("sha3/256"), std::unique_ptr<crypto_hash>(new sha3(256))));
	hashes.emplace(std::make_pair(_T("sha3/384"), std::unique_ptr<crypto_hash>(new sha3(384))));
	hashes.emplace(std::make_pair(_T("sha3/224"), std::unique_ptr<crypto_hash>(new sha3(224))));
	hashes.emplace(std::make_pair(_T("jh/512"), std::unique_ptr<crypto_hash>(new jh(512))));
	hashes.emplace(std::make_pair(_T("jh/384"), std::unique_ptr<crypto_hash>(new jh(384))));
	hashes.emplace(std::make_pair(_T("jh/224"), std::unique_ptr<crypto_hash>(new jh(224))));
	hashes.emplace(std::make_pair(_T("jh/256"), std::unique_ptr<crypto_hash>(new jh(256))));
	hashes.emplace(std::make_pair(_T("sha1"), std::unique_ptr<crypto_hash>(new sha1)));

	hashes.emplace(std::make_pair(_T("streebog/512"), std::unique_ptr<crypto_hash>(new streebog(512))));
	hashes.emplace(std::make_pair(_T("streebog/256"), std::unique_ptr<crypto_hash>(new streebog(256))));
	hashes.emplace(std::make_pair(_T("sm3"), std::unique_ptr<crypto_hash>(new sm3)));
	hashes.emplace(std::make_pair(_T("md5"), std::unique_ptr<crypto_hash>(new md5)));

	hashes.emplace(std::make_pair(_T("blake2b/512"), std::unique_ptr<crypto_hash>(new blake2b(512))));
	hashes.emplace(std::make_pair(_T("blake2b/256"), std::unique_ptr<crypto_hash>(new blake2b(256))));
	hashes.emplace(std::make_pair(_T("blake2b/384"), std::unique_ptr<crypto_hash>(new blake2b(384))));
	hashes.emplace(std::make_pair(_T("blake2b/224"), std::unique_ptr<crypto_hash>(new blake2b(224))));
	hashes.emplace(std::make_pair(_T("blake2b/160"), std::unique_ptr<crypto_hash>(new blake2b(160))));
	hashes.emplace(std::make_pair(_T("blake2b/128"), std::unique_ptr<crypto_hash>(new blake2b(128))));
	hashes.emplace(std::make_pair(_T("blake2s/256"), std::unique_ptr<crypto_hash>(new blake2s(256))));
	hashes.emplace(std::make_pair(_T("blake2s/224"), std::unique_ptr<crypto_hash>(new blake2s(224))));
	hashes.emplace(std::make_pair(_T("blake2s/160"), std::unique_ptr<crypto_hash>(new blake2s(160))));
	hashes.emplace(std::make_pair(_T("blake2s/128"), std::unique_ptr<crypto_hash>(new blake2s(128))));

	hashes.emplace(std::make_pair(_T("esch/256"), std::unique_ptr<crypto_hash>(new esch(256))));
	hashes.emplace(std::make_pair(_T("esch/384"), std::unique_ptr<crypto_hash>(new esch(384))));
	hashes.emplace(std::make_pair(_T("echo/224"), std::unique_ptr<crypto_hash>(new echo(224))));
	hashes.emplace(std::make_pair(_T("echo/256"), std::unique_ptr<crypto_hash>(new echo(256))));
	hashes.emplace(std::make_pair(_T("echo/384"), std::unique_ptr<crypto_hash>(new echo(384))));
	hashes.emplace(std::make_pair(_T("echo/512"), std::unique_ptr<crypto_hash>(new echo(512))));

	hashes.emplace(std::make_pair(_T("sha512/128"), std::unique_ptr<crypto_hash>(new sha512(128))));
	hashes.emplace(std::make_pair(_T("sha512/160"), std::unique_ptr<crypto_hash>(new sha512(160))));

	std::map<std::wstring, std::unique_ptr<aead>> aeads;

	std::set<std::wstring> excluded_hashes, excluded_bcs;
	excluded_hashes.emplace(_T("md5"));
	excluded_hashes.emplace(_T("sha1"));
	excluded_hashes.emplace(_T("streebog/256"));
	excluded_hashes.emplace(_T("streebog/512"));
	excluded_bcs.emplace(_T("kuznyechik"));


	for (auto hash_it = hashes.begin(); hash_it != hashes.end(); ++hash_it)
	{
		if (excluded_hashes.find(hash_it->first) != excluded_hashes.end())
			continue;
		//if (hash_it->first != _T("sha256"))
		//	continue;
		for (auto bc_it = block_ciphers.begin(); bc_it != block_ciphers.end(); ++bc_it)
		{
			if (excluded_bcs.find(bc_it->first) != excluded_bcs.end())
				continue;
			aeads.emplace(std::make_pair(bc_it->first + _T("-ctr-hmac-") + hash_it->first, std::unique_ptr<aead>(new aead_etm(ctr(*bc_it->second), hmac(*hash_it->second)))));
		}
		for (auto sc_it = stream_ciphers.begin(); sc_it != stream_ciphers.end(); ++sc_it)
		{
			aeads.emplace(std::make_pair(sc_it->first + _T("-hmac-") + hash_it->first, std::unique_ptr<aead>(new aead_etm(*sc_it->second, hmac(*hash_it->second)))));
		}
	}
	for (auto bc_it = block_ciphers.begin(); bc_it != block_ciphers.end(); ++bc_it)
	{
		if (excluded_bcs.find(bc_it->first) != excluded_bcs.end())
			continue;
		aeads.emplace(std::make_pair(bc_it->first + _T("-ocb"), std::unique_ptr<aead>(new aead_ocb(*bc_it->second))));
		if (bc_it->second->blocksize() == 128)
			aeads.emplace(std::make_pair(bc_it->first + _T("-gcm"), std::unique_ptr<aead>(new aead_gcm(*bc_it->second))));
	}
	for (auto sc_it = stream_ciphers.begin(); sc_it != stream_ciphers.end(); ++sc_it)
	{
		if (sc_it->first.find(_T("chacha")) != std::wstring::npos || sc_it->first.find(_T("salsa")) != std::wstring::npos)
			aeads.emplace(std::make_pair(sc_it->first + _T("-poly1305"), std::unique_ptr<aead>(new aead_ietf_chacha_poly(*sc_it->second))));
	}
	for (auto bc_it = block_ciphers.begin(); bc_it != block_ciphers.end(); ++bc_it)
	{
		if (excluded_bcs.find(bc_it->first) != excluded_bcs.end())
			continue;
		aeads.emplace(std::make_pair(bc_it->first + _T("-ctr-poly1305"), std::unique_ptr<aead>(new aead_etm(ctr(*bc_it->second), poly1305()))));
	}
	for (auto sc_it = stream_ciphers.begin(); sc_it != stream_ciphers.end(); ++sc_it)
	{
		if (sc_it->first.find(_T("chacha")) == std::wstring::npos && sc_it->first.find(_T("salsa")) == std::wstring::npos)
			aeads.emplace(std::make_pair(sc_it->first + _T("-poly1305"), std::unique_ptr<aead>(new aead_etm(*sc_it->second, poly1305()))));
	}

	aeads.emplace(_T("schwaemm-256-256"), std::unique_ptr<aead>(new schwaemm(schwaemm::variant::schwaemm256_256)));
	aeads.emplace(_T("schwaemm-192-192"), std::unique_ptr<aead>(new schwaemm(schwaemm::variant::schwaemm192_192)));
	aeads.emplace(_T("schwaemm-256-128"), std::unique_ptr<aead>(new schwaemm(schwaemm::variant::schwaemm256_128)));

	if (argc == 4 && std::wstring(argv[1]) == _T("hashtest"))
	{
		long iterations = 0;
		if (argc != 4 || (iterations = std::stol(argv[2])) < 1)
		{
			std::cerr << "Syntax: digest test <iterations> <filename>" << std::endl;
			return 3;
		}
		perftest(hashes, iterations, argv[3]);
		return 0;
	}

	if (argc == 4 && std::wstring(argv[1]) == _T("bctest"))
	{
		long iterations = 0;
		if (argc != 4 || (iterations = std::stol(argv[2])) < 1)
		{
			std::cerr << "Syntax: digest bctest <iterations> <filename>" << std::endl;
			return 3;
		}
		bcperftest(block_ciphers, iterations, argv[3]);
		return 0;
	}

	if (argc == 4 && std::wstring(argv[1]) == _T("sctest"))
	{
		long iterations = 0;
		if (argc != 4 || (iterations = std::stol(argv[2])) < 1)
		{
			std::cerr << "Syntax: digest sctest <iterations> <filename>" << std::endl;
			return 3;
		}
		scperftest(stream_ciphers, iterations, argv[3]);
		return 0;
	}


	if (argc == 4 && std::wstring(argv[1]) == _T("aeadtest"))
	{
		long iterations = 0;
		if (argc != 4 || (iterations = std::stol(argv[2])) < 1)
		{
			std::cerr << "Syntax: digest sctest <iterations> <filename>" << std::endl;
			return 3;
		}
		aeadperftest(aeads, iterations, argv[3]);
		return 0;
	}

	std::cerr << "Syntax:" << std::endl;
	std::cerr << "  cppcryptotest all" << std::endl;
	std::cerr << "Performance tests: " << std::endl;
	std::cerr << "  cppcryptotest hashtest <iterations> <filename>" << std::endl;
	std::cerr << "  cppcryptotest bctest <iterations> <filename>" << std::endl;
	std::cerr << "  cppcryptotest scest <iterations> <filename>" << std::endl;
	std::cerr << "  cppcryptotest aeadtest <iterations> <filename>" << std::endl;
	return 1;
}
