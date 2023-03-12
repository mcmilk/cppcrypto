/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "stdafx.h"
#include <sys/stat.h>
#include <algorithm>
#include <numeric>
#include <limits>

using namespace std;
using namespace cppcrypto;

#ifndef _MSC_VER
#define wchar_t char
#define _T(A) A
#define _stat64 stat
#define _wstat64 stat
#define wstring string
#define wmain main
#define wregex regex
#define wsmatch smatch
#define wcerr cerr
#define wcout cout
#define wifstream ifstream
#define wprintf printf
#define wsprintf sprintf
#define sscanf_s sscanf
#else
#define _T(A) L ## A
#endif

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


bool hash_file(const wchar_t* filename, vector<char>* hashsum, size_t hashsize, crypto_hash* hash)
{
	ifstream file;
	char buffer[10240];
	long long read = 0;
	long long fileSize = file_size(filename);

	hash->init();

	if (static_cast<unsigned long long>(fileSize) == std::numeric_limits<size_t>::max())
		return false;

	file.open(filename, ios::in | ios::binary);

	if (!file)
		return false;

	while (read < fileSize)
	{
		long long blockSize = std::min(static_cast<long long>(sizeof(buffer)), fileSize - read);

		if (!file.read(buffer, blockSize))
			return false;

		read += blockSize;

		hash->update((const unsigned char*)buffer, static_cast<size_t>(blockSize));
	}

	hashsum->resize(hashsize/8);
	hash->final((unsigned char*)(&((*hashsum)[0])));

	return true;
}

void checksumfile(const wchar_t* filename, crypto_hash* hash)
{
	wstring str;
	wifstream file(filename, ios::in);
	while (getline(file, str)) {
		wregex parts(_T("^(\\w+)\\s+(.+)$"));
		wsmatch sm;
		if (regex_search(str, sm, parts)) {
			wstring fn = sm.str(2);
			wchar_t buf[129];
			vector<char> res;
			bool ret = hash_file(fn.c_str(), &res, hash->hashsize(), hash);
			if (ret) {
				for (size_t i = 0; i < (hash->hashsize() + 7) / 8; i++)
					wsprintf(buf + i * 2, _T("%02x"), (unsigned char)res[i]);
			}
			else
				wcerr << "Error for " << fn << endl;
			wcout << fn << ": " << (wstring(buf) == sm.str(1) ? _T("OK") : _T("FAILED")) << endl;
		}
	}
}

void hex2array(const string& hex, unsigned char* array)
{
	const char* pos = hex.c_str();
	for (size_t count = 0; count < hex.size()/2; count++) {
		sscanf_s(pos, "%2hhx", array+count);
		pos += 2;
	}
}

int wmain(int argc, wchar_t* argv[])
{
	map<wstring, unique_ptr<crypto_hash>> hashes;
	hashes.emplace(make_pair(_T("sha256"), unique_ptr<crypto_hash>(new sha256)));
	hashes.emplace(make_pair(_T("groestl/256"), unique_ptr<crypto_hash>(new groestl(256))));
	hashes.emplace(make_pair(_T("blake/256"), unique_ptr<crypto_hash>(new blake(256))));

	hashes.emplace(make_pair(_T("groestl/512"), unique_ptr<crypto_hash>(new groestl(512))));
	hashes.emplace(make_pair(_T("sha512"), unique_ptr<crypto_hash>(new sha512)));
	hashes.emplace(make_pair(_T("sha512/256"), unique_ptr<crypto_hash>(new sha512(256))));
	hashes.emplace(make_pair(_T("sha512/224"), unique_ptr<crypto_hash>(new sha512(224))));
	hashes.emplace(make_pair(_T("sha512/160"), unique_ptr<crypto_hash>(new sha512(160))));
	hashes.emplace(make_pair(_T("sha512/128"), unique_ptr<crypto_hash>(new sha512(128))));
	hashes.emplace(make_pair(_T("sha384"), unique_ptr<crypto_hash>(new sha384)));
	hashes.emplace(make_pair(_T("groestl/384"), unique_ptr<crypto_hash>(new groestl(384))));
	hashes.emplace(make_pair(_T("groestl/224"), unique_ptr<crypto_hash>(new groestl(224))));

	hashes.emplace(make_pair(_T("skein512/256"), unique_ptr<crypto_hash>(new skein512(256))));
	hashes.emplace(make_pair(_T("skein512/512"), unique_ptr<crypto_hash>(new skein512(512))));
	hashes.emplace(make_pair(_T("blake/512"), unique_ptr<crypto_hash>(new blake(512))));
	hashes.emplace(make_pair(_T("blake/384"), unique_ptr<crypto_hash>(new blake(384))));
	hashes.emplace(make_pair(_T("blake/224"), unique_ptr<crypto_hash>(new blake(224))));
	hashes.emplace(make_pair(_T("skein512/384"), unique_ptr<crypto_hash>(new skein512(384))));
	hashes.emplace(make_pair(_T("skein512/224"), unique_ptr<crypto_hash>(new skein512(224))));

	hashes.emplace(make_pair(_T("skein256/256"), unique_ptr<crypto_hash>(new skein256(256))));
	hashes.emplace(make_pair(_T("skein256/224"), unique_ptr<crypto_hash>(new skein256(224))));
	hashes.emplace(make_pair(_T("skein1024/1024"), unique_ptr<crypto_hash>(new skein1024(1024))));
	hashes.emplace(make_pair(_T("skein1024/512"), unique_ptr<crypto_hash>(new skein1024(512))));
	hashes.emplace(make_pair(_T("skein1024/384"), unique_ptr<crypto_hash>(new skein1024(384))));
	hashes.emplace(make_pair(_T("sha224"), unique_ptr<crypto_hash>(new sha224)));

	hashes.emplace(make_pair(_T("whirlpool"), unique_ptr<crypto_hash>(new whirlpool)));
	hashes.emplace(make_pair(_T("kupyna/256"), unique_ptr<crypto_hash>(new kupyna(256))));
	hashes.emplace(make_pair(_T("kupyna/512"), unique_ptr<crypto_hash>(new kupyna(512))));
	hashes.emplace(make_pair(_T("skein512/128"), unique_ptr<crypto_hash>(new skein512(128))));
	hashes.emplace(make_pair(_T("skein512/160"), unique_ptr<crypto_hash>(new skein512(160))));
	hashes.emplace(make_pair(_T("skein256/128"), unique_ptr<crypto_hash>(new skein256(128))));
	hashes.emplace(make_pair(_T("skein256/160"), unique_ptr<crypto_hash>(new skein256(160))));
	hashes.emplace(make_pair(_T("skein1024/256"), unique_ptr<crypto_hash>(new skein1024(256))));

	hashes.emplace(make_pair(_T("sha3/512"), unique_ptr<crypto_hash>(new sha3(512))));
	hashes.emplace(make_pair(_T("sha3/256"), unique_ptr<crypto_hash>(new sha3(256))));
	hashes.emplace(make_pair(_T("sha3/384"), unique_ptr<crypto_hash>(new sha3(384))));
	hashes.emplace(make_pair(_T("sha3/224"), unique_ptr<crypto_hash>(new sha3(224))));
	hashes.emplace(make_pair(_T("jh/512"), unique_ptr<crypto_hash>(new jh(512))));
	hashes.emplace(make_pair(_T("jh/384"), unique_ptr<crypto_hash>(new jh(384))));
	hashes.emplace(make_pair(_T("jh/224"), unique_ptr<crypto_hash>(new jh(224))));
	hashes.emplace(make_pair(_T("jh/256"), unique_ptr<crypto_hash>(new jh(256))));
	hashes.emplace(make_pair(_T("sha1"), unique_ptr<crypto_hash>(new sha1)));

	hashes.emplace(make_pair(_T("streebog/512"), unique_ptr<crypto_hash>(new streebog(512))));
	hashes.emplace(make_pair(_T("streebog/256"), unique_ptr<crypto_hash>(new streebog(256))));
	hashes.emplace(make_pair(_T("sm3"), unique_ptr<crypto_hash>(new sm3)));
	hashes.emplace(make_pair(_T("md5"), unique_ptr<crypto_hash>(new md5)));

	hashes.emplace(make_pair(_T("blake2b/512"), unique_ptr<crypto_hash>(new blake2b(512))));
	hashes.emplace(make_pair(_T("blake2b/256"), unique_ptr<crypto_hash>(new blake2b(256))));
	hashes.emplace(make_pair(_T("blake2b/384"), unique_ptr<crypto_hash>(new blake2b(384))));
	hashes.emplace(make_pair(_T("blake2b/224"), unique_ptr<crypto_hash>(new blake2b(224))));
	hashes.emplace(make_pair(_T("blake2b/160"), unique_ptr<crypto_hash>(new blake2b(160))));
	hashes.emplace(make_pair(_T("blake2b/128"), unique_ptr<crypto_hash>(new blake2b(128))));
	hashes.emplace(make_pair(_T("blake2s/256"), unique_ptr<crypto_hash>(new blake2s(256))));
	hashes.emplace(make_pair(_T("blake2s/224"), unique_ptr<crypto_hash>(new blake2s(224))));
	hashes.emplace(make_pair(_T("blake2s/160"), unique_ptr<crypto_hash>(new blake2s(160))));
	hashes.emplace(make_pair(_T("blake2s/128"), unique_ptr<crypto_hash>(new blake2s(128))));

	hashes.emplace(make_pair(_T("shake128/256"), unique_ptr<crypto_hash>(new shake128(256))));
	hashes.emplace(make_pair(_T("shake256/512"), unique_ptr<crypto_hash>(new shake256(512))));
	hashes.emplace(make_pair(_T("esch/256"), unique_ptr<crypto_hash>(new esch(256))));
	hashes.emplace(make_pair(_T("esch/384"), unique_ptr<crypto_hash>(new esch(384))));
	hashes.emplace(make_pair(_T("echo/224"), unique_ptr<crypto_hash>(new echo(224))));
	hashes.emplace(make_pair(_T("echo/256"), unique_ptr<crypto_hash>(new echo(256))));
	hashes.emplace(make_pair(_T("echo/384"), unique_ptr<crypto_hash>(new echo(384))));
	hashes.emplace(make_pair(_T("echo/512"), unique_ptr<crypto_hash>(new echo(512))));

	if (argc < 3)
	{
		cerr << "Syntax: digest [-c] <algorithm> <filename> ..." << endl;
		cerr << "Supported algorithms: ";
		for (auto it = hashes.begin(); it != hashes.end(); ++it)
			wcerr << it->first << " ";
		cerr << endl;
		return 1;
	}

	bool checking = wstring(argv[1]) == _T("-c");
	wstring hash = argv[checking ? 2 : 1];

	auto hashit = hashes.find(hash);
	if (hashit == hashes.end())
	{
		wcerr << _T("Unknown hash algorithm: ") << hash << endl;
		return 2;
	}

	for (int i = checking ? 3 : 2; i < argc; i++) {
		if (checking) {
			checksumfile(argv[i], hashit->second.get());
			continue;
		}
		if (!file_exists(argv[i])) {
			wcerr << argv[i] << _T(": No such file or directory") << endl;
			continue;
		}
		if (is_directory(argv[i])) {
			wcerr << argv[i] << _T(": Is a directory") << endl;
			continue;
		}
		vector<char> res;
		if (hash_file(argv[i], &res, hashit->second->hashsize(), hashit->second.get()))
		{
			for (size_t b = 0; b < (hashit->second->hashsize() + 7) / 8; b++)
				printf("%02x", (unsigned char)res[b]);
			wprintf(_T("  %s\n"), argv[i]);
		}
		else
			wcerr << _T("Error for ") << argv[i] << endl;
	}

	return 0;
}

