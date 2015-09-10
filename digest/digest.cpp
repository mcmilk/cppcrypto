/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "stdafx.h"
#include "perftimer.h"
#include <sys/stat.h>

using namespace std;
using namespace cppcrypto;

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

inline std::wstring& rtrim(std::wstring& str, const wchar_t* chars = L" \t\r\n")
{
	return str.erase(str.find_last_not_of(chars) + 1);
}

bool is_directory(const wchar_t* path)
{
	std::wstring spath(path);
	struct _stat64 st_stat;

	rtrim(spath, L"/\\");

	if (spath.length() > 1 && *spath.rbegin() == L':')
		spath += L'/';

	return !_wstat64(spath.c_str(), &st_stat) && (st_stat.st_mode & S_IFDIR);
}


bool hash_file(const wchar_t* filename, vector<char>* hashsum, int hashbitlen, crypto_hash* hash)
{
	ifstream file;
	char buffer[10240];
	long long read = 0;
	long long fileSize = file_size(filename);

	hash->init();

	if (fileSize == std::numeric_limits<size_t>::max())
		return false;

	file.open(filename, ios::in | ios::binary);

	if (!file)
		return false;

	while (read < fileSize)
	{
		long long blockSize = std::min(long long(sizeof(buffer)), fileSize - read);

		if (!file.read(buffer, blockSize))
			return false;

		read += blockSize;

		hash->update((const uint8_t*)buffer, static_cast<size_t>(blockSize));
	}

	hashsum->resize(hashbitlen/8);
	hash->final((uint8_t*)(&((*hashsum)[0])));

	return true;
}


static void print_hex(uint8_t *key, int len)
{
	int i;
	for (i = 0; i< len; i++) printf("%02x", key[i]);  puts("");
}

void perftest(map<wstring, unique_ptr<crypto_hash>>& hashes, long iterations, wstring filename)
{
	perftimer timer;

	if (!file_exists(filename.c_str())) {
		wcerr << filename << L": No such file or directory" << endl;
		return;
	}
	if (is_directory(filename.c_str())) {
		wcerr << filename << L": Is a directory" << endl;
		return;
	}

	long long fileSize = file_size(filename.c_str());

	if (fileSize > 10000000)
	{
		cerr << "File is too big.\n";
		return;
	}

	char* message = new char[static_cast<size_t>(fileSize)];

	ifstream file;
	file.open(filename, ios::in | ios::binary);
	if (!file)
		return;

	if (!file.read(message, fileSize))
		return;

	file.close();
	unsigned char hash[128];

	for (auto it = hashes.begin(); it != hashes.end(); ++it)
	{
		wcout << it->first << L" ";

		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			it->second->hash_string(message, static_cast<size_t>(fileSize), hash);
		}
		wcout << fixed << timer.elapsed() << L" ";
		for (int i = 0; i < (it->second->hashbitlen() + 7) / 8; i++)
			wcout << setfill(L'0') << setw(2) << hex << (unsigned char)hash[i];
		wcout << endl;
	}
}


void checksumfile(const wchar_t* filename, crypto_hash* hash)
{
	wstring str;
	wifstream file(filename, ios::in);
	while (getline(file, str)) {
		wregex parts(L"^(\\w+)\\s+(.+)$");
		wsmatch sm;
		if (regex_search(str, sm, parts)) {
			wstring fn = sm.str(2);
			wchar_t buf[129];
			vector<char> res;
			bool ret = hash_file(fn.c_str(), &res, hash->hashbitlen(), hash);
			if (ret) {
				for (int i = 0; i < (hash->hashbitlen() + 7) / 8; i++)
					wsprintf(buf + i * 2, L"%02x", (unsigned char)res[i]);
			}
			else
				wcerr << "Error for " << fn << endl;
			wcout << fn << ": " << (wstring(buf) == sm.str(1) ? L"OK" : L"FAILED") << endl;
		}
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	map<wstring, unique_ptr<crypto_hash>> hashes;
	hashes.emplace(make_pair(L"sha256", unique_ptr<crypto_hash>(new sha256)));
	hashes.emplace(make_pair(L"groestl256", unique_ptr<crypto_hash>(new groestl256)));
	hashes.emplace(make_pair(L"blake256", unique_ptr<crypto_hash>(new blake256)));

	hashes.emplace(make_pair(L"groestl512", unique_ptr<crypto_hash>(new groestl512)));
	hashes.emplace(make_pair(L"sha512", unique_ptr<crypto_hash>(new sha512)));
	hashes.emplace(make_pair(L"sha512/256", unique_ptr<crypto_hash>(new sha512_256)));
	hashes.emplace(make_pair(L"sha512/224", unique_ptr<crypto_hash>(new sha512_224)));
	hashes.emplace(make_pair(L"sha384", unique_ptr<crypto_hash>(new sha384)));
	hashes.emplace(make_pair(L"groestl384", unique_ptr<crypto_hash>(new groestl384)));
	hashes.emplace(make_pair(L"groestl224", unique_ptr<crypto_hash>(new groestl224)));

	hashes.emplace(make_pair(L"skein512/256", unique_ptr<crypto_hash>(new skein512_256)));
	hashes.emplace(make_pair(L"skein512/512", unique_ptr<crypto_hash>(new skein512_512)));
	hashes.emplace(make_pair(L"blake512", unique_ptr<crypto_hash>(new blake512)));
	hashes.emplace(make_pair(L"blake384", unique_ptr<crypto_hash>(new blake384)));
	hashes.emplace(make_pair(L"blake224", unique_ptr<crypto_hash>(new blake224)));
	hashes.emplace(make_pair(L"skein512/384", unique_ptr<crypto_hash>(new skein512_384)));
	hashes.emplace(make_pair(L"skein512/224", unique_ptr<crypto_hash>(new skein512_224)));

	hashes.emplace(make_pair(L"skein256/256", unique_ptr<crypto_hash>(new skein256_256)));
	hashes.emplace(make_pair(L"skein256/224", unique_ptr<crypto_hash>(new skein256_224)));
	hashes.emplace(make_pair(L"skein1024/1024", unique_ptr<crypto_hash>(new skein1024_1024)));
	hashes.emplace(make_pair(L"skein1024/512", unique_ptr<crypto_hash>(new skein1024_512)));
	hashes.emplace(make_pair(L"skein1024/384", unique_ptr<crypto_hash>(new skein1024_384)));
	hashes.emplace(make_pair(L"sha224", unique_ptr<crypto_hash>(new sha224)));

	hashes.emplace(make_pair(L"whirlpool", unique_ptr<crypto_hash>(new whirlpool)));

	if (argc < 3)
	{
		cerr << "Syntax: digest [-c] <algorithm> <filename> ..." << endl;
		cerr << "Performance test: digest test <iterations> <filename>" << endl;
		cerr << "Supported algorithms: ";
		for (auto it = hashes.begin(); it != hashes.end(); ++it)
			wcerr << it->first << " ";
		cerr << endl;
		return 1;
	}

	bool checking = wstring(argv[1]) == L"-c";
	wstring hash = argv[checking ? 2 : 1];

	if (hash == L"test")
	{
		long iterations = 0;
		if (argc != 4 || (iterations = stol(argv[2])) < 1)
		{
			cerr << "Syntax: digest test <iterations> <filename>" << endl;
			return 3;
		}
		perftest(hashes, iterations, argv[3]);
		return 0;
	}

	auto hashit = hashes.find(hash);
	if (hashit == hashes.end())
	{
		wcerr << L"Unknown hash algorithm: " << hash << endl;
		return 2;
	}

	for (int i = checking ? 3 : 2; i < argc; i++) {
		if (checking) {
			checksumfile(argv[i], hashit->second.get());
			continue;
		}
		if (!file_exists(argv[i])) {
			wcerr << argv[i] << L": No such file or directory" << endl;
			continue;
		}
		if (is_directory(argv[i])) {
			wcerr << argv[i] << L": Is a directory" << endl;
			continue;
		}
		vector<char> res;
		if (hash_file(argv[i], &res, hashit->second->hashbitlen(), hashit->second.get()))
		{
			for (int b = 0; b < (hashit->second->hashbitlen() + 7) / 8; b++)
				printf("%02x", (unsigned char)res[b]);
			wprintf(L"  %s\n", argv[i]);
		}
		else
			wcerr << L"Error for " << argv[i] << endl;
	}

	return 0;
}

