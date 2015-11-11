/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "stdafx.h"
#include "perftimer.h"
#include <sys/stat.h>
//#define DUMP_TEST_ENCRYPTION

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


bool hash_file(const wchar_t* filename, vector<char>* hashsum, int hashsize, crypto_hash* hash)
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

		hash->update((const uint8_t*)buffer, static_cast<size_t>(blockSize));
	}

	hashsum->resize(hashsize/8);
	hash->final((uint8_t*)(&((*hashsum)[0])));

	return true;
}


void block_cipher_perf_test(map<wstring, unique_ptr<block_cipher>>& ciphers, long iterations)
{
	perftimer timer;
	unsigned char pt[512];
	unsigned char ct[512];
	unsigned char key[512];
	memset(pt, 0, sizeof(pt));
	memset(key, 0, sizeof(key));

	for (auto it = ciphers.begin(); it != ciphers.end(); ++it)
	{
		wcout << it->first << _T(" ");

		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			it->second->init(key, block_cipher::encryption);
			it->second->encrypt_block(pt, ct);
		}
		wcout << fixed << timer.elapsed() << _T(" ");
		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			it->second->init(key, block_cipher::decryption);
			it->second->decrypt_block(ct, pt);
		}
		wcout << fixed << timer.elapsed() << _T(" ");
		wcout << endl;
	}


}

void perftest(map<wstring, unique_ptr<crypto_hash>>& hashes, long iterations, wstring filename)
{
	perftimer timer;

	if (!file_exists(filename.c_str())) {
		wcerr << filename << _T(": No such file or directory") << endl;
		return;
	}
	if (is_directory(filename.c_str())) {
		wcerr << filename << _T(": Is a directory") << endl;
		return;
	}

	long long fileSize = file_size(filename.c_str());

	if (fileSize > 20000000)
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
		wcout << it->first << _T(" ");

		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			it->second->hash_string(message, static_cast<size_t>(fileSize), hash);
		}
		double seconds = timer.elapsed();
		wcout << fixed << setprecision(5) << seconds << _T(" (") << setprecision(2) 
			<< (static_cast<double>(fileSize) / 1024.0 / 1024.0 * static_cast<double>(iterations) / seconds) << _T(" MB/s) ");
		for (int i = 0; i < (it->second->hashsize() + 7) / 8; i++)
			wcout << setfill(_T('0')) << setw(2) << hex << (unsigned int)hash[i];
		wcout << endl;
	}
}


void bcperftest(map<wstring, unique_ptr<block_cipher>>& ciphers, long iterations, wstring filename)
{
	perftimer timer;

	if (!file_exists(filename.c_str())) {
		wcerr << filename << _T(": No such file or directory") << endl;
		return;
	}
	if (is_directory(filename.c_str())) {
		wcerr << filename << _T(": Is a directory") << endl;
		return;
	}

	long long fileSize = file_size(filename.c_str());

	if (fileSize > 20000000)
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
	unsigned char* ct = new unsigned char[static_cast<size_t>(fileSize + 1024*2)];
	unsigned char* pt = new unsigned char[static_cast<size_t>(fileSize + 1024 * 2)];
	unsigned char key[1024];
	unsigned char iv[1024];
	unsigned char* next = ct;
	memset(key, 0, sizeof(key));
	memset(iv, 0, sizeof(iv));
	for (int i = 0; i < 16; i++)
		iv[i] = i;

	key[0] = 0x2b;
	key[1] = 0x7e;
	key[2] = 0x15;
	key[3] = 0x16;
	key[4] = 0x28;
	key[5] = 0xae;
	key[6] = 0xd2;
	key[7] = 0xa6;
	key[8] = 0xab;
	key[9] = 0xf7;
	key[10] = 0x15;
	key[11] = 0x88;
	key[12] = 0x09;
	key[13] = 0xcf;
	key[14] = 0x4f;
	key[15] = 0x3c;
	for (auto it = ciphers.begin(); it != ciphers.end(); ++it)
	{
		wcout << it->first << _T(" ");
		cbc cbc(*it->second);
		ctr ctr(*it->second);
		timer.reset();
		size_t resultlen;
		for (long i = 0; i < iterations; i++)
		{
			cbc.init(key, it->second->keysize()/8, iv,it->second->blocksize()/8 ,block_cipher::encryption);
			next = ct;
			cbc.encrypt_update((uint8_t*)message, static_cast<size_t>(fileSize), ct, resultlen);
			next += resultlen;
			cbc.encrypt_final(next, resultlen);
		}
		next += resultlen;
		double seconds = timer.elapsed();
		wcout << fixed << setprecision(5) << seconds << _T(" (") << setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s) ");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream ofile(filename + _T(".") + it->first, ios::out | ios::binary);
		ofile.write((const char*)ct, next - ct);
#endif

		uint8_t* next2 = pt;
		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			cbc.init(key, it->second->keysize()/8, iv, it->second->blocksize()/8, block_cipher::decryption);
			next2 = pt;
			cbc.decrypt_update((uint8_t*)ct, next-ct, next2, resultlen);
			next2 += resultlen;
			cbc.decrypt_final(next2, resultlen);
		}
		next2 += resultlen;
		seconds = timer.elapsed();
		wcout << fixed << setprecision(5) << seconds << _T(" (") << setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s)");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream odfile(filename + _T(".") + it->first + _T(".decrypted"), ios::out | ios::binary);
		odfile.write((const char*)pt, next2 - pt);
#endif

		if (memcmp(pt, message, static_cast<size_t>(fileSize)))
			wcout << _T(" ERROR");
		if (fileSize != next2 - pt)
			wcout << _T(" SZMISMATCH");

		wcout << _T(" ");
		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			ctr.init(key, it->second->keysize() / 8, iv, it->second->blocksize() / 8, block_cipher::encryption);
			ctr.encrypt((uint8_t*)message, static_cast<size_t>(fileSize), ct);
		}
		seconds = timer.elapsed();
		wcout << fixed << setprecision(5) << seconds << _T(" (") << setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s) ");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream octrfile(filename + _T(".") + it->first + _T(".ctr"), ios::out | ios::binary);
		octrfile.write((const char*)ct, fileSize);
#endif

		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			ctr.init(key, it->second->keysize() / 8, iv, it->second->blocksize() / 8, block_cipher::decryption);
			ctr.decrypt((uint8_t*)ct, static_cast<size_t>(fileSize), pt);
		}
		seconds = timer.elapsed();
		wcout << fixed << setprecision(5) << seconds << _T(" (") << setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s)");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream odctrfile(filename + _T(".") + it->first + _T(".ctr.decrypted"), ios::out | ios::binary);
		odctrfile.write((const char*)pt, fileSize);
#endif

		if (memcmp(pt, message, static_cast<size_t>(fileSize)))
			wcout << _T(" ERROR");

		wcout << endl;
	}
	delete[] ct;
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
				for (int i = 0; i < (hash->hashsize() + 7) / 8; i++)
					wsprintf(buf + i * 2, _T("%02x"), (unsigned char)res[i]);
			}
			else
				wcerr << "Error for " << fn << endl;
			wcout << fn << ": " << (wstring(buf) == sm.str(1) ? _T("OK") : _T("FAILED")) << endl;
		}
	}
}

void hex2array(const string& hex, uint8_t* array)
{
	const char* pos = hex.c_str();
	for (size_t count = 0; count < hex.size()/2; count++) {
		sscanf_s(pos, "%2hhx", array+count);
		pos += 2;
	}
}

void test_vector(block_cipher* bc, const wstring& filename)
{
	ifstream file(filename, ios::in | ios::binary);
	string line;
	uint8_t key[128], pt[128], ct[128], res[128];
	uint32_t count = 0;
	regex eq(R"((\w+)\s*=\s*(\w+))");
	while (getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		smatch sm;
		if (regex_match(line, sm, eq))
		{
			string second = sm.str(2);
			if (sm.str(1) == "PT")
				hex2array(second, pt);
			if (sm.str(1) == "KEY")
				hex2array(second, key);
			if (sm.str(1) == "CT")
			{
				hex2array(second, ct);
				bc->init(key, bc->encryption);
				bc->encrypt_block(pt, res);
				if (memcmp(ct, res, second.length() / 2))
					cerr << "Error for test " << count << " (encryption)" << endl;
				bc->init(key, bc->decryption);
				bc->decrypt_block(ct, res);
				if (memcmp(pt, res, second.length() / 2))
					cerr << "Error for test " << count << " (decryption)" << endl;
				count++;
			}

		}
	}
	cout << count << " tests completed." << endl;
}

int wmain(int argc, wchar_t* argv[])
{
	map<wstring, unique_ptr<block_cipher>> block_ciphers;

	block_ciphers.emplace(make_pair(_T("rijndael128-128"), unique_ptr<block_cipher>(new rijndael128_128)));
	block_ciphers.emplace(make_pair(_T("rijndael128-160"), unique_ptr<block_cipher>(new rijndael128_160)));
	block_ciphers.emplace(make_pair(_T("rijndael128-192"), unique_ptr<block_cipher>(new rijndael128_192)));
	block_ciphers.emplace(make_pair(_T("rijndael128-224"), unique_ptr<block_cipher>(new rijndael128_224)));
	block_ciphers.emplace(make_pair(_T("rijndael128-256"), unique_ptr<block_cipher>(new rijndael128_256)));
	block_ciphers.emplace(make_pair(_T("rijndael256-256"), unique_ptr<block_cipher>(new rijndael256_256)));
	block_ciphers.emplace(make_pair(_T("rijndael256-128"), unique_ptr<block_cipher>(new rijndael256_128)));
	block_ciphers.emplace(make_pair(_T("rijndael256-224"), unique_ptr<block_cipher>(new rijndael256_224)));
	block_ciphers.emplace(make_pair(_T("rijndael256-160"), unique_ptr<block_cipher>(new rijndael256_160)));
	block_ciphers.emplace(make_pair(_T("rijndael256-192"), unique_ptr<block_cipher>(new rijndael256_192)));

	block_ciphers.emplace(make_pair(_T("anubis128"), unique_ptr<block_cipher>(new anubis128)));
	block_ciphers.emplace(make_pair(_T("anubis160"), unique_ptr<block_cipher>(new anubis160)));
	block_ciphers.emplace(make_pair(_T("anubis192"), unique_ptr<block_cipher>(new anubis192)));
	block_ciphers.emplace(make_pair(_T("anubis224"), unique_ptr<block_cipher>(new anubis224)));
	block_ciphers.emplace(make_pair(_T("anubis256"), unique_ptr<block_cipher>(new anubis256)));
	block_ciphers.emplace(make_pair(_T("anubis288"), unique_ptr<block_cipher>(new anubis288)));
	block_ciphers.emplace(make_pair(_T("anubis320"), unique_ptr<block_cipher>(new anubis320)));

	block_ciphers.emplace(make_pair(_T("rijndael192-128"), unique_ptr<block_cipher>(new rijndael192_128)));
	block_ciphers.emplace(make_pair(_T("rijndael192-160"), unique_ptr<block_cipher>(new rijndael192_160)));
	block_ciphers.emplace(make_pair(_T("rijndael192-192"), unique_ptr<block_cipher>(new rijndael192_192)));
	block_ciphers.emplace(make_pair(_T("rijndael192-224"), unique_ptr<block_cipher>(new rijndael192_224)));
	block_ciphers.emplace(make_pair(_T("rijndael192-256"), unique_ptr<block_cipher>(new rijndael192_256)));

	block_ciphers.emplace(make_pair(_T("twofish128"), unique_ptr<block_cipher>(new twofish128)));
	block_ciphers.emplace(make_pair(_T("twofish192"), unique_ptr<block_cipher>(new twofish192)));
	block_ciphers.emplace(make_pair(_T("twofish256"), unique_ptr<block_cipher>(new twofish256)));

	map<wstring, unique_ptr<crypto_hash>> hashes;
	hashes.emplace(make_pair(_T("sha256"), unique_ptr<crypto_hash>(new sha256)));
	hashes.emplace(make_pair(_T("groestl256"), unique_ptr<crypto_hash>(new groestl256)));
	hashes.emplace(make_pair(_T("blake256"), unique_ptr<crypto_hash>(new blake256)));

	hashes.emplace(make_pair(_T("groestl512"), unique_ptr<crypto_hash>(new groestl512)));
	hashes.emplace(make_pair(_T("sha512"), unique_ptr<crypto_hash>(new sha512)));
	hashes.emplace(make_pair(_T("sha512/256"), unique_ptr<crypto_hash>(new sha512_256)));
	hashes.emplace(make_pair(_T("sha512/224"), unique_ptr<crypto_hash>(new sha512_224)));
	hashes.emplace(make_pair(_T("sha384"), unique_ptr<crypto_hash>(new sha384)));
	hashes.emplace(make_pair(_T("groestl384"), unique_ptr<crypto_hash>(new groestl384)));
	hashes.emplace(make_pair(_T("groestl224"), unique_ptr<crypto_hash>(new groestl224)));

	hashes.emplace(make_pair(_T("skein512/256"), unique_ptr<crypto_hash>(new skein512_256)));
	hashes.emplace(make_pair(_T("skein512/512"), unique_ptr<crypto_hash>(new skein512_512)));
	hashes.emplace(make_pair(_T("blake512"), unique_ptr<crypto_hash>(new blake512)));
	hashes.emplace(make_pair(_T("blake384"), unique_ptr<crypto_hash>(new blake384)));
	hashes.emplace(make_pair(_T("blake224"), unique_ptr<crypto_hash>(new blake224)));
	hashes.emplace(make_pair(_T("skein512/384"), unique_ptr<crypto_hash>(new skein512_384)));
	hashes.emplace(make_pair(_T("skein512/224"), unique_ptr<crypto_hash>(new skein512_224)));

	hashes.emplace(make_pair(_T("skein256/256"), unique_ptr<crypto_hash>(new skein256_256)));
	hashes.emplace(make_pair(_T("skein256/224"), unique_ptr<crypto_hash>(new skein256_224)));
	hashes.emplace(make_pair(_T("skein1024/1024"), unique_ptr<crypto_hash>(new skein1024_1024)));
	hashes.emplace(make_pair(_T("skein1024/512"), unique_ptr<crypto_hash>(new skein1024_512)));
	hashes.emplace(make_pair(_T("skein1024/384"), unique_ptr<crypto_hash>(new skein1024_384)));
	hashes.emplace(make_pair(_T("sha224"), unique_ptr<crypto_hash>(new sha224)));

	hashes.emplace(make_pair(_T("whirlpool"), unique_ptr<crypto_hash>(new whirlpool)));
	hashes.emplace(make_pair(_T("kupyna256"), unique_ptr<crypto_hash>(new kupyna256)));
	hashes.emplace(make_pair(_T("kupyna512"), unique_ptr<crypto_hash>(new kupyna512)));
	hashes.emplace(make_pair(_T("skein512/128"), unique_ptr<crypto_hash>(new skein512_128)));
	hashes.emplace(make_pair(_T("skein512/160"), unique_ptr<crypto_hash>(new skein512_160)));
	hashes.emplace(make_pair(_T("skein256/128"), unique_ptr<crypto_hash>(new skein256_128)));
	hashes.emplace(make_pair(_T("skein256/160"), unique_ptr<crypto_hash>(new skein256_160)));
	hashes.emplace(make_pair(_T("skein1024/256"), unique_ptr<crypto_hash>(new skein1024_256)));

	hashes.emplace(make_pair(_T("sha3_512"), unique_ptr<crypto_hash>(new sha3_512)));
	hashes.emplace(make_pair(_T("sha3_256"), unique_ptr<crypto_hash>(new sha3_256)));
	hashes.emplace(make_pair(_T("sha3_384"), unique_ptr<crypto_hash>(new sha3_384)));
	hashes.emplace(make_pair(_T("sha3_224"), unique_ptr<crypto_hash>(new sha3_224)));

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

	bool checking = wstring(argv[1]) == _T("-c");
	wstring hash = argv[checking ? 2 : 1];

	if (hash == _T("-tv"))
	{
		if (argc != 4)
		{
			cerr << "Syntax: digest -tv <algorithm> <filename>" << endl;
			return 3;
		}
		hash = argv[2];
		auto hashit = block_ciphers.find(hash);
		if (hashit == block_ciphers.end())
		{
			wcerr << _T("Unknown block cipher algorithm: ") << hash << endl;
			return 2;
		}

		test_vector(hashit->second.get(), argv[3]);
		return 0;
	}

	if (hash == _T("bcperftest"))
	{
		long iterations = stol(argv[2]);
		if (iterations < 1)
		{
			cerr << "Syntax: digest bcperftest" << endl;
			return 3;
		}
		block_cipher_perf_test(block_ciphers, iterations);
		return 0;
	}

	if (hash == _T("test"))
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

	if (hash == _T("bctest"))
	{
		long iterations = 0;
		if (argc != 4 || (iterations = stol(argv[2])) < 1)
		{
			cerr << "Syntax: digest bctest <iterations> <filename>" << endl;
			return 3;
		}
		bcperftest(block_ciphers, iterations, argv[3]);
		return 0;
	}

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
			for (int b = 0; b < (hashit->second->hashsize() + 7) / 8; b++)
				printf("%02x", (unsigned char)res[b]);
			wprintf(_T("  %s\n"), argv[i]);
		}
		else
			wcerr << _T("Error for ") << argv[i] << endl;
	}

	return 0;
}

