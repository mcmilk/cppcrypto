/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "stdafx.h"
#include "perftimer.h"
#include <sys/stat.h>
#include <algorithm>
#include <numeric>
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

void perftest(map<wstring, unique_ptr<crypto_hash>>& hashes, long iterations, wstring filename, size_t outputsize)
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
		if (it->second->hashsize() != outputsize)
			continue;
		wcout << setfill(_T(' ')) << setw(14) << it->first << _T(" ");

		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			it->second->hash_string(message, static_cast<size_t>(fileSize), hash);
		}
		double seconds = timer.elapsed();
		wcout << fixed << setprecision(5) << seconds << _T(" (") << setprecision(2) 
			<< (static_cast<double>(fileSize) / 1024.0 / 1024.0 * static_cast<double>(iterations) / seconds) << _T(" MB/s) ");
		for (size_t i = 0; i < (it->second->hashsize() + 7) / 8; i++)
			wcout << setfill(_T('0')) << setw(2) << hex << (unsigned int)hash[i];
		wcout << endl;
	}
}

void perftest(map<wstring, unique_ptr<crypto_hash>>& hashes, long iterations, wstring filename)
{
	array<size_t, 7> output_sizes { 128, 160, 224, 256, 384, 512, 1024 };

	for (size_t outputsize : output_sizes)
	{
		wcout << _T("\nHashes with output size ") << dec << outputsize << _T("bits:") << endl;
		perftest(hashes, iterations, filename, outputsize);
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
	wcout << _T("Cipher\t\tCBC encrypt\t\tCBC decrypt\t\tCTR encrypt\t\tCTR decrypt") << endl;
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
			cbc.encrypt_update((unsigned char*)message, static_cast<size_t>(fileSize), ct, resultlen);
			next += resultlen;
			cbc.encrypt_final(next, resultlen);
		}
		next += resultlen;
		double seconds = timer.elapsed();
		wcout << fixed << setprecision(5) << seconds << _T(" (") << setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s) ");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream ofile(filename + _T(".") + it->first + _T(".cbc.encrypted"), ios::out | ios::binary);
		ofile.write((const char*)ct, next - ct);
#endif

		unsigned char* next2 = pt;
		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			cbc.init(key, it->second->keysize()/8, iv, it->second->blocksize()/8, block_cipher::decryption);
			next2 = pt;
			cbc.decrypt_update((unsigned char*)ct, next-ct, next2, resultlen);
			next2 += resultlen;
			cbc.decrypt_final(next2, resultlen);
		}
		next2 += resultlen;
		seconds = timer.elapsed();
		wcout << fixed << setprecision(5) << seconds << _T(" (") << setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s)");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream odfile(filename + _T(".") + it->first + _T(".cbc.decrypted"), ios::out | ios::binary);
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
			ctr.init(key, it->second->keysize() / 8, iv, it->second->blocksize() / 8);
			ctr.encrypt((unsigned char*)message, static_cast<size_t>(fileSize), ct);
		}
		seconds = timer.elapsed();
		wcout << fixed << setprecision(5) << seconds << _T(" (") << setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s) ");

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
	delete[] pt;
}


void scperftest(map<wstring, unique_ptr<stream_cipher>>& ciphers, long iterations, wstring filename)
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
	unsigned char* ct = new unsigned char[static_cast<size_t>(fileSize + 1024 * 2)];
	unsigned char* pt = new unsigned char[static_cast<size_t>(fileSize + 1024 * 2)];
	unsigned char key[1024];
	unsigned char iv[1024];
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
	wcout << _T("Cipher\t\tEncrypt\t\tDecrypt") << endl;
	for (auto it = ciphers.begin(); it != ciphers.end(); ++it)
	{
		wcout << it->first << _T(" ");
		stream_cipher* sc = it->second->clone();
		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			sc->init(key, it->second->keysize() / 8, iv, it->second->ivsize() / 8);
			sc->encrypt((unsigned char*)message, static_cast<size_t>(fileSize), ct);
		}
		double seconds = timer.elapsed();
		wcout << fixed << setprecision(5) << seconds << _T(" (") << setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s) ");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream octrfile(filename + _T(".") + it->first + _T(".encrypted"), ios::out | ios::binary);
		octrfile.write((const char*)ct, fileSize);
#endif

		timer.reset();
		for (long i = 0; i < iterations; i++)
		{
			sc->init(key, it->second->keysize() / 8, iv, it->second->ivsize() / 8);
			sc->decrypt((unsigned char*)ct, static_cast<size_t>(fileSize), pt);
		}
		seconds = timer.elapsed();
		wcout << fixed << setprecision(5) << seconds << _T(" (") << setprecision(2) << (static_cast<double>(fileSize) / 1024.0 / 1024.0 * iterations / seconds) << _T(" MB/s)");

#ifdef DUMP_TEST_ENCRYPTION
		ofstream odctrfile(filename + _T(".") + it->first + _T(".decrypted"), ios::out | ios::binary);
		odctrfile.write((const char*)pt, fileSize);
#endif

		if (memcmp(pt, message, static_cast<size_t>(fileSize)))
			wcout << _T(" ERROR");

		wcout << endl;
		delete sc;
	}
	delete[] ct;
	delete[] pt;
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


void test_argon(const wstring& name, const wstring& filename)
{
	ifstream file(filename, ios::in | ios::binary);
	string line;
	unsigned char pwd[260], salt[260], secret[260], ad[260], tag[260], pwdhash[260];
	uint32_t pwdlen = 0, saltlen = 0, secretlen = 0, adlen = 0, taglen = 32;
	uint32_t memory = 32, iterations = 3, parallelism = 4;
	uint32_t count = 0, failed = 0, success = 0;
	regex eq(R"((\w+)\s*=\s*(\w*))");
	while (getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		smatch sm;
		if (regex_match(line, sm, eq))
		{
			string second = sm.str(2);
			if (sm.str(1) == "PWD")
			{
				hex2array(second, pwd);
				pwdlen = static_cast<uint32_t>(second.length() / 2);
			}
			if (sm.str(1) == "SALT")
			{
				hex2array(second, salt);
				saltlen = static_cast<uint32_t>(second.length() / 2);
			}
			if (sm.str(1) == "SECRET")
			{
				hex2array(second, secret);
				secretlen = static_cast<uint32_t>(second.length() / 2);
			}
			if (sm.str(1) == "AD")
			{
				hex2array(second, ad);
				adlen = static_cast<uint32_t>(second.length() / 2);
			}
			if (sm.str(1) == "MEMORY")
				memory = stoul(second);
			if (sm.str(1) == "ITERATIONS")
				iterations = stoul(second);
			if (sm.str(1) == "PARALLELISM")
				parallelism = stoul(second);
			if (sm.str(1) == "TAG")
			{
				bool error = false;
				hex2array(second, tag);
				taglen = static_cast<uint32_t>(second.length() / 2);
				if (name == _T("argon2d"))
					argon2d(reinterpret_cast<const char*>(pwd), pwdlen, salt, saltlen, parallelism, memory, iterations, pwdhash, taglen, ad, adlen, secret, secretlen);
				else if (name == _T("argon2i"))
					argon2i(reinterpret_cast<const char*>(pwd), pwdlen, salt, saltlen, parallelism, memory, iterations, pwdhash, taglen, ad, adlen, secret, secretlen);
				else if (name == _T("argon2id"))
					argon2id(reinterpret_cast<const char*>(pwd), pwdlen, salt, saltlen, parallelism, memory, iterations, pwdhash, taglen, ad, adlen, secret, secretlen);
					
				if (memcmp(pwdhash, tag, second.length() / 2))
				{
					wcerr << _T("Error for test ") << count << endl;
#define CPPCRYPTO_DEBUG
#ifdef CPPCRYPTO_DEBUG
					wcerr << _T("password was: ");
					for (size_t i = 0; i < pwdlen; i++)
						wcerr << setfill(_T('0')) << setw(2) << hex << (unsigned int)pwd[i];
					wcerr << _T("\nsalt was: ");
					for (size_t i = 0; i < saltlen; i++)
						wcerr << setfill(_T('0')) << setw(2) << hex << (unsigned int)salt[i];
					wcerr << _T("\nsecret was: ");
					for (size_t i = 0; i < secretlen; i++)
						wcerr << setfill(_T('0')) << setw(2) << hex << (unsigned int)secret[i];
					wcerr << _T("\nad was: ");
					for (size_t i = 0; i < adlen; i++)
						wcerr << setfill(_T('0')) << setw(2) << hex << (unsigned int)ad[i];
					wcerr << endl << "memory: " << memory << ", iterations: " << iterations << ", parallelism: " << parallelism;
					wcerr << "\nexpected is: ";
					for (size_t i = 0; i < taglen; i++)
						wcerr << setfill(_T('0')) << setw(2) << hex << (unsigned int)tag[i];
					wcerr << "\nactual is: ";
					for (size_t i = 0; i < taglen; i++)
						wcerr << setfill(_T('0')) << setw(2) << hex << (unsigned int)pwdhash[i];
					wcerr << endl;
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
	wcout << name << _T(": ");
	if (success)
		wcout << (success) << _T("/") << count << _T(" OK");
	if (failed && success)
		wcout << _T(", ");
	if (failed)
		wcout << failed << _T("/") << count << _T(" FAILED");
	if (!success && !failed)
		wcout << _T("No tests found");
	wcout << endl;
}


void test_vector(const wstring& name, block_cipher* bc, const wstring& filename)
{
	ifstream file(filename, ios::in | ios::binary);
	string line;
	unsigned char key[260], pt[260], ct[260], res[260], tweak[260];
	uint32_t count = 0, failed = 0, success = 0, repeat = 1;
	bool tweakable = false;
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
				bc->init(key, bc->encryption);

				if (tweakable)
				{
					tweakable_block_cipher* tc = dynamic_cast<tweakable_block_cipher*>(bc);
					if (tc)
						tc->set_tweak(tweak);
				}

				bc->encrypt_block(pt, res);
				for (unsigned int i = 1; i < repeat; i++)
					bc->encrypt_block(res, res);
				if (memcmp(ct, res, second.length() / 2))
				{
					cerr << "Error for test " << count << " (encryption)" << endl;
#define CPPCRYPTO_DEBUG
#ifdef CPPCRYPTO_DEBUG
					wprintf(_T("key was: "));
					for (size_t i = 0; i < bc->keysize() / 8; i++)
						wprintf(_T("%02x"), (unsigned char)key[i]);
					wprintf(_T("\nPT was: "));
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						wprintf(_T("%02x"), (unsigned char)pt[i]);
					wprintf(_T("\nCT is: "));
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						wprintf(_T("%02x"), (unsigned char)res[i]);
					wprintf(_T("\nexpected is: "));
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						wprintf(_T("%02x"), (unsigned char)ct[i]);
					wprintf(_T("\n"));
#endif
					error = true;
				}
				bc->init(key, bc->decryption);

				if (tweakable)
				{
					tweakable_block_cipher* tc = dynamic_cast<tweakable_block_cipher*>(bc);
					if (tc)
						tc->set_tweak(tweak);
					tweakable = false;
				}
				for (unsigned int i = 1; i < repeat; i++)
					bc->decrypt_block(ct, ct);
				bc->decrypt_block(ct, res);
				if (memcmp(pt, res, second.length() / 2))
				{
					cerr << "Error for test " << count << " (decryption)" << endl;
#ifdef CPPCRYPTO_DEBUG
					wprintf(_T("key was: "));
					for (size_t i = 0; i < bc->keysize() / 8; i++)
						wprintf(_T("%02x"), (unsigned char)key[i]);
					wprintf(_T("\nCT was: "));
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						wprintf(_T("%02x"), (unsigned char)ct[i]);
					wprintf(_T("\nPT is: "));
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						wprintf(_T("%02x"), (unsigned char)res[i]);
					wprintf(_T("\nexpected is: "));
					for (size_t i = 0; i < bc->blocksize() / 8; i++)
						wprintf(_T("%02x"), (unsigned char)pt[i]);
					wprintf(_T("\n"));
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
	wcout << name << _T(": ");
	if (success)
		wcout << (success) << _T("/") << count << _T(" OK");
	if (failed && success)
		wcout << _T(", ");
	if (failed)
		wcout << failed << _T("/") << count << _T(" FAILED");
	if (!success && !failed)
		wcout << _T("No tests found");
	wcout << endl;
}

void test_vector(const wstring& name, crypto_hash* ch, const wstring& filename)
{
	ifstream file(filename, ios::in | ios::binary);
	string line;
	unsigned char md[1024], res[4096];
	vector<unsigned char> msg;
	uint32_t count = 0, failed = 0, success = 0;
	regex eq(R"((\w+)\s*=\s*(\w*))");
	while (getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		smatch sm;
		if (regex_match(line, sm, eq))
		{
			string second = sm.str(2);
			if (sm.str(1) == "Msg")
			{
				msg.resize(second.size()+2);
				if (!msg.empty())
					hex2array(second, &msg[0]);
			}
			if (sm.str(1) == "MD")
			{
				hex2array(second, md);
				if (msg.size() <= 2)
					ch->hash_string("", res);
				else
					ch->hash_string(&msg[0], msg.size()/2-1, res);
				if (memcmp(md, res, second.length() / 2))
				{
					cerr << "Error for test " << count << endl;
#define CPPCRYPTO_DEBUG
#ifdef CPPCRYPTO_DEBUG
					wprintf(_T("Message was: "));
					for (size_t i = 0; i < msg.size()/2-1; i++)
						wprintf(_T("%02x"), (unsigned char)msg[i]);
					wprintf(_T("\nHash was: "));
					for (size_t i = 0; i < ch->hashsize() / 8; i++)
						wprintf(_T("%02x"), (unsigned char)res[i]);
					wprintf(_T("\nexpected is: "));
					for (size_t i = 0; i < second.length() / 2; i++)
						wprintf(_T("%02x"), (unsigned char)md[i]);
					wprintf(_T("\n"));
#endif
					failed++;
				}
				else success++;
				count++;
			}

		}
	}
	wcout << name << _T(": ");
	if (success)
		wcout << (success) << _T("/") << count << _T(" OK");
	if (failed && success)
		wcout << _T(", ");
	if (failed)
		wcout << failed << _T("/") << count << _T(" FAILED");
	if (!success && !failed)
		wcout << _T("No tests found");
	wcout << endl;
}

void test_vector(const wstring& name, stream_cipher* ch, const wstring& filename)
{
	ifstream file(filename, ios::in | ios::binary);
	string line;
	unsigned char key[260], iv[260], xord[260];
	size_t keylen = 0, ivlen = 0, ptlen = 0;
	vector<unsigned char> pt;
	vector<unsigned char> res;
	vector<unsigned char> ct;
	uint32_t count = 0, failed = 0, success = 0;
	regex eq(R"((\w+)\s*=\s*(\w*))");
	while (getline(file, line))
	{
		line.erase(line.find_last_not_of("\r\n \t") + 1);
		smatch sm;
		if (regex_match(line, sm, eq))
		{
			string second = sm.str(2);
			if (sm.str(1) == "PT")
			{
				pt.resize(second.size());
				res.resize(second.size());
				if (!pt.empty())
					hex2array(second, &pt[0]);
				ptlen = second.size() / 2;
			}
			if (sm.str(1) == "PTZERO")
			{
				long size = stol(second);
				pt.resize(size);
				res.resize(size);
				memset(&pt[0], 0, size);
				ptlen = size;
			}
			if (sm.str(1) == "KEY")
			{
				hex2array(second, key);
				keylen = second.size()/2;
			}
			if (sm.str(1) == "IV")
			{
				hex2array(second, iv);
				ivlen = second.size() / 2;
			}
			if (sm.str(1) == "CT" || sm.str(1) == "XOR")
			{
				bool isxor = sm.str(1) == "XOR";
				bool error = false;
				ct.resize(second.size());
				if (!ct.empty())
					hex2array(second, &ct[0]);
				ch->init(key, keylen, iv, ivlen);
				if (isxor)
				{
					memset(xord, 0, sizeof(xord));
					for (size_t b = 0; b < ptlen; b+=64)
					{
						ch->encrypt(&pt[b], 64, &res[b]);
						for (int i = 0; i < 64; i++)
							xord[i] ^= res[b+i];
					}
					if (memcmp(&ct[0], &xord[0], 64))
					{
						cerr << "Error for test " << count << " (encryption)" << endl;
#define CPPCRYPTO_DEBUG
#ifdef CPPCRYPTO_DEBUG
						wprintf(_T("key was: "));
						for (size_t i = 0; i < keylen; i++)
							wprintf(_T("%02x"), (unsigned char)key[i]);
						wprintf(_T("\nIV was: "));
						for (size_t i = 0; i < ivlen; i++)
							wprintf(_T("%02x"), (unsigned char)iv[i]);
						wprintf(_T("\nPT was: "));
						for (size_t i = 0; i < ptlen; i++)
							wprintf(_T("%02x"), (unsigned char)pt[i]);
						wprintf(_T("\nXOR is: "));
						for (size_t i = 0; i < 64; i++)
							wprintf(_T("%02x"), (unsigned char)xord[i]);
						wprintf(_T("\nexpected is: "));
						for (size_t i = 0; i < second.size() / 2; i++)
							wprintf(_T("%02x"), (unsigned char)ct[i]);
						wprintf(_T("\n"));
#endif
						error = true;
					}
				}
				else
				{
					ch->encrypt(&pt[0], ptlen, &res[0]);
					if (memcmp(&ct[0], &res[0], ptlen))
					{
						cerr << "Error for test " << count << " (encryption)" << endl;
#define CPPCRYPTO_DEBUG
#ifdef CPPCRYPTO_DEBUG
						wprintf(_T("key was: "));
						for (size_t i = 0; i < keylen; i++)
							wprintf(_T("%02x"), (unsigned char)key[i]);
						wprintf(_T("\nIV was: "));
						for (size_t i = 0; i < ivlen; i++)
							wprintf(_T("%02x"), (unsigned char)iv[i]);
						wprintf(_T("\nPT was: "));
						for (size_t i = 0; i < ptlen; i++)
							wprintf(_T("%02x"), (unsigned char)pt[i]);
						wprintf(_T("\nCT is: "));
						for (size_t i = 0; i < ptlen; i++)
							wprintf(_T("%02x"), (unsigned char)res[i]);
						wprintf(_T("\nexpected is: "));
						for (size_t i = 0; i < second.size() / 2; i++)
							wprintf(_T("%02x"), (unsigned char)ct[i]);
						wprintf(_T("\n"));
#endif
						error = true;
					}
				}
				ch->init(key, keylen, iv, ivlen);
				if (isxor)
				{
					vector<unsigned char> res2(res);
					ch->decrypt(&res2[0], ptlen, &res[0]);
				}
				else
					ch->decrypt(&ct[0], second.size()/2, &res[0]);
				if (memcmp(&pt[0], &res[0], ptlen))
				{
					cerr << "Error for test " << count << " (decryption)" << endl;
#ifdef CPPCRYPTO_DEBUG
					wprintf(_T("key was: "));
					for (size_t i = 0; i < keylen; i++)
						wprintf(_T("%02x"), (unsigned char)key[i]);
					wprintf(_T("\nIV was: "));
					for (size_t i = 0; i < ivlen; i++)
						wprintf(_T("%02x"), (unsigned char)key[i]);
					wprintf(_T("\nCT was: "));
					for (size_t i = 0; i < second.size()/2; i++)
						wprintf(_T("%02x"), (unsigned char)ct[i]);
					wprintf(_T("\nPT is: "));
					for (size_t i = 0; i < ptlen; i++)
						wprintf(_T("%02x"), (unsigned char)res[i]);
					wprintf(_T("\nexpected is: "));
					for (size_t i = 0; i < ptlen; i++)
						wprintf(_T("%02x"), (unsigned char)pt[i]);
					wprintf(_T("\n"));
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
	wcout << name << _T(": ");
	if (success)
		wcout << (success) << _T("/") << count << _T(" OK");
	if (failed && success)
		wcout << _T(", ");
	if (failed)
		wcout << failed << _T("/") << count << _T(" FAILED");
	if (!success && !failed)
		wcout << _T("No tests found");
	wcout << endl;
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

	block_ciphers.emplace(make_pair(_T("serpent256"), unique_ptr<block_cipher>(new serpent256)));
	block_ciphers.emplace(make_pair(_T("serpent128"), unique_ptr<block_cipher>(new serpent128)));
	block_ciphers.emplace(make_pair(_T("serpent192"), unique_ptr<block_cipher>(new serpent192)));

	block_ciphers.emplace(make_pair(_T("cast6_256"), unique_ptr<block_cipher>(new cast6_256)));
	block_ciphers.emplace(make_pair(_T("cast6_224"), unique_ptr<block_cipher>(new cast6_224)));
	block_ciphers.emplace(make_pair(_T("cast6_192"), unique_ptr<block_cipher>(new cast6_192)));
	block_ciphers.emplace(make_pair(_T("cast6_160"), unique_ptr<block_cipher>(new cast6_160)));
	block_ciphers.emplace(make_pair(_T("cast6_128"), unique_ptr<block_cipher>(new cast6_128)));

	block_ciphers.emplace(make_pair(_T("rijndael160-128"), unique_ptr<block_cipher>(new rijndael160_128)));
	block_ciphers.emplace(make_pair(_T("rijndael160-160"), unique_ptr<block_cipher>(new rijndael160_160)));
	block_ciphers.emplace(make_pair(_T("rijndael160-192"), unique_ptr<block_cipher>(new rijndael160_192)));
	block_ciphers.emplace(make_pair(_T("rijndael160-224"), unique_ptr<block_cipher>(new rijndael160_224)));
	block_ciphers.emplace(make_pair(_T("rijndael160-256"), unique_ptr<block_cipher>(new rijndael160_256)));
	block_ciphers.emplace(make_pair(_T("rijndael224-128"), unique_ptr<block_cipher>(new rijndael224_128)));
	block_ciphers.emplace(make_pair(_T("rijndael224-160"), unique_ptr<block_cipher>(new rijndael224_160)));
	block_ciphers.emplace(make_pair(_T("rijndael224-192"), unique_ptr<block_cipher>(new rijndael224_192)));
	block_ciphers.emplace(make_pair(_T("rijndael224-224"), unique_ptr<block_cipher>(new rijndael224_224)));
	block_ciphers.emplace(make_pair(_T("rijndael224-256"), unique_ptr<block_cipher>(new rijndael224_256)));

	block_ciphers.emplace(make_pair(_T("camellia128"), unique_ptr<block_cipher>(new camellia128)));
	block_ciphers.emplace(make_pair(_T("camellia256"), unique_ptr<block_cipher>(new camellia256)));
	block_ciphers.emplace(make_pair(_T("camellia192"), unique_ptr<block_cipher>(new camellia192)));
	block_ciphers.emplace(make_pair(_T("kalyna512-512"), unique_ptr<block_cipher>(new kalyna512_512)));
	block_ciphers.emplace(make_pair(_T("kalyna256-512"), unique_ptr<block_cipher>(new kalyna256_512)));
	block_ciphers.emplace(make_pair(_T("kalyna256-256"), unique_ptr<block_cipher>(new kalyna256_256)));
	block_ciphers.emplace(make_pair(_T("kalyna128-256"), unique_ptr<block_cipher>(new kalyna128_256)));
	block_ciphers.emplace(make_pair(_T("kalyna128-128"), unique_ptr<block_cipher>(new kalyna128_128)));

	block_ciphers.emplace(make_pair(_T("aria128"), unique_ptr<block_cipher>(new aria128)));
	block_ciphers.emplace(make_pair(_T("aria256"), unique_ptr<block_cipher>(new aria256)));
	block_ciphers.emplace(make_pair(_T("aria192"), unique_ptr<block_cipher>(new aria192)));

	block_ciphers.emplace(make_pair(_T("kuznyechik"), unique_ptr<block_cipher>(new kuznyechik)));
	block_ciphers.emplace(make_pair(_T("sm4"), unique_ptr<block_cipher>(new sm4)));
	block_ciphers.emplace(make_pair(_T("mars448"), unique_ptr<block_cipher>(new mars448)));
	block_ciphers.emplace(make_pair(_T("mars192"), unique_ptr<block_cipher>(new mars192)));
	block_ciphers.emplace(make_pair(_T("mars256"), unique_ptr<block_cipher>(new mars256)));
	block_ciphers.emplace(make_pair(_T("mars320"), unique_ptr<block_cipher>(new mars320)));
	block_ciphers.emplace(make_pair(_T("mars128"), unique_ptr<block_cipher>(new mars128)));
	block_ciphers.emplace(make_pair(_T("mars160"), unique_ptr<block_cipher>(new mars160)));
	block_ciphers.emplace(make_pair(_T("mars224"), unique_ptr<block_cipher>(new mars224)));
	block_ciphers.emplace(make_pair(_T("mars288"), unique_ptr<block_cipher>(new mars288)));
	block_ciphers.emplace(make_pair(_T("mars352"), unique_ptr<block_cipher>(new mars352)));
	block_ciphers.emplace(make_pair(_T("mars384"), unique_ptr<block_cipher>(new mars384)));
	block_ciphers.emplace(make_pair(_T("mars416"), unique_ptr<block_cipher>(new mars416)));

	block_ciphers.emplace(make_pair(_T("threefish512_512"), unique_ptr<block_cipher>(new threefish512_512)));
	block_ciphers.emplace(make_pair(_T("threefish1024_1024"), unique_ptr<block_cipher>(new threefish1024_1024)));
	block_ciphers.emplace(make_pair(_T("threefish256_256"), unique_ptr<block_cipher>(new threefish256_256)));

	block_ciphers.emplace(make_pair(_T("simon128_128"), unique_ptr<block_cipher>(new simon128_128)));
	block_ciphers.emplace(make_pair(_T("simon128_192"), unique_ptr<block_cipher>(new simon128_192)));
	block_ciphers.emplace(make_pair(_T("simon128_256"), unique_ptr<block_cipher>(new simon128_256)));

	block_ciphers.emplace(make_pair(_T("speck128_128"), unique_ptr<block_cipher>(new speck128_128)));
	block_ciphers.emplace(make_pair(_T("speck128_192"), unique_ptr<block_cipher>(new speck128_192)));
	block_ciphers.emplace(make_pair(_T("speck128_256"), unique_ptr<block_cipher>(new speck128_256)));

	map<wstring, unique_ptr<stream_cipher>> stream_ciphers;

	stream_ciphers.emplace(make_pair(_T("salsa20_256"), unique_ptr<stream_cipher>(new salsa20_256)));
	stream_ciphers.emplace(make_pair(_T("salsa20_128"), unique_ptr<stream_cipher>(new salsa20_128)));
	stream_ciphers.emplace(make_pair(_T("hc256"), unique_ptr<stream_cipher>(new hc256)));
	stream_ciphers.emplace(make_pair(_T("xsalsa20_256"), unique_ptr<stream_cipher>(new xsalsa20_256)));
	stream_ciphers.emplace(make_pair(_T("xsalsa20_128"), unique_ptr<stream_cipher>(new xsalsa20_128)));
	stream_ciphers.emplace(make_pair(_T("hc128"), unique_ptr<stream_cipher>(new hc128)));
	stream_ciphers.emplace(make_pair(_T("salsa20_12_256"), unique_ptr<stream_cipher>(new salsa20_12_256)));
	stream_ciphers.emplace(make_pair(_T("salsa20_12_128"), unique_ptr<stream_cipher>(new salsa20_12_128)));
	stream_ciphers.emplace(make_pair(_T("xsalsa20_12_256"), unique_ptr<stream_cipher>(new xsalsa20_12_256)));
	stream_ciphers.emplace(make_pair(_T("xsalsa20_12_128"), unique_ptr<stream_cipher>(new xsalsa20_12_128)));
	stream_ciphers.emplace(make_pair(_T("chacha20_256"), unique_ptr<stream_cipher>(new chacha20_256)));
	stream_ciphers.emplace(make_pair(_T("chacha20_128"), unique_ptr<stream_cipher>(new chacha20_128)));
	stream_ciphers.emplace(make_pair(_T("xchacha20_256"), unique_ptr<stream_cipher>(new xchacha20_256)));
	stream_ciphers.emplace(make_pair(_T("xchacha20_128"), unique_ptr<stream_cipher>(new xchacha20_128)));
	stream_ciphers.emplace(make_pair(_T("chacha12_256"), unique_ptr<stream_cipher>(new chacha12_256)));
	stream_ciphers.emplace(make_pair(_T("chacha12_128"), unique_ptr<stream_cipher>(new chacha12_128)));
	stream_ciphers.emplace(make_pair(_T("xchacha12_256"), unique_ptr<stream_cipher>(new xchacha12_256)));
	stream_ciphers.emplace(make_pair(_T("xchacha12_128"), unique_ptr<stream_cipher>(new xchacha12_128)));

	map<wstring, unique_ptr<crypto_hash>> hashes;
	hashes.emplace(make_pair(_T("sha256"), unique_ptr<crypto_hash>(new sha256)));
	hashes.emplace(make_pair(_T("groestl/256"), unique_ptr<crypto_hash>(new groestl(256))));
	hashes.emplace(make_pair(_T("blake/256"), unique_ptr<crypto_hash>(new blake(256))));

	hashes.emplace(make_pair(_T("groestl/512"), unique_ptr<crypto_hash>(new groestl(512))));
	hashes.emplace(make_pair(_T("sha512"), unique_ptr<crypto_hash>(new sha512)));
	hashes.emplace(make_pair(_T("sha512/256"), unique_ptr<crypto_hash>(new sha512(256))));
	hashes.emplace(make_pair(_T("sha512/224"), unique_ptr<crypto_hash>(new sha512(224))));
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

	// additional variants for test vector testing
	map<wstring, unique_ptr<crypto_hash>> test_hashes;
	test_hashes.emplace(make_pair(_T("skein256/2056"), unique_ptr<crypto_hash>(new skein256(2056))));
	test_hashes.emplace(make_pair(_T("skein512/2056"), unique_ptr<crypto_hash>(new skein512(2056))));
	test_hashes.emplace(make_pair(_T("skein1024/2056"), unique_ptr<crypto_hash>(new skein1024(2056))));
	test_hashes.emplace(make_pair(_T("shake256/4096"), unique_ptr<crypto_hash>(new shake256(4096))));
	test_hashes.emplace(make_pair(_T("cshake256/512"), unique_ptr<crypto_hash>(new shake256(512, "", "Email Signature"))));
	test_hashes.emplace(make_pair(_T("shake128/1120"), unique_ptr<crypto_hash>(new shake128(1120))));
	unsigned char blakesalt[32];
	iota(blakesalt, blakesalt + sizeof(blakesalt), 0);
	test_hashes.emplace(make_pair(_T("blake/256salt"), unique_ptr<crypto_hash>(new blake(256, blakesalt, 16))));
	blake temp12(384, blakesalt, 32);
	test_hashes.emplace(make_pair(_T("blake/384salt"), unique_ptr<crypto_hash>(temp12.clone())));


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
		if (hash == _T("argon2i") || hash == _T("argon2d") || hash == _T("argon2id"))
		{
			test_argon(hash, argv[3]);
			return 0;
		}
		else if (hashit == block_ciphers.end())
		{
			// maybe it's hash
			auto hashit2 = hashes.find(hash);
			if (hashit2 == hashes.end())
				hashit2 = test_hashes.find(hash);
			if (hashit2 == hashes.end() || hashit2 == test_hashes.end())
			{
				// maybe it's a stream cipher
				auto hashit3 = stream_ciphers.find(hash);
				if (hashit3 == stream_ciphers.end())
				{
					wcerr << _T("Unknown algorithm: ") << hash << endl;
					return 2;
				}
				test_vector(hash, hashit3->second.get(), argv[3]);
				return 0;
			}
			test_vector(hash, hashit2->second.get(), argv[3]);
			return 0;
		}

		test_vector(hash, hashit->second.get(), argv[3]);
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

	if (hash == _T("sctest"))
	{
		long iterations = 0;
		if (argc != 4 || (iterations = stol(argv[2])) < 1)
		{
			cerr << "Syntax: digest sctest <iterations> <filename>" << endl;
			return 3;
		}
		scperftest(stream_ciphers, iterations, argv[3]);
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
			for (size_t b = 0; b < (hashit->second->hashsize() + 7) / 8; b++)
				printf("%02x", (unsigned char)res[b]);
			wprintf(_T("  %s\n"), argv[i]);
		}
		else
			wcerr << _T("Error for ") << argv[i] << endl;
	}

	return 0;
}

