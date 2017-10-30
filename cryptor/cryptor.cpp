/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#include "stdafx.h"
#include <sys/stat.h>
#include <string>
#include <algorithm>
#include <sstream>

#ifndef WIN32
#include <termios.h>
#include <unistd.h>
#else
#include "windows.h"
#endif

#include "compatibility.h"
#include "file_wrapper.h"

#define CPPCRYPTO_DEBUG

using namespace std;
using namespace cppcrypto;

namespace
{
	// Magic file header, just to quickly reject invalid files during decryption
	const unsigned char magic[5] { 0x71, 0x84, 0x68, 0x96, 0x01 };
}

// Suppress console echo during password input
void enable_tty_echo(bool on)
{
#ifdef WIN32
	DWORD  mode = 0;
	HANDLE hConIn = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(hConIn, &mode);
	mode = on ? (mode | ENABLE_ECHO_INPUT) : (mode & (~ENABLE_ECHO_INPUT));
	SetConsoleMode(hConIn, mode);
#else
	struct termios settings;
	tcgetattr(STDIN_FILENO, &settings);
	settings.c_lflag = on ? (settings.c_lflag | ECHO) : (settings.c_lflag & (~ECHO));
	tcsetattr(STDIN_FILENO, TCSANOW, &settings);
#endif
}

// Compare magic file header
bool compare_magic(unsigned char* other)
{
	return equal(magic, magic + sizeof(magic), other);
}

// Generate random bytes for salt and initialization vector
bool gen_random_bytes(unsigned char* buffer, size_t buflen)
{
	unsigned char buf[4096];
#ifdef WIN32
	HCRYPTPROV prov = 0;

	if (!CryptAcquireContext(&prov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		throw runtime_error("Cannot acquire crypto context!");

	if (!CryptGenRandom(prov, sizeof(buf), buf))
	{
		CryptReleaseContext(prov, 0);
		throw runtime_error("Cannot generate random bytes!");
	}

	if (!CryptReleaseContext(prov, 0))
		throw runtime_error("Cannot release crypto context!");
#else
	ifstream urandom("/dev/urandom", ios::in|ios::binary);
	urandom.read((ifstream::char_type*)buf, sizeof(buf));
	urandom.close();
#endif

	// Additionally hash random bytes
	skein1024 skein(buflen*8);
	skein.hash_string(buf, sizeof(buf), buffer);
	return true;
}

// Encrypt a file using specified cipher and hash function (for HMAC)
void encrypt_file(cbc* cipher, crypto_hash* hash, wstring filename)
{
	file_wrapper file(filename);
	long long fileSize = file.file_size();

	// Ask user for password
	enable_tty_echo(false);
	string pwd;
	wcout << _T("Password: ");
	getline(cin, pwd);
	enable_tty_echo(true);
	wcout << endl;

	// Generate salt and initialization vector
	unsigned char salt[32];
	unsigned char iv[128];
	gen_random_bytes(salt, sizeof(salt));
	gen_random_bytes(iv, sizeof(iv));

	// Generate encryption and HMAC keys (in one wide array)
	unsigned char pwdhash[160];
	argon2d(pwd.c_str(), static_cast<uint32_t>(pwd.length()), salt, static_cast<uint32_t>(sizeof(salt)), 4, 4096, 1000, pwdhash, static_cast<uint32_t>(sizeof(pwdhash)));
	zero_memory(&pwd[0], pwd.length());

#ifdef CPPCRYPTO_DEBUG
	wcout << _T("Password length is: ") << pwd.length() << _T(" bytes.") << endl;
	wcout << _T("Password hash is: ");
	for (size_t i = 0; i < sizeof(pwdhash); i++)
		wcout << setfill(_T('0')) << setw(2) << hex << (unsigned int)pwdhash[i];
	wcout << endl;
#endif

	// Start calculating HMAC over magic, salt, iv and ciphertext
	hmac hmac(*hash, pwdhash + cipher->keysize() / 8, sizeof(pwdhash) - cipher->keysize() / 8);
	hmac.init();
	hmac.update(magic, sizeof(magic));
	hmac.update(salt, sizeof(salt));
	hmac.update(iv, cipher->ivsize() / 8);

	// Initialize cipher for encryption 
	cipher->init(pwdhash, cipher->keysize() / 8, iv, cipher->ivsize() / 8, block_cipher::encryption);
	zero_memory(pwdhash, sizeof(pwdhash));

	// Write magic header, salt and initialization vector to file
	file.write(magic, sizeof(magic));
	file.write(salt, sizeof(salt));
	file.write(iv, cipher->ivsize() / 8);

	// Encrypt a file in blocks of 10240 bytes
	unsigned char buffer[10240];
	unsigned char ct[10240 + 2048];
	long long read = 0;
	size_t resultLen = 0;
	while (read < fileSize)
	{
		long long blockSize = std::min(static_cast<long long>(sizeof(buffer)), fileSize - read);
		file.read(buffer, static_cast<size_t>(blockSize));
		read += blockSize;
		cipher->encrypt_update(buffer, static_cast<size_t>(blockSize), ct, resultLen);
		hmac.update(ct, resultLen);
		file.write(ct, resultLen);
	}

	// Encrypt the last block
	cipher->encrypt_final(ct, resultLen);
	hmac.update(ct, resultLen);
	file.write(ct, resultLen);

	// Calculate final HMAC and write it to a file
	unsigned char sum[128];
	hmac.final(sum);
	file.write(sum, hmac.hashsize() / 8);

	file.complete();
	wcout << filename << ": Encrypted successfully" << endl;

#ifdef CPPCRYPTO_DEBUG
	wcout << _T("HMAC: ");
	for (size_t i = 0; i < hmac.hashsize() / 8; i++)
		wcout << setfill(_T('0')) << setw(2) << hex << (unsigned int)sum[i];
	wcout << endl;
#endif
}

// Encrypt a file using specified cipher and hash function (for HMAC)
void decrypt_file(cbc* cipher, crypto_hash* hash, wstring filename)
{
	file_wrapper file(filename);
	long long fileSize = file.file_size();
	long long read = 0;
	unsigned char magic[5];
	unsigned char salt[32];
	unsigned char iv[128];

	if (fileSize < static_cast<long long>(sizeof(salt) + sizeof(magic) + cipher->ivsize() / 8 + hash->hashsize() / 8))
		throw runtime_error("Invalid input file");

	// Read magic file header
	file.read(magic, sizeof(magic));
	read += sizeof(magic);

	if (!compare_magic(magic))
		throw runtime_error("Unsupported file format");

	// Read salt and initialization vector
	file.read(salt, sizeof(salt));
	read += sizeof(salt);

	file.read(iv, cipher->ivsize() / 8);
	read += cipher->ivsize() / 8;

	// Ask user for a password
	enable_tty_echo(false);
	string pwd;
	cout << "Password: ";
	getline(cin, pwd);
	enable_tty_echo(true);
	cout << endl;

	// Generate encryption and HMAC keys (in one wide array)
	unsigned char pwdhash[160];
	argon2d(pwd.c_str(), static_cast<uint32_t>(pwd.length()), salt, static_cast<uint32_t>(sizeof(salt)), 4, 4096, 1000, pwdhash, static_cast<uint32_t>(sizeof(pwdhash)));
	zero_memory(&pwd[0], pwd.length());

#ifdef CPPCRYPTO_DEBUG
	cout << "Password length is: " << pwd.length() << " bytes." << endl;
	cout << "Password hash is: ";
	for (size_t i = 0; i < sizeof(pwdhash); i++)
		wcout << setfill(_T('0')) << setw(2) << hex << (unsigned int)pwdhash[i];
	cout << endl;
#endif

	// Start calculating HMAC over magic, salt, iv and ciphertext
	hmac hmac(*hash, pwdhash + cipher->keysize() / 8, sizeof(pwdhash) - cipher->keysize() / 8);
	hmac.init();
	hmac.update(magic, sizeof(magic));
	hmac.update(salt, sizeof(salt));
	hmac.update(iv, cipher->ivsize() / 8);

	// Initialize cipher for decryption 
	cipher->init(pwdhash, cipher->keysize() / 8, iv, cipher->ivsize() / 8, block_cipher::decryption);
	zero_memory(pwdhash, sizeof(pwdhash));

	// Decrypt a file in blocks of 10240 bytes
	unsigned char buffer[10240];
	unsigned char ct[10240 + 2048];
	fileSize -= hmac.hashsize() / 8;
	size_t resultLen = 0;
	while (read < fileSize)
	{
		long long blockSize = std::min(static_cast<long long>(sizeof(buffer)), fileSize - read);
		file.read(buffer, static_cast<size_t>(blockSize));
		read += blockSize;
		hmac.update(buffer, static_cast<size_t>(blockSize));
		cipher->decrypt_update(buffer, static_cast<size_t>(blockSize), ct, resultLen);
		file.write(ct, resultLen);
	}
	cipher->decrypt_final(ct, resultLen);
	file.write(ct, resultLen);

	// Calculate final HMAC and compare it with the one saved in a file
	unsigned char sum[128];
	unsigned char expectedsum[128];
	hmac.final(sum);
	file.read(expectedsum, hmac.hashsize() / 8);

#ifdef CPPCRYPTO_DEBUG
	cout << "HMAC: ";
	for (size_t i = 0; i < hmac.hashsize() / 8; i++)
		wcout << setfill(_T('0')) << setw(2) << hex << (unsigned int)sum[i];
	cout << endl;
#endif

	if (memcmp(sum, expectedsum, hmac.hashsize() / 8))
		wcout << filename << ": Password incorrect or file is corrupted" << endl;
	else {
		file.complete();
		wcout << filename << ": Decrypted successfully" << endl;
	}
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 3 || (wstring(argv[1]) != _T("dec") && wstring(argv[1]) != _T("enc"))) {
		cerr << "Syntax:" << endl;
		cerr << "Encrypt: cryptor enc <filename> ..." << endl;
		cerr << "Decrypt: cryptor dec <filename> ..." << endl;
		return 1;
	}

	bool decoding = wstring(argv[1]) == _T("dec");

	// We'll use Serpent cipher with key size 256 bits, CBC mode, and Groestl-256 hash for HMAC authentication
	serpent256 cipher;
	cbc cbc(cipher);
	groestl hash(256);
	int error_count = 0;
	for (int n = 2; n < argc; ++n)
	{
		try {
			if (!decoding)
				encrypt_file(&cbc, &hash, argv[n]);
			else
				decrypt_file(&cbc, &hash, argv[n]);
		}
		catch (std::exception& ex) {
			wcerr << argv[n] << _T(": ");
			cerr << ex.what() << endl;
			++error_count;
		}
	}

	return error_count;
}

