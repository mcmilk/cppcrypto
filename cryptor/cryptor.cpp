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

//#define CPPCRYPTO_DEBUG

using namespace cppcrypto;

namespace
{
	// Magic file header, just to quickly reject invalid files during decryption
	const unsigned char magic[5] { 0x71, 0x84, 0x68, 0x96, 0x02 };

	// Size of segments for file encryption/decryption using streaming AEAD
	const size_t SegmentSize = 1024 * 1024;
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
	return std::equal(magic, magic + sizeof(magic), other);
}

// Encrypt a file using specified cipher and hash function (for HMAC)
void encrypt_file(streaming_aead* aead, std::wstring filename, std::string& pwd)
{
	file_wrapper file(filename);
	long long file_size = file.file_size();

	// Ask user for password
	while (pwd.empty())
	{
		enable_tty_echo(false);
		std::wcout << _T("Password: ");
		std::getline(std::cin, pwd);
		enable_tty_echo(true);
		std::wcout << std::endl;
	}

	// Initialize streaming AEAD encryption using password based key derivation function Argon2d
	argon2 kdf(argon2::type::argon2d, 4, 4096, 1000);
	std::vector<unsigned char> buffer(aead->header_bytes());
	aead->init_encryption(reinterpret_cast<const unsigned char*>(pwd.data()), pwd.length(), &buffer[0], buffer.size(), kdf);

	// Write magic header and streaming AEAD header to file
	file.write(magic, sizeof(magic)); // FIXME change to std::array
	file.write(buffer.data(), buffer.size());

	// Encrypt a file in blocks of 1 megabyte
	std::vector<unsigned char> ct;
	long long read = 0;
	do
	{
		long long block_size = std::min(static_cast<long long>(SegmentSize), file_size - read);
		buffer.resize(static_cast<size_t>(block_size));
		file.read(&buffer[0], buffer.size());
		read += block_size;
		auto block_type = read >= file_size ? cppcrypto::streaming_aead::segment_type::final : cppcrypto::streaming_aead::segment_type::non_final;
		ct.resize(static_cast<size_t>(block_size) + aead->tag_bytes());
		aead->encrypt_segment(block_type, buffer.data(), buffer.size(), nullptr, 0, &ct[0], ct.size());
		file.write(ct.data(), ct.size());
	} while (read < file_size);

	file.complete();
	std::wcout << filename << ": Encrypted successfully" << std::endl;
}

// Encrypt a file using specified cipher and hash function (for HMAC)
void decrypt_file(streaming_aead* aead, std::wstring filename, std::string& pwd)
{
	file_wrapper file(filename);
	long long file_size = file.file_size();
	long long read = 0;
	unsigned char magic[5];

	if (file_size < static_cast<long long>(sizeof(magic) + aead->header_bytes() + aead->tag_bytes()))
		throw std::runtime_error("Invalid input file");

	// Read magic file header
	file.read(magic, sizeof(magic));
	read += sizeof(magic);

	if (!compare_magic(magic))
		throw std::runtime_error("Unsupported file format");

	// Ask user for a password
	while (pwd.empty())
	{
		enable_tty_echo(false);
		std::cout << "Password: ";
		std::getline(std::cin, pwd);
		enable_tty_echo(true);
		std::cout << std::endl;
	}

	// Read streaming AEAD header from file and init decryption
	std::vector<unsigned char> buffer(aead->header_bytes());
	file.read(&buffer[0], buffer.size());
	argon2 kdf(argon2::type::argon2d, 4, 4096, 1000);
	aead->init_decryption(reinterpret_cast<const unsigned char*>(pwd.data()), pwd.length(), &buffer[0], buffer.size(), kdf);
	read += buffer.size();

	// Decrypt a file in blocks of 1 megabyte
	std::vector<unsigned char> pt;
	do
	{
		long long block_size = std::min(static_cast<long long>(SegmentSize + aead->tag_bytes()), file_size - read);
		buffer.resize(static_cast<size_t>(block_size));
		file.read(&buffer[0], buffer.size());
		read += block_size;
		pt.resize(buffer.size() - aead->tag_bytes());
		auto block_type = read >= file_size ? cppcrypto::streaming_aead::segment_type::final : cppcrypto::streaming_aead::segment_type::non_final;
		if (!aead->decrypt_segment(block_type, buffer.data(), buffer.size(), nullptr, 0, &pt[0], pt.size()))
			throw std::runtime_error("Password incorrect or file is corrupted");
		file.write(pt.data(), pt.size());
	} while (read < file_size);

	file.complete();
	std::wcout << filename << ": Decrypted successfully" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 3 || (std::wstring(argv[1]) != _T("dec") && std::wstring(argv[1]) != _T("enc"))) {
		std::cerr << "Syntax:" << std::endl;
		std::cerr << "Encrypt: cryptor enc <filename> ..." << std::endl;
		std::cerr << "Decrypt: cryptor dec <filename> ..." << std::endl;
		return 1;
	}

	bool decoding = std::wstring(argv[1]) == _T("dec");

	// We'll use Serpent cipher with key size 256 bits, CTR mode, and Groestl-256 hash for HMAC authentication
	streaming_aead aead(aead_etm(ctr(serpent256()), hmac(groestl(256))));
	int error_count = 0;
	std::string pwd;
	for (int n = 2; n < argc; ++n)
	{
		try {
			if (!decoding)
				encrypt_file(&aead, argv[n], pwd);
			else
				decrypt_file(&aead, argv[n], pwd);
		}
		catch (std::exception& ex) {
			std::wcerr << argv[n] << _T(": ");
			std::cerr << ex.what() << std::endl;
			++error_count;
		}
	}
	if (!pwd.empty())
		zero_memory(&pwd[0], pwd.length());

	return error_count;
}

