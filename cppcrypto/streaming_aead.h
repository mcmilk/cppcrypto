/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_STREAMING_AEAD_H
#define CPPCRYPTO_STREAMING_AEAD_H

#include "aead.h"
#include "hkdf.h"
#include "sha256.h"
#include <memory>

namespace cppcrypto
{
	/**
	Streaming authenticated encryption with associated data (AEAD).
	
	To start streaming encryption, call init_encryption(), which creates a
	stream header, then call encrypt_segment() for each segment that needs
	to be encrypted. The last call to encrypt_segment must indicate that
	the segment being encrypted is the final segment of the stream.

	Segments can be of any length, but encryption should match decryption.
	E.g. if encryption uses segments of 1 Mb, decryption should also use
	segments of 1 Mb (enlarged by tag_bytes()).

	The encryption key is generated internally from the input key
	material using specified key derivation function and random salt.
	If you already have a key (not a password), you can use 'hkdf'
	as the key derivation function. If you have a password, use password
	based kdf such as argon2 or lyra2.

	The format of the generated stream header is:
	- header size in bytes (1 byte);
	- random salt (size equal to salt_bytes());
	- random nonce prefix (size equal to nonce_prefix_bytes()).

	The format of the stream is:
	- header of size header_bytes()
	- ciphertext 1 with authentication tag 1
	- ciphertext 2 with authentication tag 2
	- ...
	- ciphertext N with authentication tag N

	Each segment is encrypted using encryption key generated as described
	above and nonce of the following format:
	- nonce prefix from the stream header
	- segment counter (4 bytes)
	- final segment flag (1 byte)
	- block counter (4 bytes, only if aead is ctr mode with mac)

	To decrypt the stream, first call init_decryption() with the
	stream header data, then call decrypt_segment for each segment.
	The last call to decrypt_segment must indicate that the segment
	being decrypted is the final segment of the stream.

	Note that the ciphertext for each segment is longer than plaintext
	by tag_bytes().

	The overall stream size is longer than plaintext by header_bytes()
	plus N * tag_bytes(), where N is the number of segments.

	*/
	class streaming_aead
	{
	public:
		enum class segment_type : uint8_t
		{
			non_final = 0,
			final = 1
		};

		streaming_aead(const aead& aead);

		~streaming_aead();

		// Initialize streaming authenticated encryption.
		// Must be done once before encryption or decryption.
		// The key will be derived from the input key material ikm using key derivation function kdf.
		// Header length must be equal to header_bytes().
		void init_encryption(const unsigned char* ikm, size_t ikmlen, unsigned char* header, size_t header_len, const crypto_kdf& kdf = hkdf(sha256()));

		// Initialize streaming authenticated decryption.
		// Must be done once before encryption or decryption.
		// The key will be derived from the input key material ikm using key derivation function kdf.
		// Header length must be equal to header_bytes().
		void init_decryption(const unsigned char* ikm, size_t ikmlen, const unsigned char* header, size_t header_len, const crypto_kdf& kdf = hkdf(sha256()));

		// Encrypt a segment.
		// The size of the result buffer must be equal to plaintext_len plus tag_bytes().
		// type must be set to streaming_aead::segment_type::final for the last segment in the stream.
		void encrypt_segment(segment_type type, const unsigned char* plaintext, size_t plaintext_len, const unsigned char* associated_data, size_t associated_data_len, unsigned char* result, size_t result_buffer_len);

		// Decrypt a segment.
		// The size of the result buffer must be equal to ciphertext_len minus tag_bytes().
		// type must be set to streaming_aead::segment_type::final for the last segment in the stream.
		bool decrypt_segment(segment_type type, const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* associated_data, size_t associated_data_len, unsigned char* result, size_t result_buffer_len);

		// informational getters

		virtual size_t tag_bytes() const;

		virtual size_t header_bytes() const;

		virtual size_t nonce_prefix_bytes() const;

		virtual size_t salt_bytes() const;

	private:
		std::unique_ptr<aead> aead_;
		std::basic_string<unsigned char> iv_;
	};
}
#endif
