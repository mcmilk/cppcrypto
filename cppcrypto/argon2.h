/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_ARGON2_H
#define CPPCRYPTO_ARGON2_H

#include <stdint.h>
#include "crypto_kdf.h"
#include "pbkdf2.h"

namespace cppcrypto
{

	/*
	Argon2 key derivation function.
	There are two versions of Argon2: argon2i and argon2d.
	Argon2i is the safest against side-channel attacks, while Argon2d provides the highest resistance against GPU cracking attacks.

	Output:
	dk       Derived key, of length dklen bytes.

	Example:

	    unsigned char dk[32];
	    argon2(argon2::type::argon2i, 4, 4096, 1000).derive_key("password", 8, (const unsigned char*)"salt", 4, dk, sizeof(dk));

	*/
	class argon2 : public crypto_kdf
	{
public:
		enum class type
		{
			argon2d = 0,
			argon2i = 1,
			argon2id = 2
		};

		/*
		   Argon2 key derivation function.
		   Parameters:
		   type     Argon2 variant (argon2i, argon2d or argon2id).
		   p        A parallelism degree, which defines the number of parallel threads.
		   m        A memory cost, which defines the memory usage, given in kibibytes.
		   t        A time cost, which defines the amount of computation realized and therefore the execution time, given in number of iterations.
		*/
		argon2(type type, uint32_t parallelism_degree = 4, uint32_t memory_cost = 4096, uint32_t time_cost = 1000);

		// Change parallelism parameter (number of parallel threads).
		void set_parallelism_degree(uint32_t parallelism_degree);

		// Change memory cost parameter (memory usage in kibibytes).
		void set_memory_cost(uint32_t memory_cost);

		// Change time cost parameter (number of iterations).
		void set_time_cost(uint32_t time_cost);

		/*
		   Derive a key from a password.

		   Input:
		   password Passphrase.
		   salt     Salt.
		   dklen    Intended output length of the derived key, given in bytes.

		   Optional input:
		   data     Associated data which will affect the derived key.
		   secret   Secret value which will affect the derived key.

		   Output:
		   dk       Derived key, of length dklen bytes.
		*/
		void derive_key(const char* password, uint32_t pwd_len, const unsigned char* salt, uint32_t salt_len, unsigned char* dk, uint32_t dklen,
			const unsigned char* data = nullptr, uint32_t datalen = 0, const unsigned char* secret = nullptr, uint32_t secretlen = 0) const;

		argon2* clone() const override;

		void clear() override;

protected:
		void derive_key(const unsigned char* ikm, size_t ikm_len, const unsigned char* random_data, size_t random_data_len, unsigned char* dk, size_t dklen) const override;

private:
		type argon2_type;
		uint32_t p;
		uint32_t m;
		uint32_t t;
	};
}

#endif

