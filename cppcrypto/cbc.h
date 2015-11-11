#ifndef CPPCRYPTO_CBC_H
#define CPPCRYPTO_CBC_H

#include <stdint.h>
#include "block_cipher.h"
#include <memory>
#include <vector>
#include <ostream>

namespace cppcrypto
{

	class cbc
	{
	public:
		cbc(const block_cipher& cipher);
		virtual ~cbc();

		void init(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen, block_cipher::direction direction);

		void encrypt_update(const uint8_t* in, size_t len, uint8_t* out, size_t& resultlen);
		void encrypt_final(uint8_t* out, size_t& resultlen);
		void decrypt_update(const uint8_t* in, size_t len, uint8_t* out, size_t& resultlen);
		void decrypt_final(uint8_t* out, size_t& resultlen);

		// These slower variants append the output to the vector, dynamically resizing the vector as needed
		void encrypt_update(const uint8_t* in, size_t len, std::vector<uint8_t>& out);
		void encrypt_final(std::vector<uint8_t>& out);
		void decrypt_update(const uint8_t* in, size_t len, std::vector<uint8_t>& out);
		void decrypt_final(std::vector<uint8_t>& out);

		// These slower variants write the output to std::ostream
		void encrypt_update(const uint8_t* in, size_t len, std::ostream& out);
		void encrypt_final(std::ostream& out);
		void decrypt_update(const uint8_t* in, size_t len, std::ostream& out);
		void decrypt_final(std::ostream& out);

	private:
		cbc(const cbc&);

		uint8_t* block_;
		uint8_t* iv_;
		size_t pos;
		int nb_;
		std::unique_ptr<block_cipher> cipher_;
	};
}

#endif
