#ifndef CPPCRYPTO_CBC_H
#define CPPCRYPTO_CBC_H

#include <stdint.h>
#include "block_cipher.h"
#include <memory>

namespace cppcrypto
{

	class cbc
	{
	public:
		cbc();
		virtual ~cbc();

		void setCipher(const block_cipher& cipher);
		void encryptInit(const uint8_t* key, const uint8_t* iv); // maybe lengths for assert
		void encryptUpdate(const uint8_t* in, size_t len, uint8_t* out, size_t& resultlen);
		void encryptFinal(uint8_t* out, size_t& resultlen);
		void decryptInit(const uint8_t* key, const uint8_t* iv); // maybe lengths for assert
		void decryptUpdate(const uint8_t* in, size_t len, uint8_t* out, size_t& resultlen);
		void decryptFinal(uint8_t* out, size_t& resultlen);

	private:
		cbc(const cbc&);

		uint8_t* block_;
		uint8_t* iv_;
		std::unique_ptr<block_cipher> cipher_;
		size_t pos;
		int nb_;
	};

}

#endif