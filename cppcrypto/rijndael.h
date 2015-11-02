/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#ifndef CPPCRYPTO_RIJNDAEL_H
#define CPPCRYPTO_RIJNDAEL_H

#include <stdint.h>
#include "block_cipher.h"
#include "rijndael-impl.h"

namespace cppcrypto
{

	class rijndael128_128 : public block_cipher
	{
	public:
		rijndael128_128();
		~rijndael128_128();

		int blocksize() const { return 128; }
		int keysize() const { return 128; }
		block_cipher* clone() const { return new rijndael128_128; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t* W_;
		detail::rijndael_impl* impl_;
	};

	class rijndael128_160 : public block_cipher
	{
	public:
		rijndael128_160();
		~rijndael128_160();

		int blocksize() const { return 128; }
		int keysize() const { return 160; }
		block_cipher* clone() const { return new rijndael128_160; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t* W_;
		detail::rijndael_impl* impl_;
	};

	class rijndael128_192 : public block_cipher
	{
	public:
		rijndael128_192();
		~rijndael128_192();

		int blocksize() const { return 128; }
		int keysize() const { return 192; }
		block_cipher* clone() const { return new rijndael128_192; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t* W_;
		detail::rijndael_impl* impl_;
	};

	class rijndael128_224 : public block_cipher
	{
	public:
		rijndael128_224();
		~rijndael128_224();

		int blocksize() const { return 128; }
		int keysize() const { return 224; }
		block_cipher* clone() const { return new rijndael128_224; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t* W_;
		detail::rijndael_impl* impl_;
	};

	class rijndael128_256 : public block_cipher
	{
	public:
		rijndael128_256();
		~rijndael128_256();

		int blocksize() const { return 128; }
		int keysize() const { return 256; }
		block_cipher* clone() const { return new rijndael128_256; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t* W_;
		detail::rijndael_impl* impl_;
	};

	namespace detail
	{
		class rijndael256 : public block_cipher
		{
		public:
			rijndael256();
			~rijndael256();

			int blocksize() const { return 256; }

			void encryptBlock(const uint8_t* in, uint8_t* out);
			void decryptBlock(const uint8_t* in, uint8_t* out);

		protected:
			uint32_t* W_;
			detail::rijndael_impl* impl_;
		};
	}

	class rijndael256_128 : public detail::rijndael256
	{
	public:
		rijndael256_128();

		int keysize() const { return 128; }
		block_cipher* clone() const { return new rijndael256_128; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class rijndael256_160 : public detail::rijndael256
	{
	public:
		rijndael256_160();

		int keysize() const { return 160; }
		block_cipher* clone() const { return new rijndael256_160; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class rijndael256_192 : public detail::rijndael256
	{
	public:
		rijndael256_192();

		int keysize() const { return 192; }
		block_cipher* clone() const { return new rijndael256_192; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class rijndael256_224 : public detail::rijndael256
	{
	public:
		rijndael256_224();

		int keysize() const { return 224; }
		block_cipher* clone() const { return new rijndael256_224; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class rijndael256_256 : public detail::rijndael256
	{
	public:
		rijndael256_256();

		int keysize() const { return 256; }
		block_cipher* clone() const { return new rijndael256_256; }

		bool init(const uint8_t* key, block_cipher::direction direction);
	};

	class rijndael192_128 : public block_cipher
	{
	public:
		rijndael192_128();
		~rijndael192_128();

		int blocksize() const { return 192; }
		int keysize() const { return 128; }
		block_cipher* clone() const { return new rijndael192_128; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t* W_;
		detail::rijndael_impl* impl_;
	};

	class rijndael192_160 : public block_cipher
	{
	public:
		rijndael192_160();
		~rijndael192_160();

		int blocksize() const { return 192; }
		int keysize() const { return 160; }
		block_cipher* clone() const { return new rijndael192_160; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t* W_;
		detail::rijndael_impl* impl_;
	};


	class rijndael192_192 : public block_cipher
	{
	public:
		rijndael192_192();
		~rijndael192_192();

		int blocksize() const { return 192; }
		int keysize() const { return 192; }
		block_cipher* clone() const { return new rijndael192_192; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t* W_;
		detail::rijndael_impl* impl_;
	};

	class rijndael192_224 : public block_cipher
	{
	public:
		rijndael192_224();
		~rijndael192_224();

		int blocksize() const { return 192; }
		int keysize() const { return 224; }
		block_cipher* clone() const { return new rijndael192_224; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t* W_;
		detail::rijndael_impl* impl_;
	};

	class rijndael192_256 : public block_cipher
	{
	public:
		rijndael192_256();
		~rijndael192_256();

		int blocksize() const { return 192; }
		int keysize() const { return 256; }
		block_cipher* clone() const { return new rijndael192_256; }

		bool init(const uint8_t* key, block_cipher::direction direction);
		void encryptBlock(const uint8_t* in, uint8_t* out);
		void decryptBlock(const uint8_t* in, uint8_t* out);

	private:
		uint32_t* W_;
		detail::rijndael_impl* impl_;
	};

}

#endif
