/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_GROESTL_H
#define CPPCRYPTO_GROESTL_H

#include "crypto_hash.h"
#include <functional>
#include <memory>
#include "alignedarray.h"
#include "groestl-impl.h"

namespace cppcrypto
{

	class groestl256 : public crypto_hash
	{
	public:
		groestl256();
		~groestl256();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		size_t hashsize() const { return 256; }
		size_t blocksize() const { return 512; }
		crypto_hash* clone() const { return new groestl256; }
		void clear();

	private:
		void transform();
		void outputTransform();

		aligned_pod_array<uint64_t, 8, 32> h;
		aligned_pod_array<uint8_t, 64, 32> m;
		size_t pos;
		uint64_t total;
		aligned_impl_ptr<detail::groestl_impl, 32> impl_;
	};

	class groestl512 : public crypto_hash
	{
	public:
		groestl512();
		~groestl512();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		size_t hashsize() const { return 512; }
		size_t blocksize() const { return 1024; }
		crypto_hash* clone() const { return new groestl512; }
		void clear();

	private:
		void transform();
		void outputTransform();

		aligned_pod_array<uint64_t, 16, 32> h;
		aligned_pod_array<uint8_t, 128, 32> m;
		size_t pos;
		uint64_t total;
		aligned_impl_ptr<detail::groestl_impl, 32> impl_;
	};

	class groestl384 : public groestl512
	{
	public:
		size_t hashsize() const { return 384; }
		crypto_hash* clone() const { return new groestl384; }
	};

	class groestl224 : public groestl256
	{
	public:
		size_t hashsize() const { return 224; }
		crypto_hash* clone() const { return new groestl224; }
	};

}

#endif
