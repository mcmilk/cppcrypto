/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_BLAKE2_H
#define CPPCRYPTO_BLAKE2_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <functional>
#include <array>

namespace cppcrypto
{
	class blake2b_512 : public crypto_hash
	{
	public:
		blake2b_512();
		~blake2b_512();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		size_t hashsize() const { return 512; }
		size_t blocksize() const { return 1024; }
		crypto_hash* clone() const { return new blake2b_512; }
		void clear();

	protected:
		void transform(bool padding);

		std::function<void(bool)> transfunc;
		aligned_pod_array<uint64_t, 8, 64> H;
		aligned_pod_array<uint8_t, 128, 64> m;
		size_t pos;
		uint64_t total;
	};

	class blake2s_256 : public crypto_hash
	{
	public:
		blake2s_256();
		~blake2s_256();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		size_t hashsize() const { return 256; }
		size_t blocksize() const { return 512; }
		crypto_hash* clone() const { return new blake2s_256; }
		void clear();

	protected:
		void transform(bool padding);

		std::function<void(bool)> transfunc;
		aligned_pod_array<uint32_t, 8, 64> H;
		aligned_pod_array<uint8_t, 64, 64> m;
		size_t pos;
		uint64_t total;
	};

	class blake2b_256 : public blake2b_512
	{
	public:
		size_t hashsize() const { return 256; }
	};

	class blake2b_224 : public blake2b_512
	{
	public:
		size_t hashsize() const { return 224; }
	};

	class blake2b_384 : public blake2b_512
	{
	public:
		size_t hashsize() const { return 384; }
	};

	class blake2b_128 : public blake2b_512
	{
	public:
		size_t hashsize() const { return 128; }
	};

	class blake2b_160 : public blake2b_512
	{
	public:
		size_t hashsize() const { return 160; }
	};

	class blake2s_224 : public blake2s_256
	{
	public:
		size_t hashsize() const { return 224; }
	};

	class blake2s_160 : public blake2s_256
	{
	public:
		size_t hashsize() const { return 160; }
	};

	class blake2s_128 : public blake2s_256
	{
	public:
		size_t hashsize() const { return 128; }
	};

}

#endif
