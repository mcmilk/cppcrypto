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

		void init() override;
		void update(const uint8_t* data, size_t len) override;
		void final(uint8_t* hash) override;

		size_t hashsize() const override { return 256; }
		size_t blocksize() const override { return 512; }
		groestl256* clone() const override { return new groestl256; }
		void clear() override;

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

		void init() override;
		void update(const uint8_t* data, size_t len) override;
		void final(uint8_t* hash) override;

		size_t hashsize() const override { return 512; }
		size_t blocksize() const override { return 1024; }
		groestl512* clone() const override { return new groestl512; }
		void clear() override;

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
		size_t hashsize() const override { return 384; }
		groestl384* clone() const override { return new groestl384; }
	};

	class groestl224 : public groestl256
	{
	public:
		size_t hashsize() const override { return 224; }
		groestl224* clone() const override { return new groestl224; }
	};

}

#endif
