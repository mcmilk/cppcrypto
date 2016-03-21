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
	namespace detail
	{
		class blake2b : public crypto_hash
		{
		public:
			blake2b(size_t hashsize);
			~blake2b();

			void init() override;
			void update(const uint8_t* data, size_t len) override;
			void final(uint8_t* hash) override;

			size_t hashsize() const override { return hs; }
			size_t blocksize() const override { return 1024; }
			blake2b* clone() const override { return new blake2b(hs); }
			void clear() override;

		protected:
			void transform(bool padding);

			std::function<void(bool)> transfunc;
			aligned_pod_array<uint64_t, 8, 64> H;
			aligned_pod_array<uint8_t, 128, 64> m;
			size_t pos;
			uint64_t total;
			size_t hs;
		};

		class blake2s : public crypto_hash
		{
		public:
			blake2s(size_t hashsize);
			~blake2s();

			void init() override;
			void update(const uint8_t* data, size_t len) override;
			void final(uint8_t* hash) override;

			size_t hashsize() const override { return hs; }
			size_t blocksize() const override { return 512; }
			blake2s* clone() const override { return new blake2s(hs); }
			void clear() override;

		protected:
			void transform(bool padding);

			std::function<void(bool)> transfunc;
			aligned_pod_array<uint32_t, 8, 64> H;
			aligned_pod_array<uint8_t, 64, 64> m;
			size_t pos;
			uint64_t total;
			size_t hs;
		};
	}

	class blake2b_512 : public detail::blake2b
	{
	public:
		blake2b_512() : blake2b(512) {}
		blake2b_512* clone() const override { return new blake2b_512; }
	};

	class blake2b_256 : public detail::blake2b
	{
	public:
		blake2b_256() : blake2b(256) {}
		blake2b_256* clone() const override { return new blake2b_256; }
	};

	class blake2b_224 : public detail::blake2b
	{
	public:
		blake2b_224() : blake2b(224) {}
		blake2b_224* clone() const override { return new blake2b_224; }
	};

	class blake2b_384 : public detail::blake2b
	{
	public:
		blake2b_384() : blake2b(384) {}
		blake2b_384* clone() const override { return new blake2b_384; }
	};

	class blake2b_128 : public detail::blake2b
	{
	public:
		blake2b_128() : blake2b(128) {}
		blake2b_128* clone() const override { return new blake2b_128; }
	};

	class blake2b_160 : public detail::blake2b
	{
	public:
		blake2b_160() : blake2b(160) {}
		blake2b_160* clone() const override { return new blake2b_160; }
	};

	class blake2s_256 : public detail::blake2s
	{
	public:
		blake2s_256() : blake2s(256) {}
		blake2s_256* clone() const override { return new blake2s_256; }
	};

	class blake2s_224 : public detail::blake2s
	{
	public:
		blake2s_224() : blake2s(224) {}
		blake2s_224* clone() const override { return new blake2s_224; }
	};

	class blake2s_160 : public detail::blake2s
	{
	public:
		blake2s_160() : blake2s(160) {}
		blake2s_160* clone() const override { return new blake2s_160; }
	};

	class blake2s_128 : public detail::blake2s
	{
	public:
		blake2s_128() : blake2s(128) {}
		blake2s_128* clone() const override { return new blake2s_128; }
	};

}

#endif
