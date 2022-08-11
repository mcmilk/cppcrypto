/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "portability.h"
#include "alignedarray.h"

namespace cppcrypto
{
	namespace detail
	{
		class poly1305_impl
		{
		public:
			virtual ~poly1305_impl() {}
			virtual void init(const unsigned char* key) = 0;
			virtual void transform(const unsigned char *in, size_t inlen) = 0;
			virtual void finish(const unsigned char *in, size_t remaining, unsigned char *mac) = 0;
			virtual int blockbytes() const = 0;
			virtual void clear() = 0;
		};

		class poly1305_impl_sse2 : public poly1305_impl
		{
		public:
			virtual void init(const unsigned char* key) override;
			virtual void transform(const unsigned char *in, size_t inlen) override;
			virtual void finish(const unsigned char *in, size_t remaining, unsigned char *mac) override;
			virtual void clear() override;
			virtual int blockbytes() const override { return 32; }

		private:
			aligned_pod_array<unsigned char, 320, 32> state_;
		};
	}
}

