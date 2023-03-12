#ifndef CPPCRYPTOTEST_RC6_H
#define CPPCRYPTOTEST_RC6_H

void rc6_decrypt(void* rkey, int w, int r, void* ct, void* pt);
void rc6_encrypt(void* rkey, int w, int r, void* pt, void* ct);
int rc6_setup(void* rkey, int w, int r, int b, void* key);

template<int B>
class rc6_16_16 : public cppcrypto::block_cipher
{
public:
    rc6_16_16() {}
    ~rc6_16_16() {}
    size_t blocksize() const override { return B; }
    size_t keysize() const override { return b * 8; }
    rc6_16_16* clone() const override { return new rc6_16_16; }
    void clear() override {};
    bool init(const unsigned char* key, block_cipher::direction direction) override
    {
        return !rc6_setup(rkey, w, r, b, const_cast<unsigned char*>(key));
    }
    void encrypt_block(const unsigned char* in, unsigned char* out) override
    {
        rc6_encrypt(rkey, w, r, const_cast<unsigned char*>(in), out);
    }
    void decrypt_block(const unsigned char* in, unsigned char* out) override
    {
        rc6_decrypt(rkey, w, r, const_cast<unsigned char*>(in), out);
    }

private:

    static const int b = 16; // keysize bytes
    static const int w = B / 4;
    static const int r = 16; // recommended values for 192 - 28, for 256 - 24, for 512 - 28, for 1024 - 32; for 160 - 28, for 224 - 28
    static const int bpw = w / 8;    // bytes per word
    unsigned char rkey[(2 * r + 4) * bpw];

};

#endif

