/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#include "Cryptography.h"
#include <oqs/oqs.h>
#include <stdexcept>

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

int bitsFromPublicKey(int length_public_key)
{
    switch (length_public_key)
    {
    case OQS_KEM_kyber_512_length_public_key:
        return 512;
    case OQS_KEM_kyber_768_length_public_key:
        return 768;
    case OQS_KEM_kyber_1024_length_public_key:
        return 1024;

    default:
        throw std::runtime_error("Invalid length_public_key.");
    }
}

int bitsFromSecretKey(int length_secret_key)
{
    switch (length_secret_key)
    {
    case OQS_KEM_kyber_512_length_secret_key:
        return 512;
    case OQS_KEM_kyber_768_length_secret_key:
        return 768;
    case OQS_KEM_kyber_1024_length_secret_key:
        return 1024;

    default:
        throw std::runtime_error("Invalid length_secret_key.");
    }
}

const char *methodFromBits(int bits)
{
    switch (bits)
    {
    case 512:
        return OQS_KEM_alg_kyber_512;
    case 768:
        return OQS_KEM_alg_kyber_768;
    case 1024:
        return OQS_KEM_alg_kyber_1024;

    default:
        throw std::runtime_error("Invalid bits.");
    }
}

std::unique_ptr<OQS_KEM, decltype(&::OQS_KEM_free)> initializeKyber(int bits)
{
    std::unique_ptr<OQS_KEM, decltype(&::OQS_KEM_free)> kem_{nullptr, ::OQS_KEM_free};

    // 支持 512、768、1024
    OQS_KEM *kem = OQS_KEM_new(methodFromBits(bits));
    if (!kem)
        throw std::runtime_error("Failed to initialize Kyber KEM.");

    kem_.reset(kem);
    return kem_;
}

std::pair<StringBuffer, StringBuffer> Cryptography::Kyber::GenerateKey(int bits)
{
    auto kem_ = initializeKyber(bits);

    StringBuffer publicKey(kem_->length_public_key);
    StringBuffer secretKey(kem_->length_secret_key);

    int ret = OQS_KEM_keypair(kem_.get(), publicKey.Data(), secretKey.Data());
    if (ret != OQS_SUCCESS)
        throw std::runtime_error("Key pair generation failed.");

    return {secretKey, publicKey};
}

std::pair<StringBuffer, StringBuffer> Cryptography::Kyber::Encrypt(const StringBuffer &publicKey)
{
    auto kem_ = initializeKyber(bitsFromPublicKey(publicKey.Size()));

    StringBuffer ciphertext(kem_->length_ciphertext);
    StringBuffer sharedSecret(kem_->length_shared_secret);
    int result = OQS_KEM_encaps(kem_.get(), ciphertext.Data(), sharedSecret.Data(), publicKey.Data());
    if (result != OQS_SUCCESS)
        throw std::runtime_error("Failed to OQS_KEM_encaps");

    return {ciphertext, sharedSecret};
}

StringBuffer Cryptography::Kyber::Decrypt(const StringBuffer &secretKey, const StringBuffer &cipherText)
{
    auto kem_ = initializeKyber(bitsFromSecretKey(secretKey.Size()));

    StringBuffer sharedSecret(kem_->length_shared_secret);
    int result = OQS_KEM_decaps(kem_.get(), sharedSecret.Data(), cipherText.Data(), secretKey.Data());
    if (result != OQS_SUCCESS)
        throw std::runtime_error("Failed to OQS_KEM_decaps");

    return sharedSecret;
}
