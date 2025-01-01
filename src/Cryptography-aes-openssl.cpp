/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#include "Cryptography.h"
#include <openssl/aes.h>
#include <openssl/rand.h>

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

StringBuffer Cryptography::AES::GenerateKey(size_t keyLength)
{
    StringBuffer key(keyLength);
    if (RAND_bytes(key.Data(), keyLength) != 1)
    {
        throw std::runtime_error("Failed to generate random key.");
    }
    return key;
}

StringBuffer Cryptography::AES::GenerateIV(size_t ivLength)
{
    static_assert(AES_BLOCK_SIZE == 16);
    StringBuffer iv(ivLength);
    if (RAND_bytes(iv.Data(), ivLength) != 1)
    {
        throw std::runtime_error("Failed to generate random IV.");
    }
    return iv;
}

StringBuffer Cryptography::AES::Encrypt(const StringBuffer &key, const StringBuffer &iv, const StringBuffer &plaintext)
{
    size_t ciphertextLength = plaintext.Size() + AES_BLOCK_SIZE; // 预留空间
    StringBuffer ciphertext(ciphertextLength);

    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.Data(), iv.Data()))
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    int len;
    int ciphertextLen;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.Data(), &len, plaintext.Data(), plaintext.Size()))
        throw std::runtime_error("EVP_EncryptUpdate failed");
    ciphertextLen = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.Data() + len, &len))
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    ciphertextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.Resize(ciphertextLen);
    return ciphertext;
}

StringBuffer Cryptography::AES::Decrypt(const StringBuffer &key, const StringBuffer &iv, const StringBuffer &encryptedData)
{
    if (encryptedData.Empty())
    {
        return {};
    }

    StringBuffer plaintext(encryptedData.Size());
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.Data(), iv.Data()))
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    int len;
    int plaintextLen;

    if (1 != EVP_DecryptUpdate(ctx, plaintext.Data(), &len, encryptedData.Data(), encryptedData.Size()))
        throw std::runtime_error("EVP_DecryptUpdate failed");
    plaintextLen = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.Data() + len, &len))
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    plaintextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext.Resize(plaintextLen);

    return plaintext;
}
