/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#pragma once
#include "GlobalDef.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

class SecurityData
{
private:
    std::vector<unsigned char> encryptedData;
    std::vector<unsigned char> iv; // 初始化向量
    std::vector<unsigned char> key;

    // 密钥生成
    static std::vector<unsigned char> generateKey(size_t keyLength)
    {
        std::vector<unsigned char> key(keyLength);
        if (RAND_bytes(key.data(), keyLength) != 1)
        {
            throw std::runtime_error("Failed to generate random key.");
        }
        return key;
    }

    // 初始化向量生成
    static std::vector<unsigned char> generateIV(size_t ivLength)
    {
        std::vector<unsigned char> iv(ivLength);
        if (RAND_bytes(iv.data(), ivLength) != 1)
        {
            throw std::runtime_error("Failed to generate random IV.");
        }
        return iv;
    }

    // AES 加密
    std::vector<unsigned char> encrypt(const std::string &data)
    {
        std::vector<unsigned char> plaintext(data.begin(), data.end());
        size_t ciphertextLength = plaintext.size() + AES_BLOCK_SIZE; // 预留空间
        std::vector<unsigned char> ciphertext(ciphertextLength);

        EVP_CIPHER_CTX *ctx;
        if (!(ctx = EVP_CIPHER_CTX_new()))
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
            throw std::runtime_error("EVP_EncryptInit_ex failed");

        int len;
        int ciphertextLen;

        if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()))
            throw std::runtime_error("EVP_EncryptUpdate failed");
        ciphertextLen = len;

        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        ciphertextLen += len;

        EVP_CIPHER_CTX_free(ctx);

        ciphertext.resize(ciphertextLen);
        return ciphertext;
    }

    // AES 解密
    std::string decrypt() const
    {
        if (encryptedData.empty())
        {
            return "";
        }

        std::vector<unsigned char> plaintext(encryptedData.size());
        EVP_CIPHER_CTX *ctx;
        if (!(ctx = EVP_CIPHER_CTX_new()))
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
            throw std::runtime_error("EVP_DecryptInit_ex failed");

        int len;
        int plaintextLen;

        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, encryptedData.data(), encryptedData.size()))
            throw std::runtime_error("EVP_DecryptUpdate failed");
        plaintextLen = len;

        if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
            throw std::runtime_error("EVP_DecryptFinal_ex failed");
        plaintextLen += len;

        EVP_CIPHER_CTX_free(ctx);

        plaintext.resize(plaintextLen);

        return std::string(plaintext.begin(), plaintext.end());
    }

public:
    SecurityData(const std::string &data) : key(generateKey(32)), iv(generateIV(AES_BLOCK_SIZE))
    { // 使用 256 位密钥
        encryptedData = encrypt(data);
    }

    std::string retrieveData() const
    {
        try
        {
            return decrypt();
        }
        catch (const std::exception &e)
        {
            std::cerr << "Decryption failed: " << e.what() << std::endl;
            return ""; // 或抛出异常，根据需求决定
        }
    }

    // 禁止拷贝构造和拷贝赋值
    SecurityData(const SecurityData &other) = delete;
    SecurityData &operator=(const SecurityData &other) = delete;

    // 移动构造和移动赋值
    SecurityData(SecurityData &&other) noexcept : encryptedData(std::move(other.encryptedData)), iv(std::move(other.iv)), key(std::move(other.key)) {}
    SecurityData &operator=(SecurityData &&other) noexcept
    {
        encryptedData = std::move(other.encryptedData);
        iv = std::move(other.iv);
        key = std::move(other.key);
        return *this;
    }
};
