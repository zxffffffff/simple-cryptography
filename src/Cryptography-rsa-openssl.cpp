/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#include "Cryptography.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

static std::string getOpenSSLError()
{
    char buffer[256];
    ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
    return std::string(buffer);
}

// 将 EVP_PKEY* 转换为 PEM 格式的字符串
StringBuffer evp_pkey_to_pem(EVP_PKEY *pkey, bool is_private)
{
    if (!pkey)
        throw std::runtime_error("Invalid pkey");

    BIO *mem = BIO_new(BIO_s_mem());
    if (!mem)
        throw std::runtime_error("BIO_new failed");

    if (is_private)
    {
        if (!PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL))
        {
            BIO_free(mem);
            throw std::runtime_error("PEM_write_bio_PrivateKey failed");
        }
    }
    else
    {
        if (!PEM_write_bio_PUBKEY(mem, pkey))
        {
            BIO_free(mem);
            throw std::runtime_error("PEM_write_bio_PUBKEY failed");
        }
    }

    char *pem_data = NULL;
    size_t pem_len = BIO_get_mem_data(mem, &pem_data);

    StringBuffer pem_string(pem_data, pem_len);
    BIO_free(mem);
    return pem_string;
}

// 从 PEM 格式的字符串加载 EVP_PKEY*
std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> pem_to_evp_pkey(const StringBuffer &pem_string, bool is_private)
{
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> pkey_{nullptr, ::EVP_PKEY_free};

    if (pem_string.Empty())
        throw std::runtime_error("Invalid pem_string");

    BIO *mem = BIO_new_mem_buf(pem_string.Data(), (int)pem_string.Size());
    if (!mem)
        throw std::runtime_error("BIO_new_mem_buf failed");

    EVP_PKEY *pkey = NULL;
    if (is_private)
    {
        pkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
    }
    else
    {
        pkey = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    }

    pkey_.reset(pkey);
    BIO_free(mem);
    return pkey_;
}

std::pair<StringBuffer, StringBuffer> Cryptography::RSA::GenerateKey(size_t bits)
{
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> privateKey_{nullptr, ::EVP_PKEY_free};
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> publicKey_{nullptr, ::EVP_PKEY_free};
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize key generation: " + getOpenSSLError());
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set RSA key size: " + getOpenSSLError());
        }

        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Key generation failed: " + getOpenSSLError());
        }

        privateKey_.reset(pkey);
        publicKey_.reset(EVP_PKEY_dup(privateKey_.get()));

        EVP_PKEY_CTX_free(ctx);
    }

    StringBuffer privateKey = evp_pkey_to_pem(privateKey_.get(), true);
    StringBuffer publicKey = evp_pkey_to_pem(publicKey_.get(), false);
    return {privateKey, publicKey};
}

StringBuffer Cryptography::RSA::Encrypt(const StringBuffer &pem_public_key, const StringBuffer &plainText, int pad_mode)
{
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> publicKey_ = pem_to_evp_pkey(pem_public_key, false);

    size_t rsa_block_size = EVP_PKEY_get_size(publicKey_.get()); // 密钥长度（字节）
    size_t padding_overhead = 0;                                 // 填充长度（字节）
    switch (pad_mode)
    {
    case RSA_PKCS1_PADDING:
        padding_overhead = 11;
        break;
    case RSA_NO_PADDING:
        padding_overhead = 0;
        break;
    case RSA_PKCS1_OAEP_PADDING:
        padding_overhead = 2 * EVP_MD_size(EVP_sha1()) + 2; // 42
        break;
    case RSA_X931_PADDING:
        padding_overhead = 1;
        break;
    default:
        throw std::runtime_error("Unknown padding mode: " + std::to_string(pad_mode));
    }
    const size_t max_encrypt_size = rsa_block_size - padding_overhead;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(publicKey_.get(), nullptr);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        throw std::runtime_error("Failed to initialize encryption: " + getOpenSSLError());
    }

    static_assert(RSA_PKCS1_OAEP_PADDING == 4);
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, pad_mode) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set RSA padding: " + getOpenSSLError());
    }

    StringBuffer encryptedText;
    encryptedText.Reserve(plainText.Size() * 2);
    for (size_t offset = 0; offset < plainText.Size(); offset += max_encrypt_size)
    {
        size_t chunk_size = std::min(max_encrypt_size, plainText.Size() - offset);

        size_t encryptedLen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &encryptedLen, plainText.Data() + offset, chunk_size) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate encrypted length: " + getOpenSSLError());
        }

        StringBuffer cipherText(encryptedLen);
        if (EVP_PKEY_encrypt(ctx, cipherText.Data(), &encryptedLen, plainText.Data() + offset, chunk_size) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Encryption failed: " + getOpenSSLError());
        }

        cipherText.Resize(encryptedLen);
        encryptedText.Append(cipherText);
    }
    EVP_PKEY_CTX_free(ctx);
    return encryptedText;
}

StringBuffer Cryptography::RSA::Decrypt(const StringBuffer &pem_private_key, const StringBuffer &cipherText, int pad_mode)
{
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> privateKey_ = pem_to_evp_pkey(pem_private_key, true);

    size_t rsa_block_size = EVP_PKEY_get_size(privateKey_.get()); // 密钥长度（字节）

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privateKey_.get(), nullptr);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        throw std::runtime_error("Failed to initialize decryption: " + getOpenSSLError());
    }

    static_assert(RSA_PKCS1_OAEP_PADDING == 4);
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, pad_mode) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set RSA padding: " + getOpenSSLError());
    }

    StringBuffer decryptedText;
    decryptedText.Reserve(cipherText.Size() * 2);
    for (size_t offset = 0; offset < cipherText.Size(); offset += rsa_block_size)
    {
        size_t chunk_size = std::min(rsa_block_size, cipherText.Size() - offset);

        size_t decryptedLen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &decryptedLen, cipherText.Data() + offset, chunk_size) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate decrypted length: " + getOpenSSLError());
        }

        StringBuffer plainText(decryptedLen);
        if (EVP_PKEY_decrypt(ctx, plainText.Data(), &decryptedLen, cipherText.Data() + offset, chunk_size) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Decryption failed: " + getOpenSSLError());
        }

        plainText.Resize(decryptedLen);
        decryptedText.Append(plainText);
    }
    EVP_PKEY_CTX_free(ctx);
    return decryptedText;
}

StringBuffer Cryptography::RSA::Sign(const StringBuffer &pem_private_key, const StringBuffer &message)
{
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> privateKey_ = pem_to_evp_pkey(pem_private_key, true);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, privateKey_.get()) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestSignUpdate(md_ctx, message.Data(), message.Size()) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("EVP_DigestSignUpdate failed");
    }

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("EVP_DigestSignFinal failed");
    }

    StringBuffer signature(sig_len);
    if (EVP_DigestSignFinal(md_ctx, signature.Data(), &sig_len) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("EVP_DigestSignFinal failed");
    }

    EVP_MD_CTX_free(md_ctx);
    return signature;
}

bool Cryptography::RSA::Verify(const StringBuffer &pem_public_key, const StringBuffer &message, const StringBuffer &signature)
{
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> publicKey_ = pem_to_evp_pkey(pem_public_key, false);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, publicKey_.get()) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("EVP_DigestVerifyInit failed");
    }

    if (EVP_DigestVerifyUpdate(md_ctx, message.Data(), message.Size()) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("EVP_DigestVerifyUpdate failed");
    }

    int ret = EVP_DigestVerifyFinal(md_ctx, signature.Data(), signature.Size());
    EVP_MD_CTX_free(md_ctx);

    return ret == 1; // 返回 1 表示验证成功
}
