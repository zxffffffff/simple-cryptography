/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#pragma once
#include "StringBuffer.h"

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

class Cryptography
{
public:
    // 哈希
    class Hash
    {
    public:
        static StringBuffer SHA(const StringBuffer &message, size_t bits = 256);

        // 转十六进制显示
        static std::string ToString(const StringBuffer &message_hash);
    };

    // 对称加密算法 (Symmetric-key algorithm)
    // - 高级加密标准 (Advanced Encryption Standard)
    class AES
    {
    public:
        // 密钥生成
        static StringBuffer GenerateKey(size_t keyLength = 256);

        // 初始化向量生成 (AES_BLOCK_SIZE = 16)
        static StringBuffer GenerateIV(size_t ivLength = 16);

        // 加密/解密
        static StringBuffer Encrypt(const StringBuffer &key, const StringBuffer &iv, const StringBuffer &plaintext);
        static StringBuffer Decrypt(const StringBuffer &key, const StringBuffer &iv, const StringBuffer &encryptedData);
    };

    // 非对称加密算法 (Public-key cryptography)
    // - 公钥密码学标准 PKCS (Public-Key Cryptography Standards)
    class RSA
    {
    public:
        // 密钥生成 (privateKey, publicKey)
        static std::pair<StringBuffer, StringBuffer> GenerateKey(size_t bits = 2048);

        // 加密/解密 (RSA_PKCS1_OAEP_PADDING = 4)
        static StringBuffer Encrypt(const StringBuffer &pem_public_key, const StringBuffer &plainText, int pad_mode = 4);
        static StringBuffer Decrypt(const StringBuffer &pem_private_key, const StringBuffer &cipherText, int pad_mode = 4);

        // 签名/验签
        static StringBuffer Sign(const StringBuffer &pem_private_key, const StringBuffer &message);
        static bool Verify(const StringBuffer &pem_public_key, const StringBuffer &message, const StringBuffer &signature);
    };

    // 椭圆曲线密码学 (Elliptic Curve Cryptography)
    // - 椭圆曲线参数 secp256k1
    class ECC
    {
    public:
        // 密钥生成 (privateKey, publicKey) 长度固定
        static std::pair<StringBuffer, StringBuffer> GenerateKey();

        // 签名/验签 (SHA256)
        static StringBuffer Sign(const StringBuffer &private_key, const StringBuffer &message_hash);
        static bool Verify(const StringBuffer &public_key, const StringBuffer &message_hash, const StringBuffer &signature);
    };

    // 秘密共享算法 (Secret sharing)
    // - Shamir 秘密共享 (Shamir's secret sharing)
    class SSS
    {
    public:
        // 2-of-3 (n=3, k=2)
        static std::vector<StringBuffer> Shares(const StringBuffer &message, int n, int k);
        static StringBuffer Combine(const std::vector<StringBuffer> &shares);
    };
};
