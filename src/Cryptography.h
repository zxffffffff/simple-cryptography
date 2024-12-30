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
    class AES
    {
    public:
        // 密钥生成
        static StringBuffer GenerateKey(size_t keyLength = 256);

        // 初始化向量生成 (AES_BLOCK_SIZE 16)
        static StringBuffer GenerateIV(size_t ivLength = 16);

        // 加密/解密
        static StringBuffer Encrypt(const StringBuffer &key, const StringBuffer &iv, const StringBuffer &plaintext);
        static StringBuffer Decrypt(const StringBuffer &key, const StringBuffer &iv, const StringBuffer &encryptedData);
    };

    class RSA
    {
    public:
        // 密钥生成 (privateKey, publicKey)
        static std::pair<StringBuffer, StringBuffer> GenerateKey(size_t bits = 2048);

        // 加密/解密 (RSA_PKCS1_OAEP_PADDING 4)
        static StringBuffer Encrypt(const StringBuffer &pem_public_key, const StringBuffer &plainText, int pad_mode = 4);
        static StringBuffer Decrypt(const StringBuffer &pem_private_key, const StringBuffer &cipherText, int pad_mode = 4);

        // 签名/验签
        static StringBuffer Sign(const StringBuffer &pem_private_key, const StringBuffer &text);
        static bool Verify(const StringBuffer &pem_public_key, const StringBuffer &text, const StringBuffer &signature);
    };
};
