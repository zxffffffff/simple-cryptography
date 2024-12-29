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

        // AES 加密
        static StringBuffer Encrypt(const StringBuffer &key, const StringBuffer &iv, const StringBuffer &plaintext);

        // AES 解密
        static StringBuffer Decrypt(const StringBuffer &key, const StringBuffer &iv, const StringBuffer &encryptedData);
    };
};
