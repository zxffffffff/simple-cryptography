/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#pragma once
#include "Cryptography.h"

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

class SecurityBuffer
{
private:
    StringBuffer encryptedData;
    StringBuffer iv;
    StringBuffer key;

public:
    SecurityBuffer(const StringBuffer &data)
        : key(Cryptography::AES::GenerateKey(256)), iv(Cryptography::AES::GenerateIV(AES_BLOCK_SIZE))
    {
        encryptedData = Cryptography::AES::Encrypt(key, iv, data);
    }

    size_t Size() const
    {
        return encryptedData.Size();
    }

    bool Empty() const
    {
        return encryptedData.Empty();
    }

    StringBuffer RetrieveData() const
    {
        try
        {
            return Cryptography::AES::Decrypt(key, iv, encryptedData);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Decryption failed: " << e.what() << std::endl;
            return {}; // 或抛出异常，根据需求决定
        }
    }

    // 禁止拷贝构造和拷贝赋值
    SecurityBuffer(const SecurityBuffer &other) = delete;
    SecurityBuffer &operator=(const SecurityBuffer &other) = delete;

    // 移动构造和移动赋值
    SecurityBuffer(SecurityBuffer &&other) noexcept : encryptedData(std::move(other.encryptedData)), iv(std::move(other.iv)), key(std::move(other.key)) {}
    SecurityBuffer &operator=(SecurityBuffer &&other) noexcept
    {
        encryptedData = std::move(other.encryptedData);
        iv = std::move(other.iv);
        key = std::move(other.key);
        return *this;
    }
};
