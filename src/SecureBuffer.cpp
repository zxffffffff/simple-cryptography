/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#include "SecureBuffer.h"
#include "Cryptography.h"

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

class SecureBufferPriv
{
    friend class SecureBuffer;

public:
    SecureBufferPriv()
        : key(Cryptography::AES::GenerateKey()), iv(Cryptography::AES::GenerateIV())
    {
    }

private:
    StringBuffer encryptedData;
    StringBuffer iv;
    StringBuffer key;
};

SecureBuffer::SecureBuffer(const StringBuffer &data) noexcept
    : priv(std::make_unique<SecureBufferPriv>())
{
    priv->encryptedData = Cryptography::AES::Encrypt(priv->key, priv->iv, data);
}

SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept
{
    priv = std::move(other.priv);
    other.priv = std::make_unique<SecureBufferPriv>();
}

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept
{
    priv = std::move(other.priv);
    other.priv = std::make_unique<SecureBufferPriv>();
    return *this;
}

SecureBuffer::~SecureBuffer() noexcept
{
}

size_t SecureBuffer::Size() const noexcept
{
    return priv->encryptedData.Size();
}

bool SecureBuffer::Empty() const noexcept
{
    return priv->encryptedData.Empty();
}

StringBuffer SecureBuffer::RetrieveData() const noexcept
{
    try
    {
        return Cryptography::AES::Decrypt(priv->key, priv->iv, priv->encryptedData);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Decryption failed: " << e.what() << std::endl;
        return {}; // 或抛出异常，根据需求决定
    }
}
