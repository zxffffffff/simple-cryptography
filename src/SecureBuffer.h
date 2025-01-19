/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#pragma once
#include "define.h"
#include "StringBuffer.h"

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

// AES Encrypt
class SIMPLE_CRYPTOGRAPHY_LIB_API SecureBuffer
{
private:
    std::unique_ptr<class SecureBufferPriv> priv;

public:
    SecureBuffer(const StringBuffer &data) noexcept;

    // 禁止拷贝构造和拷贝赋值
    SecureBuffer(const SecureBuffer &other) = delete;
    SecureBuffer &operator=(const SecureBuffer &other) = delete;

    // 移动构造和移动赋值
    SecureBuffer(SecureBuffer &&other) noexcept;
    SecureBuffer &operator=(SecureBuffer &&other) noexcept;

    virtual ~SecureBuffer() noexcept;

    size_t Size() const noexcept;
    bool Empty() const noexcept;
    StringBuffer RetrieveData() const noexcept;
};
