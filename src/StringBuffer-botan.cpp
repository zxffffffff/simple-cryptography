/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#include "StringBuffer.h"
#include <botan/secmem.h>

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

class StringBufferPriv
{
    friend class StringBuffer;

private:
    // std::vector<uint8_t> vec_buf;
    Botan::secure_vector<uint8_t> vec_buf;

public:
    ~StringBufferPriv()
    {
        if (!vec_buf.empty())
            memset(vec_buf.data(), 0, vec_buf.size());
    }
};

StringBuffer::StringBuffer() noexcept
    : priv(std::make_unique<StringBufferPriv>())
{
}

StringBuffer::StringBuffer(const uint8_t *buf, size_t len) noexcept
    : priv(std::make_unique<StringBufferPriv>())
{
    priv->vec_buf.resize(len);
    memmove(priv->vec_buf.data(), buf, len);
}

StringBuffer::StringBuffer(const char *buf, size_t len) noexcept
    : priv(std::make_unique<StringBufferPriv>())
{
    priv->vec_buf.resize(len);
    memmove(priv->vec_buf.data(), buf, len);
}

StringBuffer::StringBuffer(size_t len, uint8_t val) noexcept
    : priv(std::make_unique<StringBufferPriv>())
{
    priv->vec_buf.resize(len, val);
}

StringBuffer::StringBuffer(const StringBuffer &other) noexcept
    : priv(std::make_unique<StringBufferPriv>())
{
    *priv = *other.priv;
}

StringBuffer &StringBuffer::operator=(const StringBuffer &other) noexcept
{
    *priv = *other.priv;
    return *this;
}

StringBuffer::StringBuffer(StringBuffer &&other) noexcept
{
    priv = std::move(other.priv);
    other.priv = std::make_unique<StringBufferPriv>();
}

StringBuffer &StringBuffer::operator=(StringBuffer &&other) noexcept
{
    priv = std::move(other.priv);
    other.priv = std::make_unique<StringBufferPriv>();
    return *this;
}

StringBuffer::~StringBuffer() noexcept
{
}

const uint8_t *StringBuffer::Data() const noexcept
{
    return priv->vec_buf.data();
}

uint8_t *StringBuffer::Data() noexcept
{
    return priv->vec_buf.data();
}

const char *StringBuffer::Str() const noexcept
{
    return reinterpret_cast<const char *>(priv->vec_buf.data());
}

size_t StringBuffer::Size() const noexcept
{
    return priv->vec_buf.size();
}

bool StringBuffer::Empty() const noexcept
{
    return priv->vec_buf.empty();
}

void StringBuffer::Reserve(size_t len) noexcept
{
    if (len > priv->vec_buf.capacity())
    {
        size_t size = Size();
        Resize(len);
        Resize(size);
    }
}

void StringBuffer::Resize(size_t len, uint8_t val) noexcept
{
    if (len > priv->vec_buf.capacity())
    {
        StringBuffer temp(len, val);
        memmove(temp.priv->vec_buf.data(), priv->vec_buf.data(), priv->vec_buf.size());
        *this = std::move(temp);
    }
    else if (len >= priv->vec_buf.size())
    {
        priv->vec_buf.resize(len, val);
    }
    else
    {
        memset(priv->vec_buf.data() + len, val, priv->vec_buf.size() - len);
        priv->vec_buf.resize(len, val);
    }
}

void StringBuffer::Reset(size_t len, uint8_t val) noexcept
{
    memset(priv->vec_buf.data(), val, priv->vec_buf.size());
    priv->vec_buf.resize(len, val);
}

void StringBuffer::Append(const uint8_t *buf, size_t len) noexcept
{
    size_t size = Size();
    Resize(size + len);
    memmove(Data() + size, buf, len);
}

void StringBuffer::Append(const StringBuffer &other) noexcept
{
    size_t size = Size();
    Resize(size + other.Size());
    memmove(Data() + size, other.Data(), other.Size());
}

void StringBuffer::RandomFill() noexcept
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto &byte : priv->vec_buf)
    {
        byte = static_cast<uint8_t>(dis(gen));
    }
}

uint8_t StringBuffer::At(size_t i) const noexcept
{
    assert(0 <= i && i < Size());
    return priv->vec_buf[i];
}

std::strong_ordering StringBuffer::operator<=>(const StringBuffer &other) const noexcept
{
    return priv->vec_buf <=> other.priv->vec_buf;
}

bool StringBuffer::operator==(const StringBuffer &other) const noexcept
{
    return priv->vec_buf == other.priv->vec_buf;
}
