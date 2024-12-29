/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#pragma once
#include "common/cpp_version.h"
#include "common/cpp_def.h"
#include "common/common.h"
#include "common/chrono.h"
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

class StringBuffer
{
private:
    std::vector<uint8_t> vec_buf;

public:
    StringBuffer()
    {
    }

    StringBuffer(const uint8_t *buf, size_t len)
    {
        Resize(len);
        memmove(vec_buf.data(), buf, len);
    }

    StringBuffer(const char *buf, size_t len)
    {
        Resize(len);
        memmove(vec_buf.data(), buf, len);
    }

    StringBuffer(size_t len)
    {
        Resize(len);
    }

    virtual ~StringBuffer()
    {
        memset(vec_buf.data(), 0, vec_buf.size());
    }

    const uint8_t *Data() const
    {
        return reinterpret_cast<const uint8_t *>(vec_buf.data());
    }

    uint8_t *Data()
    {
        return const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(vec_buf.data()));
    }

    const char *Str() const
    {
        return reinterpret_cast<const char *>(vec_buf.data());
    }

    size_t Size() const
    {
        return vec_buf.size();
    }

    bool Empty() const
    {
        return vec_buf.empty();
    }

    void Resize(size_t len, uint8_t val = 0)
    {
        if (len > vec_buf.size())
        {
            std::vector<uint8_t> temp(len, val);
            memmove(temp.data(), vec_buf.data(), vec_buf.size());
            memset(vec_buf.data(), val, vec_buf.size());
            vec_buf.swap(temp);
        }
        else
        {
            vec_buf.resize(len, val);
        }
    }

    void Reset(size_t len, uint8_t val = 0)
    {
        memset(vec_buf.data(), val, vec_buf.size());
        vec_buf.resize(len, val);
    }

    std::strong_ordering operator<=>(const StringBuffer &other) const
    {
        return vec_buf <=> other.vec_buf;
    }

    bool operator==(const StringBuffer &other) const
    {
        return vec_buf == other.vec_buf;
    }
};