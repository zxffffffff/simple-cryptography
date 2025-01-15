/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#pragma once
#include <string>
#include <cstring>
#include <vector>
#include <memory>
#include <stdexcept>
#include <random>
#include <cassert>
#include <sstream>

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

// std::vector<uint8_t>
class StringBuffer
{
private:
    std::unique_ptr<class StringBufferPriv> priv;

public:
    StringBuffer() noexcept;
    StringBuffer(const uint8_t *buf, size_t len) noexcept;
    StringBuffer(const char *buf, size_t len) noexcept;
    StringBuffer(size_t len, uint8_t val = 0) noexcept;

    // 拷贝构造和拷贝赋值
    StringBuffer(const StringBuffer &other) noexcept;
    StringBuffer &operator=(const StringBuffer &other) noexcept;

    // 移动构造和移动赋值
    StringBuffer(StringBuffer &&other) noexcept;
    StringBuffer &operator=(StringBuffer &&other) noexcept;

    virtual ~StringBuffer() noexcept;

    const uint8_t *Data() const noexcept;
    uint8_t *Data() noexcept;
    const char *Str() const noexcept;

    size_t Size() const noexcept;
    bool Empty() const noexcept;
    void Reserve(size_t len) noexcept;
    void Resize(size_t len, uint8_t val = 0) noexcept;
    void Reset(size_t len, uint8_t val = 0) noexcept;
    void Append(const uint8_t *buf, size_t len) noexcept;
    void Append(const StringBuffer &other) noexcept;
    void RandomFill() noexcept;
    uint8_t At(size_t i) const noexcept;

    std::strong_ordering operator<=>(const StringBuffer &other) const noexcept;
    bool operator==(const StringBuffer &other) const noexcept;
};
