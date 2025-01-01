/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#include "Cryptography.h"
#include <openssl/sha.h>

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

StringBuffer Cryptography::Hash::SHA(const StringBuffer &message, size_t bits)
{
    static_assert(SHA256_DIGEST_LENGTH == 256 / 8);
    StringBuffer hash(bits / 8);
    SHA256(message.Data(), message.Size(), hash.Data());
    return hash;
}
