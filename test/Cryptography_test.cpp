/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#include "gtest/gtest.h"
#include "fmt/format.h"
#include "Cryptography.h"

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

using namespace std::literals::chrono_literals;

TEST(Cryptography, test)
{
    std::string str = "XDFGHJafhdldknf@p9US*jknbgKSQ!~!@#$%^&*()_+}\"?><MNBVCXJHGV>NHBV-";

    for (int i = 0; i < 25; ++i)
    {
        StringBuffer buf(str.data(), str.size());
        StringBuffer iv = Cryptography::AES::GenerateIV(AES_BLOCK_SIZE);
        constexpr size_t keyLength = 256;
        StringBuffer key = Cryptography::AES::GenerateKey(keyLength);

        Chrono chrono;
        StringBuffer encryptedData = Cryptography::AES::Encrypt(key, iv, buf);
        chrono.stop();

        Chrono chrono2;
        StringBuffer buf2 = Cryptography::AES::Decrypt(key, iv, encryptedData);
        chrono2.stop();

        /* x64 Debug
         * keyLength=256, buf=1.00KB, encrypt=0.03ms, decrypt=0.01ms
         * keyLength=256, buf=1.00MB, encrypt=1.81ms, decrypt=1.16ms
         * keyLength=256, buf=1.00GB, encrypt=1.28s, decrypt=1.69s
         *
         * x64 Release
         * keyLength=256, buf=1.00KB, encrypt=0.01ms, decrypt=0.01ms
         * keyLength=256, buf=1.00MB, encrypt=2.39ms, decrypt=1.91ms
         * keyLength=256, buf=1.00GB, encrypt=1.27s, decrypt=1.07s
         */
        fmt::print("keyLength={}, buf={}, encrypt={}, decrypt={} \n",
                   keyLength,
                   Common::FormatBytes(buf.Size()),
                   Common::FormatMillisecons(chrono.use_time()),
                   Common::FormatMillisecons(chrono2.use_time()));

        EXPECT_EQ(buf, buf2);
        str += str;
    }
}
