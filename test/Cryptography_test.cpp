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
        constexpr size_t keyLength = 256;
        constexpr size_t ivLength = 16;
        StringBuffer key = Cryptography::AES::GenerateKey(keyLength);
        StringBuffer iv = Cryptography::AES::GenerateIV(ivLength);
        StringBuffer buf(str.data(), str.size());

        Chrono chrono;
        StringBuffer encryptedData = Cryptography::AES::Encrypt(key, iv, buf);
        chrono.stop();

        Chrono chrono2;
        StringBuffer buf2 = Cryptography::AES::Decrypt(key, iv, encryptedData);
        chrono2.stop();

        /*
         * Laptop x64-windows Release
         * keyLength=256, buf=1.00KB, encrypt=0.01ms, decrypt=0.01ms
         * keyLength=256, buf=1.00MB, encrypt=2.39ms, decrypt=1.91ms
         * keyLength=256, buf=1.00GB, encrypt=1.27s, decrypt=1.07s
         *
         * Desktop arm64-osx Release
         * keyLength=256, buf=1.00KB, encrypt=0.00ms, decrypt=0.00ms
         * keyLength=256, buf=1.00MB, encrypt=0.88ms, decrypt=0.20ms
         * keyLength=256, buf=1.00GB, encrypt=915.64ms, decrypt=321.96ms
         */
        fmt::print("key={}, iv={}, buf={}, encrypt={}, decrypt={} \n",
                   keyLength,
                   ivLength,
                   Common::FormatBytes(buf.Size()),
                   Common::FormatMillisecons(chrono.use_time()),
                   Common::FormatMillisecons(chrono2.use_time()));

        EXPECT_EQ(buf, buf2);
        str += str;
    }
}
