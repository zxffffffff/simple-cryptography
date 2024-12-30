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

TEST(Cryptography, Hash_SHA)
{
    std::string str = "XDFGHJafhdldknf@p9US*jknbgKSQ!~!@#$%^&*()_+}\"?><MNBVCXJHGV>NHBV-";

    for (int i = 0; i < 10; ++i)
    {
        constexpr size_t bits = 256;

        StringBuffer buf(str.data(), str.size());

        Chrono chrono;
        StringBuffer hash = Cryptography::Hash::SHA(buf, bits);
        StringBuffer hash2 = Cryptography::Hash::SHA(buf, bits);
        chrono.stop();

        /*
         * Laptop x64-windows Release
         * bits=256, buf=1.00KB, sha=0.01ms, hash=f369...
         * bits=256, buf=1.00MB, sha=8.95ms, hash=58e6...
         * bits=256, buf=1.00GB, sha=2.31s, hash=6bda...
         *
         * Desktop arm64-osx Release
         * bits=256, buf=1.00KB, sha=0.00ms, hash=f369...
         * bits=256, buf=1.00MB, sha=0.43ms, hash=58e6...
         * bits=256, buf=1.00GB, sha=407.88ms, hash=6bda...
         */
        fmt::print("bits={}, buf={}, sha={}, hash={} \n",
                   bits,
                   Common::FormatBytes(buf.Size()),
                   Common::FormatMillisecons(chrono.use_time() / 2),
                   Cryptography::Hash::ToString(hash));

        EXPECT_EQ(hash, hash2);
        EXPECT_NE(buf, hash);
        str += str;
    }
}

TEST(Cryptography, AES_Encrypt)
{
    std::string str = "XDFGHJafhdldknf@p9US*jknbgKSQ!~!@#$%^&*()_+}\"?><MNBVCXJHGV>NHBV-";

    for (int i = 0; i < 10; ++i)
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
        EXPECT_NE(buf, encryptedData);
        str += str;
    }
}

TEST(Cryptography, RSA_Encrypt)
{
    std::string str = "XDFGHJafhdldknf@p9US*jknbgKSQ!~!@#$%^&*()_+}\"?><MNBVCXJHGV>NHBV-";

    for (int i = 0; i < 10; ++i)
    {
        constexpr size_t bits = 2048;
        constexpr int pad_mode = 4;
        auto [privateKey, publicKey] = Cryptography::RSA::GenerateKey(bits);

        StringBuffer buf(str.data(), str.size());

        Chrono chrono;
        StringBuffer encryptedData = Cryptography::RSA::Encrypt(publicKey, buf, pad_mode);
        chrono.stop();

        Chrono chrono2;
        StringBuffer buf2 = Cryptography::RSA::Decrypt(privateKey, encryptedData, pad_mode);
        chrono2.stop();

        /*
         * Laptop x64-windows Release
         * bits=2048, pad_mode=4, buf=1.00KB, encrypt=0.38ms, decrypt=8.73ms
         * bits=2048, pad_mode=4, buf=64.00KB, encrypt=8.52ms, decrypt=206.61ms
         * bits=2048, pad_mode=4, buf=1.00MB, encrypt=151.11ms, decrypt=2.99s
         *
         * Desktop arm64-osx Release
         * bits=2048, pad_mode=4, buf=1.00KB, encrypt=0.12ms, decrypt=2.70ms
         * bits=2048, pad_mode=4, buf=64.00KB, encrypt=4.65ms, decrypt=155.96ms
         * bits=2048, pad_mode=4, buf=1.00MB, encrypt=73.32ms, decrypt=2.44s
         */
        fmt::print("bits={}, pad_mode={}, buf={}, encrypt={}, decrypt={} \n",
                   bits,
                   pad_mode,
                   Common::FormatBytes(buf.Size()),
                   Common::FormatMillisecons(chrono.use_time()),
                   Common::FormatMillisecons(chrono2.use_time()));

        EXPECT_EQ(buf, buf2);
        EXPECT_NE(buf, encryptedData);
        str += str;
    }
}

TEST(Cryptography, RSA_Sign)
{
    std::string str = "XDFGHJafhdldknf@p9US*jknbgKSQ!~!@#$%^&*()_+}\"?><MNBVCXJHGV>NHBV-";

    for (int i = 0; i < 10; ++i)
    {
        constexpr size_t bits = 2048;
        auto [privateKey, publicKey] = Cryptography::RSA::GenerateKey(bits);

        StringBuffer buf(str.data(), str.size());

        Chrono chrono;
        StringBuffer signature = Cryptography::RSA::Sign(privateKey, buf);
        chrono.stop();

        Chrono chrono2;
        bool ok = Cryptography::RSA::Verify(publicKey, buf, signature);
        chrono2.stop();

        /*
         * Laptop x64-windows Release
         * bits=2048, buf=1.00KB, sign=1.50ms, verify=0.12ms
         * bits=2048, buf=1.00MB, sign=4.14ms, verify=2.74ms
         * bits=2048, buf=1.00GB, sign=2.15s, verify=2.16s
         *
         * Desktop arm64-osx Release
         * bits=2048, buf=1.00KB, sign=0.84ms, verify=0.05ms
         * bits=2048, buf=1.00MB, sign=1.17ms, verify=0.44ms
         * bits=2048, buf=1.00GB, sign=407.62ms, verify=409.73ms
         */
        fmt::print("bits={}, buf={}, sign={}, verify={} \n",
                   bits,
                   Common::FormatBytes(buf.Size()),
                   Common::FormatMillisecons(chrono.use_time()),
                   Common::FormatMillisecons(chrono2.use_time()));

        EXPECT_TRUE(ok);
        EXPECT_NE(buf, signature);
        str += str;
    }
}

TEST(Cryptography, ECC_Sign)
{
    std::string str = "XDFGHJafhdldknf@p9US*jknbgKSQ!~!@#$%^&*()_+}\"?><MNBVCXJHGV>NHBV-";

    for (int i = 0; i < 10; ++i)
    {
        auto [privateKey, publicKey] = Cryptography::ECC::GenerateKey();

        StringBuffer buf(str.data(), str.size());
        StringBuffer hash = Cryptography::Hash::SHA(buf);

        Chrono chrono;
        StringBuffer signature = Cryptography::ECC::Sign(privateKey, hash);
        chrono.stop();

        Chrono chrono2;
        bool ok = Cryptography::ECC::Verify(publicKey, hash, signature);
        chrono2.stop();

        /*
         * Laptop x64-windows Release
         * hash=32B, sign=0.05ms, verify=0.13ms
         *
         * Desktop arm64-osx Release
         * hash=32B, sign=0.02ms, verify=0.02ms
         */
        fmt::print("hash={}, sign={}, verify={} \n",
                   Common::FormatBytes(hash.Size()),
                   Common::FormatMillisecons(chrono.use_time()),
                   Common::FormatMillisecons(chrono2.use_time()));

        EXPECT_TRUE(ok);
        EXPECT_NE(buf, signature);
        str += str;
    }
}
