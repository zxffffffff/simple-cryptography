/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#include "gtest/gtest.h"
#include "fmt/format.h"
#include "SecureBuffer.h"
#include "common/chrono.h"
#include "common/common.h"

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

using namespace std::literals::chrono_literals;

TEST(SecureBuffer, test)
{
    std::string str = "XDFGHJafhdldknf@p9US*jknbgKSQ!~!@#$%^&*()_+}\"?><MNBVCXJHGV>NHBV-";

    for (int i = 0; i < 10; ++i)
    {
        StringBuffer buf(str.data(), str.size());

        Chrono chrono;
        SecureBuffer security(buf);
        chrono.stop();

        Chrono chrono2;
        StringBuffer buf2 = security.RetrieveData();
        chrono2.stop();

        fmt::print("buf={}, security={} encrypt={}, decrypt={} \n",
                   Common::FormatBytes(buf.Size()),
                   Common::FormatBytes(security.Size()),
                   Common::FormatMillisecons(chrono.use_time()),
                   Common::FormatMillisecons(chrono2.use_time()));

        EXPECT_EQ(buf, buf2);
        str += str;
    }
}
