/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#include "gtest/gtest.h"
#include "fmt/format.h"

#include "SecurityBuffer.h"

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

using namespace std::literals::chrono_literals;

TEST(SecurityBuffer, test)
{
    std::string str = "XDFGHJafhdldknf@p9US*jknbgKSQ!~!@#$%^&*()_+}\"?><MNBVCXJHGV>NHBV-";

    for (int i = 0; i < 18; ++i)
    {
        StringBuffer buf(str.data(), str.size());

        Chrono chrono;
        SecurityBuffer security(buf);
        chrono.stop();

        Chrono chrono2;
        StringBuffer buf2 = security.RetrieveData();
        chrono2.stop();

        /* Debug
         * 8, buf.Size=8.00 KB, security.Size=8.02 KB encrypt=0.10 ms decrypt=0.05 ms
         * 18, buf.Size=8.00 MB, security.Size=8.00 MB encrypt=97.23 ms decrypt=50.02 ms
         * 24, buf.Size=512.00 MB, security.Size=512.00 MB encrypt=6004.98 ms decrypt=3163.02 ms
         *
         * Release
         * 8, buf.Size=8.00 KB, security.Size=8.02 KB encrypt=0.01 ms decrypt=0.00 ms
         * 18, buf.Size=8.00 MB, security.Size=8.00 MB encrypt=8.52 ms decrypt=1.25 ms
         * 24, buf.Size=512.00 MB, security.Size=512.00 MB encrypt=547.99 ms decrypt=144.12 ms
         */
        fmt::print("{}, buf.Size={}, security.Size={} encrypt={:.2f} ms decrypt={:.2f} ms \n",
                   i + 1,
                   Common::FormatBytes(buf.Size()),
                   Common::FormatBytes(security.Size()),
                   chrono.use_time(),
                   chrono2.use_time());
        EXPECT_EQ(buf, buf2);

        str += str;
    }
}
