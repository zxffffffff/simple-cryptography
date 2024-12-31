/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#include "Cryptography.h"
extern "C"
{
#include <sss.h>
}

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

std::vector<StringBuffer> Cryptography::SSS::Shares(const StringBuffer &message, int n, int k)
{
    std::vector<StringBuffer> shares(n);

    unsigned char sss_message[sss_MLEN];
    sss_Share *sss_shares = new sss_Share[n];
    for (size_t i = 0; i < message.Size(); i += sss_MLEN)
    {
        memset(sss_message, 0, sss_MLEN);
        memmove(sss_message, message.Data() + i, std::min(sss_MLEN, message.Size() - i));
        std::memset(sss_shares, 0, n * sss_SHARE_LEN);

        sss_create_shares(sss_shares, sss_message, n, k);

        for (int j = 0; j < n; ++j)
            shares[j].Append(sss_shares[j], sss_SHARE_LEN);
    }
    memset(sss_message, 0, sss_MLEN);
    std::memset(sss_shares, 0, n * sss_SHARE_LEN);
    delete[] sss_shares;

    return shares;
}

StringBuffer Cryptography::SSS::Combine(const std::vector<StringBuffer> &shares)
{
    StringBuffer restored;
    const int k = shares.size();

    unsigned char sss_restored[sss_MLEN];
    sss_Share *sss_shares = new sss_Share[k];
    for (size_t i = 0; i < shares[0].Size(); i += sss_SHARE_LEN)
    {
        memset(sss_restored, 0, sss_MLEN);
        for (int j = 0; j < k; ++j)
            memmove(sss_shares[j], shares[j].Data() + i, sss_SHARE_LEN);

        int ret = sss_combine_shares(sss_restored, sss_shares, k);
        if (ret)
        {
            memset(sss_restored, 0, sss_MLEN);
            std::memset(sss_shares, 0, k * sss_SHARE_LEN);
            delete[] sss_shares;

            throw std::runtime_error("sss_combine_shares failed");
        }
        restored.Append(sss_restored, sss_MLEN);
    }
    memset(sss_restored, 0, sss_MLEN);
    std::memset(sss_shares, 0, k * sss_SHARE_LEN);
    delete[] sss_shares;

    return restored;
}
