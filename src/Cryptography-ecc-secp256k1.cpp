/****************************************************************************
** MIT License
**
** Author	: xiaofeng.zhu
** Support	: zxffffffff@outlook.com, 1337328542@qq.com
**
****************************************************************************/
#include "Cryptography.h"
#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#if defined(_MSC_VER) && (_MSC_VER >= 1500 && _MSC_VER < 1900)
/* msvc兼容utf-8: https://support.microsoft.com/en-us/kb/980263 */
#if (_MSC_VER >= 1700)
#pragma execution_character_set("utf-8")
#endif
#pragma warning(disable : 4566)
#endif

std::pair<StringBuffer, StringBuffer> Cryptography::ECC::GenerateKey()
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx)
    {
        throw std::runtime_error("Failed to create secp256k1 context");
    }

    StringBuffer private_key(32);
    StringBuffer public_key(65); // 公钥压缩时为33字节，非压缩为65字节

    do
    {
        private_key.RandomFill();
    } while (secp256k1_ec_seckey_verify(ctx, private_key.Data()) != 1);

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, private_key.Data()) != 1)
    {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Failed to create public key");
    }

    size_t public_key_len = public_key.Size();
    secp256k1_ec_pubkey_serialize(ctx, public_key.Data(), &public_key_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    secp256k1_context_destroy(ctx);
    return {private_key, public_key};
}

StringBuffer Cryptography::ECC::Sign(const StringBuffer &private_key, const StringBuffer &message_hash)
{
    if (private_key.Size() != 32 || message_hash.Size() != 32)
    {
        throw std::invalid_argument("Invalid key or hash size");
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx)
    {
        throw std::runtime_error("Failed to create secp256k1 context");
    }

    StringBuffer signature(64);
    secp256k1_ecdsa_signature sig;

    if (secp256k1_ecdsa_sign(ctx, &sig, message_hash.Data(), private_key.Data(), nullptr, nullptr) != 1)
    {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Failed to sign message");
    }

    if (secp256k1_ecdsa_signature_serialize_compact(ctx, signature.Data(), &sig) != 1)
    {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Failed to serialize signature");
    }

    secp256k1_context_destroy(ctx);
    return signature;
}

bool Cryptography::ECC::Verify(const StringBuffer &public_key, const StringBuffer &message_hash, const StringBuffer &signature)
{
    if (public_key.Size() != 65 || message_hash.Size() != 32 || signature.Size() != 64)
    {
        throw std::invalid_argument("Invalid input sizes");
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx)
    {
        throw std::runtime_error("Failed to create secp256k1 context");
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_parse(ctx, &pubkey, public_key.Data(), public_key.Size()) != 1)
    {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("secp256k1_ec_pubkey_parse failed");
    }

    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature.Data()) != 1)
    {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("secp256k1_ecdsa_signature_parse_compact failed");
    }

    secp256k1_context_destroy(ctx);
    int ret = secp256k1_ecdsa_verify(ctx, &sig, message_hash.Data(), &pubkey);
    return ret == 1;
}

StringBuffer Cryptography::ECC::ECDH(const StringBuffer &a_private_key, const StringBuffer &b_public_key)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx)
    {
        throw std::runtime_error("Failed to create secp256k1 context");
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_parse(ctx, &pubkey, b_public_key.Data(), b_public_key.Size()) != 1)
    {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("secp256k1_ec_pubkey_parse failed");
    }

    StringBuffer sharedSecret(32);
    if (!secp256k1_ecdh(ctx, sharedSecret.Data(), &pubkey, a_private_key.Data(), NULL, NULL))
    {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("secp256k1_ecdh failed");
    }

    secp256k1_context_destroy(ctx);
    return sharedSecret;
}
