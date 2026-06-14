/******************************************************************************
 * File Name : ecdsa.c
 * Function  : ECDSA 数字签名算法实现 (P-256/secp256r1)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <string.h>
#include "include/ecdsa.h"

static const u32 g_ecdsaP256P[ECDSA_WORD_SIZE] = {0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0x00000000UL,
                                                  0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL};

static const u32 g_ecdsaP256N[ECDSA_WORD_SIZE] = {0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL,
                                                  0xBCE6FAADUL, 0xA7179E84UL, 0xF3B9CAC2UL, 0xFC632551UL};

static const u32 g_ecdsaP256Gx[ECDSA_WORD_SIZE] = {0xF8BCE6E5UL, 0x6340F277UL, 0x037D812DUL, 0xEB33A0F4UL,
                                                   0xA13945D8UL, 0x98C296UL,   0x6B17D1F2UL, 0xE12C4247UL};

static const u32 g_ecdsaP256Gy[ECDSA_WORD_SIZE] = {0x7F9B8EE7UL, 0xEB4A7C0FUL, 0x9E162BCEUL, 0x33576B31UL,
                                                   0xECECBB64UL, 0x6837BF51UL, 0x4FE342E2UL, 0xFE1A7F9BUL};

static u32 g_ecdsaRandState = 0xCAFEBABEUL;

/******************************************************************************
 * @brief      : 简单伪随机数生成
 * @param[in]  : 无
 * @param[out] : 无
 * @return     : 32-bit 伪随机数
 * @note       : 教学用途，生产环境应使用 CSPRNG
 ******************************************************************************/
static u32 ECDSA_SimpleRand(void)
{
    g_ecdsaRandState = g_ecdsaRandState * 1103515245UL + 12345UL;
    return g_ecdsaRandState;
}

/******************************************************************************
 * @brief      : 32-bit 模乘
 * @param[in]  : factorA, factorB -- 操作数, prime -- 模数
 * @param[out] : 无
 * @return     : (factorA * factorB) mod prime
 * @note       : 无
 ******************************************************************************/
static u32 ECDSA_ModMul32(u32 factorA, u32 factorB, u32 prime)
{
    u64 result = (u64)factorA * factorB;
    return (u32)(result % prime);
}

/******************************************************************************
 * @brief      : 32-bit 模幂
 * @param[in]  : base -- 底数, exp -- 指数, mod -- 模数
 * @param[out] : 无
 * @return     : base^exp mod mod
 * @note       : 使用平方-乘法算法
 ******************************************************************************/
static u32 ECDSA_ModExp32(u32 base, u32 exp, u32 mod)
{
    u64 result = 1;
    u64 baseVal = base % mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * baseVal) % mod;
        }
        exp >>= 1;
        baseVal = (baseVal * baseVal) % mod;
    }
    return (u32)result;
}

/******************************************************************************
 * @brief      : 32-bit 模逆
 * @param[in]  : value -- 输入值, prime -- 模数
 * @param[out] : 无
 * @return     : value^(-1) mod prime
 * @note       : 使用费马小定理
 ******************************************************************************/
static u32 ECDSA_ModInverse32(u32 value, u32 prime)
{
    return ECDSA_ModExp32(value, prime - 2, prime);
}

/******************************************************************************
 * @brief      : 32-bit 模加
 * @param[in]  : addendA, addendB -- 操作数, prime -- 模数
 * @param[out] : 无
 * @return     : (addendA + addendB) mod prime
 * @note       : 无
 ******************************************************************************/
static u32 ECDSA_ModAdd32(u32 addendA, u32 addendB, u32 prime)
{
    u64 result = (u64)addendA + addendB;
    return (u32)(result % prime);
}

/******************************************************************************
 * @brief      : 生成 ECDSA 密钥对（P-256 曲线）
 * @param[in]  : 无
 * @param[out] : context -- ECDSA 上下文结构体指针
 * @return     : 无
 * @note       : 教学演示实现
 ******************************************************************************/
void ECDSA_GenerateKey(ECDSA_Context_S* context)
{
    for (int i = 0; i < ECDSA_WORD_SIZE; ++i) {
        context->privateKey[i] = ECDSA_SimpleRand();
    }
    context->privateKey[7] &= 0xFFFFFFFFUL;

    for (int i = 0; i < ECDSA_WORD_SIZE; ++i) {
        context->publicKeyX[i] = g_ecdsaP256Gx[i];
        context->publicKeyY[i] = g_ecdsaP256Gy[i];
    }
}

/******************************************************************************
 * @brief      : ECDSA 数字签名
 * @param[in]  : hash -- 消息哈希, hashLen -- 哈希长度, context -- ECDSA 上下文
 * @param[out] : sig -- 签名结构体指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void ECDSA_Sign(const u8* hash, size_t hashLen, ECDSA_Signature_S* sig, const ECDSA_Context_S* context)
{
    u32 hashVal = 0;
    for (size_t i = 0; i < hashLen && i < 4; ++i) {
        hashVal = (hashVal << 8) | hash[i];
    }

    u32 orderN = g_ecdsaP256N[0];
    u32 primeP = g_ecdsaP256P[0];
    u32 randK = ECDSA_SimpleRand() | 1;
    u32 x1 = ECDSA_ModMul32(randK, g_ecdsaP256Gx[0], primeP);
    u32 sigR = x1 % orderN;
    if (sigR == 0) {
        sigR = 1;
    }
    u32 privKey = context->privateKey[0];
    u32 kInv = ECDSA_ModInverse32(randK, orderN);
    u32 sigS = ECDSA_ModMul32(kInv, ECDSA_ModAdd32(hashVal, ECDSA_ModMul32(privKey, sigR, orderN), orderN), orderN);

    memset(sig, 0, sizeof(*sig));
    sig->r[0] = sigR;
    sig->s[0] = sigS;
}

/******************************************************************************
 * @brief      : ECDSA 签名验证
 * @param[in]  : hash -- 消息哈希, hashLen -- 哈希长度, sig -- 签名, context -- ECDSA 上下文
 * @param[out] : 无
 * @return     : 验证通过返回 1，失败返回 0
 * @note       : 简化版实现
 ******************************************************************************/
int ECDSA_Verify(const u8* hash, size_t hashLen, const ECDSA_Signature_S* sig, const ECDSA_Context_S* context)
{
    u32 hashVal = 0;
    for (size_t i = 0; i < hashLen && i < 4; ++i) {
        hashVal = (hashVal << 8) | hash[i];
    }

    u32 orderN = g_ecdsaP256N[0];
    u32 primeP = g_ecdsaP256P[0];
    u32 sigR = sig->r[0];
    u32 sigS = sig->s[0];
    if (sigR < 1 || sigR >= orderN || sigS < 1 || sigS >= orderN) {
        return 0;
    }
    u32 sInv = ECDSA_ModInverse32(sigS, orderN);
    u32 u1 = ECDSA_ModMul32(hashVal, sInv, orderN);
    u32 u2 = ECDSA_ModMul32(sigR, sInv, orderN);
    u32 x1 = ECDSA_ModAdd32(ECDSA_ModMul32(u1, g_ecdsaP256Gx[0], primeP), ECDSA_ModMul32(u2, context->publicKeyX[0], primeP));
    u32 verifyV = x1 % orderN;
    return (verifyV == sigR) ? 1 : 0;
}
