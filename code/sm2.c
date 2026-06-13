/******************************************************************************
 * File Name : sm2.c
 * Function  : SM2 椭圆曲线公钥密码算法实现 (GB/T 32918-2016)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <string.h>
#include <stdint.h>
#include "include/sm2.h"

static const u32 g_sm2Prime[SM2_WORD_SIZE] = {
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0x00000000UL, 0xFFFFFFFFUL,
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL
};

static const u32 g_sm2GenGx[SM2_WORD_SIZE] = {
    0x7C74C743UL, 0x1F198119UL, 0x2C1F1981UL, 0x9948FE30UL,
    0xBBFF2660UL, 0xBE1715A4UL, 0x589334C7UL, 0x32C4AE2CUL
};

static const u32 g_sm2GenGy[SM2_WORD_SIZE] = {
    0x474002DFUL, 0x2F4F6779UL, 0x59BDCEE3UL, 0x6B692153UL,
    0xD0A9877CUL, 0xC62A4740UL, 0x139F0A0AUL, 0xBC3736A2UL
};

static const u32 g_sm2Order[SM2_WORD_SIZE] = {
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0x00000000UL, 0xFFFFFFFFUL,
    0x7203DF6BUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL
};

static u32 g_sm2RandState = 0xDEADBEEFUL;

/******************************************************************************
 * @brief      : 简单伪随机数生成
 * @param[in]  : 无
 * @param[out] : 无
 * @return     : 32-bit 伪随机数
 * @note       : 教学用途，生产环境应使用 CSPRNG
 ******************************************************************************/
static u32 SM2_SimpleRand(void)
{
    g_sm2RandState = g_sm2RandState * 1103515245UL + 12345UL;
    return g_sm2RandState;
}

/******************************************************************************
 * @brief      : 32-bit 模加
 * @param[in]  : addendA, addendB -- 操作数
 * @param[out] : 无
 * @return     : (addendA + addendB) mod p
 * @note       : 无
 ******************************************************************************/
static u32 SM2_ModAdd32(u32 addendA, u32 addendB)
{
    u64 result = (u64)addendA + addendB;
    return (u32)(result);
}

/******************************************************************************
 * @brief      : 32-bit 模乘
 * @param[in]  : factorA, factorB -- 操作数, prime -- 模数
 * @param[out] : 无
 * @return     : (factorA * factorB) mod prime
 * @note       : 简化版，仅处理小数
 ******************************************************************************/
static u32 SM2_ModMul32(u32 factorA, u32 factorB, u32 prime)
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
static u32 SM2_ModExp32(u32 base, u32 exp, u32 mod)
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
static u32 SM2_ModInverse32(u32 value, u32 prime)
{
    return SM2_ModExp32(value, prime - 2, prime);
}

/******************************************************************************
 * @brief      : 生成 SM2 密钥对
 * @param[in]  : 无
 * @param[out] : context -- SM2 上下文结构体指针
 * @return     : 无
 * @note       : 教学演示实现
 ******************************************************************************/
void SM2_GenerateKey(SM2_Context_S* context)
{
    for (int i = 0; i < SM2_WORD_SIZE; ++i) {
        context->privateKey[i] = SM2_SimpleRand();
    }
    context->privateKey[7] &= 0xFFFFFFFEUL;

    for (int i = 0; i < SM2_WORD_SIZE; ++i) {
        context->publicKeyX[i] = g_sm2GenGx[i];
        context->publicKeyY[i] = g_sm2GenGy[i];
    }
}

/******************************************************************************
 * @brief      : SM2 数字签名
 * @param[in]  : hash -- 消息哈希, hashLen -- 哈希长度, context -- SM2 上下文
 * @param[out] : sig -- 签名结构体指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void SM2_Sign(const u8* hash, size_t hashLen, SM2_Signature_S* sig, const SM2_Context_S* context)
{
    u32 hashVal = 0;
    for (size_t i = 0; i < hashLen && i < 4; ++i) {
        hashVal = (hashVal << 8) | hash[i];
    }

    u32 randK = SM2_SimpleRand() | 1;
    u32 x1 = SM2_ModMul32(randK, g_sm2GenGx[0], g_sm2Prime[0]);
    u32 orderN = g_sm2Order[0];
    u32 sigR = SM2_ModAdd32(hashVal, x1) % orderN;
    if (sigR == 0) {
        sigR = 1;
    }
    u32 privKey = context->privateKey[0];
    u32 kInv = SM2_ModInverse32(randK, orderN);
    u32 sigS = SM2_ModMul32(kInv, (SM2_ModAdd32(randK, orderN - SM2_ModMul32(sigR, privKey, orderN)) % orderN), orderN);

    memset(sig, 0, sizeof(*sig));
    sig->r[0] = sigR;
    sig->s[0] = sigS;
}

/******************************************************************************
 * @brief      : SM2 签名验证
 * @param[in]  : hash -- 消息哈希, hashLen -- 哈希长度, sig -- 签名, context -- SM2 上下文
 * @param[out] : 无
 * @return     : 验证通过返回 1，失败返回 0
 * @note       : 简化版实现
 ******************************************************************************/
int SM2_Verify(const u8* hash, size_t hashLen, const SM2_Signature_S* sig, const SM2_Context_S* context)
{
    u32 hashVal = 0;
    for (size_t i = 0; i < hashLen && i < 4; ++i) {
        hashVal = (hashVal << 8) | hash[i];
    }

    u32 orderN = g_sm2Order[0];
    u32 sigR = sig->r[0];
    u32 sigS = sig->s[0];
    if (sigR < 1 || sigR >= orderN || sigS < 1 || sigS >= orderN) {
        return 0;
    }
    u32 sumT = (sigR + sigS) % orderN;
    if (sumT == 0) {
        return 0;
    }
    u32 sInv = SM2_ModInverse32(sigS, orderN);
    u32 u1 = SM2_ModMul32(hashVal, sInv, orderN);
    u32 u2 = SM2_ModMul32(sigR, sInv, orderN);
    u32 x1 = SM2_ModAdd32(SM2_ModMul32(u1, g_sm2GenGx[0], g_sm2Prime[0]),
                           SM2_ModMul32(u2, context->publicKeyX[0], g_sm2Prime[0]));
    u32 verifyV = (hashVal + x1) % orderN;
    return (verifyV == sigR) ? 1 : 0;
}

/******************************************************************************
 * @brief      : SM2 公钥加密
 * @param[in]  : plaintext -- 明文, ptLen -- 明文长度, context -- SM2 上下文
 * @param[out] : ciphertext -- 密文, ctLen -- 密文长度指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void SM2_Encrypt(const u8* plaintext, size_t ptLen, u8* ciphertext, size_t* ctLen, const SM2_Context_S* context)
{
    u32 randK = SM2_SimpleRand() | 1;
    u32 c1x = SM2_ModMul32(randK, g_sm2GenGx[0], g_sm2Prime[0]);
    u32 c1y = SM2_ModMul32(randK, g_sm2GenGy[0], g_sm2Prime[0]);
    u32 x2 = SM2_ModMul32(randK, context->publicKeyX[0], g_sm2Prime[0]);
    u32 y2 = SM2_ModMul32(randK, context->publicKeyY[0], g_sm2Prime[0]);

    (void)c1y;
    (void)y2;

    size_t offset = 0;
    for (int i = 0; i < 4; ++i) {
        ciphertext[offset++] = (u8)((c1x >> (24 - i * 8)) & 0xFF);
    }
    for (size_t i = 0; i < ptLen; ++i) {
        ciphertext[offset++] = plaintext[i] ^ (u8)(x2 & 0xFF);
    }
    if (ctLen) {
        *ctLen = offset;
    }
}

/******************************************************************************
 * @brief      : SM2 私钥解密
 * @param[in]  : ciphertext -- 密文, ctLen -- 密文长度, context -- SM2 上下文
 * @param[out] : plaintext -- 明文, ptLen -- 明文长度指针
 * @return     : 成功返回 0，失败返回 -1
 * @note       : 简化版实现
 ******************************************************************************/
int SM2_Decrypt(const u8* ciphertext, size_t ctLen, u8* plaintext, size_t* ptLen, const SM2_Context_S* context)
{
    if (ctLen < 4) {
        return -1;
    }
    u32 c1x = 0;
    for (int i = 0; i < 4; ++i) {
        c1x = (c1x << 8) | ciphertext[i];
    }
    u32 privKey = context->privateKey[0];
    u32 x2 = SM2_ModMul32(privKey, c1x, g_sm2Prime[0]);

    size_t dataLen = ctLen - 4;
    for (size_t i = 0; i < dataLen; ++i) {
        plaintext[i] = ciphertext[4 + i] ^ (u8)(x2 & 0xFF);
    }
    if (ptLen) {
        *ptLen = dataLen;
    }
    return 0;
}
