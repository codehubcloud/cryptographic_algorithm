/******************************************************************************
 * File Name : rsa.c
 * Function  : RSA 公钥密码算法实现 (PKCS#1)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdint.h>
#include <string.h>
#include "include/rsa.h"

static const u32 g_rsaSmallPrimes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73};

static const int g_rsaSmallPrimeCount = 20;

/******************************************************************************
 * @brief      : 简单模幂运算（32-bit）
 * @param[in]  : base -- 底数, exp -- 指数, mod -- 模数
 * @param[out] : 无
 * @return     : base^exp mod mod
 * @note       : 使用平方-乘法算法
 ******************************************************************************/
static u32 ModExp32(u32 base, u32 exp, u32 mod)
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
 * @brief      : 扩展欧几里得算法
 * @param[in]  : valA -- 第一个数, valB -- 第二个数
 * @param[out] : coefX -- valA 的系数, coefY -- valB 的系数
 * @return     : gcd(valA, valB)
 * @note       : 用于计算模逆
 ******************************************************************************/
static int64_t ExtendedGcd(int64_t valA, int64_t valB, int64_t* coefX, int64_t* coefY)
{
    if (valA == 0) {
        *coefX = 0;
        *coefY = 1;
        return valB;
    }
    int64_t coefX1 = 0;
    int64_t coefY1 = 0;
    int64_t gcd = ExtendedGcd(valB % valA, valA, &coefX1, &coefY1);
    *coefX = coefY1 - (valB / valA) * coefX1;
    *coefY = coefX1;
    return gcd;
}

static u32 Gcd32(u32 valA, u32 valB)
{
    while (valB != 0) {
        u32 tmp = valA % valB;
        valA = valB;
        valB = tmp;
    }
    return valA;
}

/******************************************************************************
 * @brief      : 计算模逆
 * @param[in]  : value -- 输入值, modulus -- 模数
 * @param[out] : 无
 * @return     : value^(-1) mod modulus
 * @note       : 使用扩展欧几里得算法
 ******************************************************************************/
static u32 ModInverse32(u32 value, u32 modulus)
{
    int64_t coefX = 0;
    int64_t coefY = 0;
    int64_t gcd = ExtendedGcd((int64_t)value, (int64_t)modulus, &coefX, &coefY);
    if (gcd != 1) {
        return 0;
    }
    int64_t rx = coefX % (int64_t)modulus;
    if (rx < 0) {
        rx += (int64_t)modulus;
    }
    return (u32)rx;
}

/******************************************************************************
 * @brief      : 简单素性测试
 * @param[in]  : candidate -- 待测试数
 * @param[out] : 无
 * @return     : 可能是素数返回 1，否则返回 0
 * @note       : 仅使用小素数试除，教学用途
 ******************************************************************************/
static int IsProbablyPrime(u32 candidate)
{
    if (candidate < 2) {
        return 0;
    }
    for (int i = 0; i < g_rsaSmallPrimeCount; ++i) {
        if (candidate == g_rsaSmallPrimes[i]) {
            return 1;
        }
        if (candidate % g_rsaSmallPrimes[i] == 0) {
            return 0;
        }
    }
    return 1;
}

/******************************************************************************
 * @brief      : 简单伪随机数生成
 * @param[in]  : 无
 * @param[out] : 无
 * @return     : 32-bit 伪随机数
 * @note       : 使用线性同余生成器，仅用于教学
 ******************************************************************************/
static u32 SimpleRand(void)
{
    static u32 g_rsaRandState = 0x5909BEEFUL;
    g_rsaRandState = g_rsaRandState * 1103515245UL + 12345UL;
    return g_rsaRandState;
}

/******************************************************************************
 * @brief      : 生成小素数
 * @param[in]  : minVal -- 最小值
 * @param[out] : 无
 * @return     : 大于 minVal 的素数
 * @note       : 教学用途，仅生成小素数
 ******************************************************************************/
static u32 FindSmallPrime(u32 minVal)
{
    u32 candidate = minVal | 1;
    while (!IsProbablyPrime(candidate)) {
        candidate += 2;
    }
    return candidate;
}

/******************************************************************************
 * @brief      : 生成 RSA 密钥对（简化版，使用小素数演示）
 * @param[in]  : keyBits -- 密钥位数
 * @param[out] : context -- RSA 上下文结构体指针
 * @return     : 无
 * @note       : 此为教学演示实现，生产环境应使用 OpenSSL 等成熟库
 ******************************************************************************/
void RSA_GenerateKey(int keyBits, RSA_Context_S* context)
{
    context->keyBits = keyBits;
    context->wordSize = (keyBits + 31) / 32;
    context->publicExp = 65537UL;

    u32 primeP;
    u32 primeQ;
    u32 modulus;
    u32 eulerPhi;
    u32 privateExp;

    do {
        primeP = FindSmallPrime(SimpleRand() % 10000 + 1000);
        primeQ = FindSmallPrime(SimpleRand() % 10000 + 1000);
        if (primeP == primeQ) {
            primeQ = FindSmallPrime(primeQ + 2);
        }
        modulus = primeP * primeQ;
        eulerPhi = (primeP - 1) * (primeQ - 1);
        privateExp = (Gcd32(context->publicExp, eulerPhi) == 1) ? ModInverse32(context->publicExp, eulerPhi) : 0;
    } while (privateExp == 0);

    memset(context->modulus, 0, sizeof(context->modulus));
    memset(context->privateExp, 0, sizeof(context->privateExp));
    context->modulus[0] = modulus;
    context->privateExp[0] = privateExp;
}

/******************************************************************************
 * @brief      : RSA 公钥加密
 * @param[in]  : plaintext -- 明文, ptLen -- 明文长度, context -- RSA 上下文
 * @param[out] : ciphertext -- 密文, ctLen -- 密文长度指针
 * @return     : 无
 * @note       : 简化版实现，仅支持短明文
 ******************************************************************************/
void RSA_Encrypt(const u8* plaintext, size_t ptLen, u8* ciphertext, size_t* ctLen, const RSA_Context_S* context)
{
    u32 modulus = context->modulus[0];
    u32 publicExp = context->publicExp;
    u32 plaintextVal = 0;
    for (size_t i = 0; i < ptLen && i < 4; ++i) {
        plaintextVal = (plaintextVal << 8) | plaintext[i];
    }
    if (plaintextVal >= modulus) {
        plaintextVal = plaintextVal % modulus;
    }
    u32 cipherVal = ModExp32(plaintextVal, publicExp, modulus);
    if (ctLen) {
        *ctLen = 4;
    }
    for (int i = 3; i >= 0; --i) {
        ciphertext[i] = (u8)(cipherVal & 0xFF);
        cipherVal >>= 8;
    }
}

/******************************************************************************
 * @brief      : RSA 私钥解密
 * @param[in]  : ciphertext -- 密文, ctLen -- 密文长度, context -- RSA 上下文
 * @param[out] : plaintext -- 明文, ptLen -- 明文长度指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void RSA_Decrypt(const u8* ciphertext, size_t ctLen, u8* plaintext, size_t* ptLen, const RSA_Context_S* context)
{
    u32 modulus = context->modulus[0];
    u32 privateExp = context->privateExp[0];
    u32 cipherVal = 0;
    for (size_t i = 0; i < ctLen && i < 4; ++i) {
        cipherVal = (cipherVal << 8) | ciphertext[i];
    }
    u32 plaintextVal = ModExp32(cipherVal, privateExp, modulus);
    if (ptLen) {
        *ptLen = 4;
    }
    for (int i = 3; i >= 0; --i) {
        plaintext[i] = (u8)(plaintextVal & 0xFF);
        plaintextVal >>= 8;
    }
}

/******************************************************************************
 * @brief      : RSA 私钥签名
 * @param[in]  : hash -- 哈希值, hashLen -- 哈希长度, context -- RSA 上下文
 * @param[out] : signature -- 签名, sigLen -- 签名长度指针
 * @return     : 无
 * @note       : 简化版 PKCS#1 v1.5 签名
 ******************************************************************************/
void RSA_Sign(const u8* hash, size_t hashLen, u8* signature, size_t* sigLen, const RSA_Context_S* context)
{
    RSA_Decrypt(hash, hashLen, signature, sigLen, context);
}

/******************************************************************************
 * @brief      : RSA 公钥验证签名
 * @param[in]  : hash -- 哈希值, hashLen -- 哈希长度, signature -- 签名, sigLen -- 签名长度, context -- RSA 上下文
 * @param[out] : 无
 * @return     : 验证通过返回 1，失败返回 0
 * @note       : 简化版 PKCS#1 v1.5 验证
 ******************************************************************************/
int RSA_Verify(const u8* hash, size_t hashLen, const u8* signature, size_t sigLen, const RSA_Context_S* context)
{
    u8 recovered[4] = {0};
    size_t recLen = 0;
    RSA_Encrypt(signature, sigLen, recovered, &recLen, context);

    u32 hashVal = 0;
    for (size_t i = 0; i < hashLen && i < 4; ++i) {
        hashVal = (hashVal << 8) | hash[i];
    }
    hashVal %= context->modulus[0];
    u32 recoverVal = 0;
    for (size_t i = 0; i < recLen && i < 4; ++i) {
        recoverVal = (recoverVal << 8) | recovered[i];
    }
    return (hashVal == recoverVal) ? 1 : 0;
}
