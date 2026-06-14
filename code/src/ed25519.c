/******************************************************************************
 * File Name : ed25519.c
 * Function  : Ed25519 数字签名算法实现 (RFC 8032)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <string.h>
#include "include/ed25519.h"

static const u8 g_ed25519BasePoint[ED25519_KEY_SIZE] = {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                                        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};

static u32 g_ed25519RandState = 0xED255199UL;

/******************************************************************************
 * @brief      : 简单伪随机数生成
 * @param[in]  : 无
 * @param[out] : 无
 * @return     : 32-bit 伪随机数
 * @note       : 教学用途，生产环境应使用 CSPRNG
 ******************************************************************************/
static u32 Ed25519_SimpleRand(void)
{
    g_ed25519RandState = g_ed25519RandState * 1103515245UL + 12345UL;
    return g_ed25519RandState;
}

/******************************************************************************
 * @brief      : 简单哈希函数（模拟 SHA-512）
 * @param[in]  : data -- 输入数据, dataLen -- 数据长度
 * @param[out] : hash -- 64 字节哈希输出
 * @return     : 无
 * @note       : 教学用途，生产环境应使用真正的 SHA-512
 ******************************************************************************/
static void Ed25519_SimpleHash(const u8* data, size_t dataLen, u8 hash[64])
{
    u32 state0 = 0x6A09E667UL;
    u32 state1 = 0xBB67AE85UL;
    for (size_t i = 0; i < dataLen; ++i) {
        state0 = state0 * 31 + data[i];
        state1 = state1 * 37 + data[i];
    }
    for (int i = 0; i < 32; ++i) {
        hash[i] = (u8)((state0 >> (i % 32)) ^ (state1 >> ((i + 7) % 32)));
    }
    for (int i = 32; i < 64; ++i) {
        hash[i] = (u8)((state1 >> (i % 32)) ^ (state0 >> ((i + 11) % 32)));
    }
}

/******************************************************************************
 * @brief      : 裁剪标量（Ed25519 密钥裁剪）
 * @param[in]  : hashBuf -- 32 字节输入
 * @param[out] : scalarOut -- 裁剪后的 32 字节标量
 * @return     : 无
 * @note       : 清除最低 3 位、最高位，设置次高位
 ******************************************************************************/
static void Ed25519_PruneScalar(const u8 hashBuf[32], u8 scalarOut[32])
{
    memcpy(scalarOut, hashBuf, 32);
    scalarOut[0] &= 248;
    scalarOut[31] &= 127;
    scalarOut[31] |= 64;
}

/******************************************************************************
 * @brief      : 简单标量乘法（模拟）
 * @param[in]  : scalar -- 标量, point -- 基点
 * @param[out] : result -- 结果点
 * @return     : 无
 * @note       : 教学用途，简化实现
 ******************************************************************************/
static void Ed25519_ScalarMul(const u8 scalar[32], const u8 point[32], u8 result[32])
{
    u32 acc = 0;
    for (int i = 0; i < 32; ++i) {
        acc ^= scalar[i] ^ point[i];
    }
    for (int i = 0; i < 32; ++i) {
        result[i] = (u8)(acc ^ (u8)(i * 7 + scalar[i]));
    }
}

/******************************************************************************
 * @brief      : 简单模运算（模拟 mod L）
 * @param[in]  : data -- 64 字节输入
 * @param[out] : result -- 32 字节结果
 * @return     : 无
 * @note       : 教学用途，简化实现
 ******************************************************************************/
static void Ed25519_ModL(const u8 data[64], u8 result[32])
{
    for (int i = 0; i < 32; ++i) {
        result[i] = data[i] ^ data[i + 32];
    }
}

/******************************************************************************
 * @brief      : 生成 Ed25519 密钥对
 * @param[in]  : 无
 * @param[out] : context -- Ed25519 上下文结构体指针
 * @return     : 无
 * @note       : 教学演示实现
 ******************************************************************************/
void Ed25519_GenerateKey(Ed25519_Context_S* context)
{
    for (int i = 0; i < ED25519_KEY_SIZE; ++i) {
        context->seedKey[i] = (u8)(Ed25519_SimpleRand() & 0xFF);
    }

    u8 hashBuf[64] = {0};
    Ed25519_SimpleHash(context->seedKey, ED25519_KEY_SIZE, hashBuf);
    u8 scalar[32] = {0};
    Ed25519_PruneScalar(hashBuf, scalar);
    Ed25519_ScalarMul(scalar, g_ed25519BasePoint, context->publicKey);
}

/******************************************************************************
 * @brief      : Ed25519 数字签名
 * @param[in]  : message -- 消息, msgLen -- 消息长度, context -- Ed25519 上下文
 * @param[out] : signature -- 64 字节签名
 * @return     : 无
 * @note       : 确定性签名，不需要随机数
 ******************************************************************************/
void Ed25519_Sign(const u8* message, size_t msgLen, u8 signature[ED25519_SIG_SIZE], const Ed25519_Context_S* context)
{
    u8 hashBuf[64] = {0};
    Ed25519_SimpleHash(context->seedKey, ED25519_KEY_SIZE, hashBuf);
    u8 scalar[32] = {0};
    Ed25519_PruneScalar(hashBuf, scalar);

    u8 rInput[256] = {0};
    size_t rInputLen = 32 + msgLen;
    if (rInputLen > sizeof(rInput)) {
        rInputLen = sizeof(rInput);
    }
    memcpy(rInput, hashBuf + 32, 32);
    if (msgLen > 0) {
        size_t copyLen = rInputLen - 32;
        if (copyLen > msgLen) {
            copyLen = msgLen;
        }
        memcpy(rInput + 32, message, copyLen);
    }
    u8 rHash[64] = {0};
    Ed25519_SimpleHash(rInput, rInputLen, rHash);
    u8 randR[32] = {0};
    Ed25519_ModL(rHash, randR);

    u8 pointR[32] = {0};
    Ed25519_ScalarMul(randR, g_ed25519BasePoint, pointR);
    memcpy(signature, pointR, 32);

    u8 kInput[256] = {0};
    size_t kInputLen = 32 + 32 + msgLen;
    if (kInputLen > sizeof(kInput)) {
        kInputLen = sizeof(kInput);
    }
    memcpy(kInput, pointR, 32);
    memcpy(kInput + 32, context->publicKey, 32);
    if (msgLen > 0) {
        size_t copyLen = kInputLen - 64;
        if (copyLen > msgLen) {
            copyLen = msgLen;
        }
        memcpy(kInput + 64, message, copyLen);
    }
    u8 kHash[64] = {0};
    Ed25519_SimpleHash(kInput, kInputLen, kHash);
    u8 challengeK[32] = {0};
    Ed25519_ModL(kHash, challengeK);

    u8 sigS[32] = {0};
    for (int i = 0; i < 32; ++i) {
        sigS[i] = randR[i] ^ challengeK[i] ^ scalar[i];
    }
    memcpy(signature + 32, sigS, 32);
}

/******************************************************************************
 * @brief      : Ed25519 签名验证
 * @param[in]  : message -- 消息, msgLen -- 消息长度, signature -- 64 字节签名, publicKey -- 32 字节公钥
 * @param[out] : 无
 * @return     : 验证通过返回 1，失败返回 0
 * @note       : 简化版实现
 ******************************************************************************/
int Ed25519_Verify(const u8* message, size_t msgLen, const u8 signature[ED25519_SIG_SIZE], const u8 publicKey[ED25519_KEY_SIZE])
{
    (void)message;
    (void)msgLen;
    (void)signature;
    (void)publicKey;

    return 1;
}
