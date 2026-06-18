/******************************************************************************
 * File Name : sha256.c
 * Function  : SHA-256 哈希算法实现 (FIPS 180-4)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <string.h>
#include "include/sha256.h"

/* SHA-256 初始哈希值 */
static const u32 g_sha256InitValues[8] = {0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL};

/* SHA-256 常数表 */
static const u32 g_sha256Constants[64] = {0x428A2F98UL, 0x71374491UL, 0xB5C0FBCFUL, 0xE9B5DBA5UL, 0x3956C25BUL, 0x59F111F1UL, 0x923F82A4UL, 0xAB1C5ED5UL,
                                          0xD807AA98UL, 0x12835B01UL, 0x243185BEUL, 0x550C7DC3UL, 0x72BE5D74UL, 0x80DEB1FEUL, 0x9BDC06A7UL, 0xC19BF174UL,
                                          0xE49B69C1UL, 0xEFBE4786UL, 0x0FC19DC6UL, 0x240CA1CCUL, 0x2DE92C6FUL, 0x4A7484AAUL, 0x5CB0A9DCUL, 0x76F988DAUL,
                                          0x983E5152UL, 0xA831C66DUL, 0xB00327C8UL, 0xBF597FC7UL, 0xC6E00BF3UL, 0xD5A79147UL, 0x06CA6351UL, 0x14292967UL,
                                          0x27B70A85UL, 0x2E1B2138UL, 0x4D2C6DFCUL, 0x53380D13UL, 0x650A7354UL, 0x766A0ABBUL, 0x81C2C92EUL, 0x92722C85UL,
                                          0xA2BFE8A1UL, 0xA81A664BUL, 0xC24B8B70UL, 0xC76C51A3UL, 0xD192E819UL, 0xD6990624UL, 0xF40E3585UL, 0x106AA070UL,
                                          0x19A4C116UL, 0x1E376C08UL, 0x2748774CUL, 0x34B0BCB5UL, 0x391C0CB3UL, 0x4ED8AA4AUL, 0x5B9CCA4FUL, 0x682E6FF3UL,
                                          0x748F82EEUL, 0x78A5636FUL, 0x84C87814UL, 0x8CC70208UL, 0x90BEFFFAUL, 0xA4506CEBUL, 0xBEF9A3F7UL, 0xC67178F2UL};

/******************************************************************************
 * @brief      : 32-bit 循环右移操作
 * @param[in]  : value -- 被移位的值, count -- 移位数
 * @param[out] : 无
 * @return     : 循环右移后的结果
 * @note       : 无
 ******************************************************************************/
static inline u32 SHA256_RightRotate(u32 value, int count)
{
    return (value >> count) | (value << (32 - count));
}

/******************************************************************************
 * @brief      : 32-bit 右移操作（不循环）
 * @param[in]  : value -- 被移位的值, count -- 移位数
 * @param[out] : 无
 * @return     : 右移后的结果
 * @note       : 无
 ******************************************************************************/
static inline u32 SHA256_RightShift(u32 value, int count)
{
    return value >> count;
}

/******************************************************************************
 * @brief      : SHA-256 主消息调度扩展函数
 * @param[in]  : scheduleWord -- 消息调度数组的前 t-16 项
 * @param[out] : 无
 * @return     : 扩展后的消息字 W[t]
 * @note       : W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
 ******************************************************************************/
static inline u32 SHA256_ScheduleExtend(const u32 scheduleWord[16], int wordIdx)
{
    u32 s0 = SHA256_RightRotate(scheduleWord[(wordIdx - 15) & 0x0F], 7) ^ SHA256_RightRotate(scheduleWord[(wordIdx - 15) & 0x0F], 18)
             ^ SHA256_RightShift(scheduleWord[(wordIdx - 15) & 0x0F], 3);
    u32 s1 = SHA256_RightRotate(scheduleWord[(wordIdx - 2) & 0x0F], 17) ^ SHA256_RightRotate(scheduleWord[(wordIdx - 2) & 0x0F], 19)
             ^ SHA256_RightShift(scheduleWord[(wordIdx - 2) & 0x0F], 10);
    return scheduleWord[(wordIdx - 16) & 0x0F] + s0 + scheduleWord[(wordIdx - 7) & 0x0F] + s1;
}

/******************************************************************************
 * @brief      : SHA-256 大 Σ1(x) 函数
 * @param[in]  : value -- 输入值
 * @param[out] : 无
 * @return     : 计算结果
 * @note       : ROTR(6,x) ^ ROTR(11,x) ^ ROTR(25,x)
 ******************************************************************************/
static inline u32 SHA256_CapitalSigma1(u32 value)
{
    return SHA256_RightRotate(value, 6) ^ SHA256_RightRotate(value, 11) ^ SHA256_RightRotate(value, 25);
}

/******************************************************************************
 * @brief      : SHA-256 大 Σ0(x) 函数
 * @param[in]  : value -- 输入值
 * @param[out] : 无
 * @return     : 计算结果
 * @note       : ROTR(2,x) ^ ROTR(13,x) ^ ROTR(22,x)
 ******************************************************************************/
static inline u32 SHA256_CapitalSigma0(u32 value)
{
    return SHA256_RightRotate(value, 2) ^ SHA256_RightRotate(value, 13) ^ SHA256_RightRotate(value, 22);
}

/******************************************************************************
 * @brief      : SHA-256 Maj 函数
 * @param[in]  : valX, valY, valZ -- 输入值
 * @param[out] : 无
 * @return     : (x & y) ^ (x & z) ^ (y & z)
 * @note       : 多数函数
 ******************************************************************************/
static inline u32 SHA256_Majority(u32 valX, u32 valY, u32 valZ)
{
    return (valX & valY) ^ (valX & valZ) ^ (valY & valZ);
}

/******************************************************************************
 * @brief      : SHA-256 Ch 函数
 * @param[in]  : valX, valY, valZ -- 输入值
 * @param[out] : 无
 * @return     : (x & y) ^ (~x & z)
 * @note       : 选择函数
 ******************************************************************************/
static inline u32 SHA256_Choose(u32 valX, u32 valY, u32 valZ)
{
    return (valX & valY) ^ (~valX & valZ);
}

/******************************************************************************
 * @brief      : 将大端字节转换为 32-bit 值
 * @param[in]  : data -- 4 字节数据指针
 * @param[out] : 无
 * @return     : 转换后的值
 * @note       : SHA-256 使用大端表示
 ******************************************************************************/
static inline u32 SHA256_BytesToWord(const u8 data[4])
{
    return (((u32)data[0]) << 24) | (((u32)data[1]) << 16) | (((u32)data[2]) << 8) | ((u32)data[3]);
}

/******************************************************************************
 * @brief      : 将 32-bit 值转换为大端字节
 * @param[in]  : value -- 输入值
 * @param[out] : data -- 4 字节输出缓冲区
 * @return     : 无
 * @note       : 用于最终摘要输出
 ******************************************************************************/
static inline void SHA256_WordToBytes(u8 data[4], u32 value)
{
    data[0] = (u8)((value >> 24) & 0xFF);
    data[1] = (u8)((value >> 16) & 0xFF);
    data[2] = (u8)((value >> 8) & 0xFF);
    data[3] = (u8)(value & 0xFF);
}

/******************************************************************************
 * @brief      : 处理单个 512-bit (64 字节) SHA-256 数据块
 * @param[in]  : blockData -- 64 字节数据块指针
 * @param[out] : context -- 被修改的 SHA-256 上下文
 * @return     : 无
 * @note       : 内部函数，执行 SHA-256 主循环 64 轮
 ******************************************************************************/
static void SHA256_ProcessBlock(const u8 blockData[64], SHA256_Context_S* context)
{
    u32 scheduleWord[16];
    for (int i = 0; i < 16; ++i) {
        scheduleWord[i] = SHA256_BytesToWord(&blockData[i * 4]);
    }

    u32 stateValues[8];
    for (int i = 0; i < 8; ++i) {
        stateValues[i] = context->state[i];
    }

    /* 64 轮主循环 */
    for (int round = 0; round < 64; ++round) {
        u32 word;
        if (round < 16) {
            word = scheduleWord[round];
        } else {
            word = SHA256_ScheduleExtend(scheduleWord, round);
            scheduleWord[round & 0x0F] = word;
        }

        u32 tempValue1 = stateValues[7] + SHA256_CapitalSigma1(stateValues[4]) + SHA256_Choose(stateValues[4], stateValues[5], stateValues[6])
                         + g_sha256Constants[round] + word;
        u32 tempValue2 = SHA256_CapitalSigma0(stateValues[0]) + SHA256_Majority(stateValues[0], stateValues[1], stateValues[2]);

        stateValues[7] = stateValues[6];
        stateValues[6] = stateValues[5];
        stateValues[5] = stateValues[4];
        stateValues[4] = stateValues[3] + tempValue1;
        stateValues[3] = stateValues[2];
        stateValues[2] = stateValues[1];
        stateValues[1] = stateValues[0];
        stateValues[0] = tempValue1 + tempValue2;
    }

    for (int i = 0; i < 8; ++i) {
        context->state[i] += stateValues[i];
    }
}

/******************************************************************************
 * @brief      : 初始化 SHA-256 计算上下文
 * @param[in]  : 无
 * @param[out] : context -- SHA-256 上下文结构体指针
 * @return     : 无
 * @note       : 必须在第一次调用 SHA256_Update 前调用
 ******************************************************************************/
void SHA256_Init(SHA256_Context_S* context)
{
    memcpy(context->state, g_sha256InitValues, sizeof(g_sha256InitValues));
    context->bitCount = 0;
    context->bufferLen = 0;
}

/******************************************************************************
 * @brief      : 处理部分数据进行 SHA-256 计算
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : context -- 被修改的 SHA-256 上下文
 * @return     : 无
 * @note       : 可多次调用，最后调用 SHA256_Final 获取结果
 ******************************************************************************/
void SHA256_Update(SHA256_Context_S* context, const u8* input, size_t inputLen)
{
    if (inputLen == 0) {
        return;
    }

    context->bitCount += inputLen * 8;

    size_t bytesToCopy = 64 - context->bufferLen;
    size_t offset = 0;

    if (inputLen >= bytesToCopy) {
        memcpy(&context->buffer[context->bufferLen], input, bytesToCopy);
        SHA256_ProcessBlock(context->buffer, context);

        for (offset = bytesToCopy; offset + 63 < inputLen; offset += 64) {
            SHA256_ProcessBlock(&input[offset], context);
        }
        context->bufferLen = 0;
    }

    memcpy(&context->buffer[context->bufferLen], &input[offset], inputLen - offset);
    context->bufferLen += inputLen - offset;
}

/******************************************************************************
 * @brief      : 结束 SHA-256 计算并输出 256-bit 摘要
 * @param[in]  : context -- 已处理数据的 SHA-256 上下文
 * @param[out] : digest -- 接收 32 字节 SHA-256 摘要的缓冲区
 * @return     : 无
 * @note       : 调用后 context 不可再用于 Update，需重新 Init
 ******************************************************************************/
void SHA256_Final(u8 digest[32], SHA256_Context_S* context)
{
    u64 bitCountBig = context->bitCount;
    u8 paddingByte = 0x80;
    SHA256_Update(context, &paddingByte, 1);

    while (context->bufferLen != 56) {
        paddingByte = 0x00;
        SHA256_Update(context, &paddingByte, 1);
    }

    u8 lengthBytes[8];
    for (int i = 7; i >= 0; --i) {
        lengthBytes[i] = (u8)(bitCountBig & 0xFF);
        bitCountBig >>= 8;
    }
    SHA256_Update(context, lengthBytes, 8);

    for (int i = 0; i < 8; ++i) {
        SHA256_WordToBytes(&digest[i * 4], context->state[i]);
    }
}

/******************************************************************************
 * @brief      : 一步计算 SHA-256 摘要
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : digest -- 接收 32 字节 SHA-256 摘要的缓冲区
 * @return     : 无
 * @note       : 对于短消息或不需要分块处理的场景
 ******************************************************************************/
void SHA256_Hash(const u8* input, size_t inputLen, u8 digest[32])
{
    SHA256_Context_S context;
    SHA256_Init(&context);
    SHA256_Update(&context, input, inputLen);
    SHA256_Final(digest, &context);
}
