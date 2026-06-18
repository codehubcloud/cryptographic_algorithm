/******************************************************************************
 * File Name : sha512.c
 * Function  : SHA-512 哈希算法实现 (FIPS 180-4)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <string.h>
#include "include/sha512.h"

/* SHA-512 初始哈希值 */
static const u64 g_sha512InitValues[8] = {0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
                                          0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL};

/* SHA-512 常数表 (前 80 项) */
static const u64 g_sha512Constants[80] = {0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL, 0x3956C25BF348B538ULL,
                                          0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL, 0xD807AA98A3030242ULL, 0x12835B0145706FBEULL,
                                          0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL, 0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL,
                                          0xC19BF174CF692694ULL, 0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
                                          0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL, 0x983E5152EE66DFABULL,
                                          0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL, 0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,
                                          0x06CA6351E003826FULL, 0x142929670A0E6E70ULL, 0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL,
                                          0x53380D139D95B3DFULL, 0x650A73548BAF63DEULL, 0x766A0EBB3C3A8A3CULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
                                          0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL,
                                          0xD69906245565A910ULL, 0xF40E3585771A0393ULL, 0x106AA07032BBD1B8ULL, 0x19A4C116B8D2D0C8ULL, 0x1E376C082DCC7021ULL,
                                          0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL, 0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL,
                                          0x682E6FF3D6B2B8A3ULL, 0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
                                          0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL, 0xCA273ECEEA26619CULL,
                                          0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL, 0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL,
                                          0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL, 0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL,
                                          0x431D67C49C100D4CULL, 0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL};

/******************************************************************************
 * @brief      : 64-bit 循环右移操作
 * @param[in]  : value -- 被移位的值, count -- 移位数
 * @param[out] : 无
 * @return     : 循环右移后的结果
 * @note       : 无
 ******************************************************************************/
static inline u64 SHA512_RightRotate(u64 value, int count)
{
    return (value >> count) | (value << (64 - count));
}

/******************************************************************************
 * @brief      : 64-bit 右移操作（不循环）
 * @param[in]  : value -- 被移位的值, count -- 移位数
 * @param[out] : 无
 * @return     : 右移后的结果
 * @note       : 无
 ******************************************************************************/
static inline u64 SHA512_RightShift(u64 value, int count)
{
    return value >> count;
}

/******************************************************************************
 * @brief      : 将大端字节转换为 64-bit 值
 * @param[in]  : data -- 8 字节数据指针
 * @param[out] : 无
 * @return     : 转换后的值
 * @note       : SHA-512 使用大端表示
 ******************************************************************************/
static inline u64 SHA512_BytesToWord(const u8 data[8])
{
    return (((u64)data[0]) << 56) | (((u64)data[1]) << 48) | (((u64)data[2]) << 40) | (((u64)data[3]) << 32) | (((u64)data[4]) << 24) | (((u64)data[5]) << 16)
           | (((u64)data[6]) << 8) | ((u64)data[7]);
}

/******************************************************************************
 * @brief      : 将 64-bit 值转换为大端字节
 * @param[in]  : value -- 输入值
 * @param[out] : data -- 8 字节输出缓冲区
 * @return     : 无
 * @note       : 用于最终摘要输出
 ******************************************************************************/
static inline void SHA512_WordToBytes(u8 data[8], u64 value)
{
    data[0] = (u8)((value >> 56) & 0xFF);
    data[1] = (u8)((value >> 48) & 0xFF);
    data[2] = (u8)((value >> 40) & 0xFF);
    data[3] = (u8)((value >> 32) & 0xFF);
    data[4] = (u8)((value >> 24) & 0xFF);
    data[5] = (u8)((value >> 16) & 0xFF);
    data[6] = (u8)((value >> 8) & 0xFF);
    data[7] = (u8)(value & 0xFF);
}

/******************************************************************************
 * @brief      : SHA-512 大 Σ1(x) 函数
 * @param[in]  : value -- 输入值
 * @param[out] : 无
 * @return     : 计算结果
 * @note       : ROTR(14,x) ^ ROTR(18,x) ^ ROTR(41,x)
 ******************************************************************************/
static inline u64 SHA512_CapitalSigma1(u64 value)
{
    return SHA512_RightRotate(value, 14) ^ SHA512_RightRotate(value, 18) ^ SHA512_RightRotate(value, 41);
}

/******************************************************************************
 * @brief      : SHA-512 大 Σ0(x) 函数
 * @param[in]  : value -- 输入值
 * @param[out] : 无
 * @return     : 计算结果
 * @note       : ROTR(28,x) ^ ROTR(34,x) ^ ROTR(39,x)
 ******************************************************************************/
static inline u64 SHA512_CapitalSigma0(u64 value)
{
    return SHA512_RightRotate(value, 28) ^ SHA512_RightRotate(value, 34) ^ SHA512_RightRotate(value, 39);
}

/******************************************************************************
 * @brief      : SHA-512 Maj 函数
 * @param[in]  : valX, valY, valZ -- 输入值
 * @param[out] : 无
 * @return     : (x & y) ^ (x & z) ^ (y & z)
 * @note       : 多数函数
 ******************************************************************************/
static inline u64 SHA512_Majority(u64 valX, u64 valY, u64 valZ)
{
    return (valX & valY) ^ (valX & valZ) ^ (valY & valZ);
}

/******************************************************************************
 * @brief      : SHA-512 Ch 函数
 * @param[in]  : valX, valY, valZ -- 输入值
 * @param[out] : 无
 * @return     : (x & y) ^ (~x & z)
 * @note       : 选择函数
 ******************************************************************************/
static inline u64 SHA512_Choose(u64 valX, u64 valY, u64 valZ)
{
    return (valX & valY) ^ (~valX & valZ);
}

/******************************************************************************
 * @brief      : 处理单个 1024-bit (128 字节) SHA-512 数据块
 * @param[in]  : blockData -- 128 字节数据块指针
 * @param[out] : context -- 被修改的 SHA-512 上下文
 * @return     : 无
 * @note       : 内部函数，执行 SHA-512 主循环 80 轮
 ******************************************************************************/
static void SHA512_ProcessBlock(const u8 blockData[128], SHA512_Context_S* context)
{
    u64 scheduleWord[16];
    for (int i = 0; i < 16; ++i) {
        scheduleWord[i] = SHA512_BytesToWord(&blockData[i * 8]);
    }

    u64 stateValues[8];
    for (int i = 0; i < 8; ++i) {
        stateValues[i] = context->state[i];
    }

    /* 80 轮主循环 */
    for (int round = 0; round < 80; ++round) {
        u64 word;
        if (round < 16) {
            word = scheduleWord[round];
        } else {
            u64 s0 = SHA512_RightRotate(scheduleWord[(round - 15) & 0x0F], 1) ^ SHA512_RightRotate(scheduleWord[(round - 15) & 0x0F], 8)
                     ^ SHA512_RightShift(scheduleWord[(round - 15) & 0x0F], 7);
            u64 s1 = SHA512_RightRotate(scheduleWord[(round - 2) & 0x0F], 19) ^ SHA512_RightRotate(scheduleWord[(round - 2) & 0x0F], 61)
                     ^ SHA512_RightShift(scheduleWord[(round - 2) & 0x0F], 6);
            word = scheduleWord[(round - 16) & 0x0F] + s0 + scheduleWord[(round - 7) & 0x0F] + s1;
            scheduleWord[round & 0x0F] = word;
        }

        u64 tempValue1 = stateValues[7] + SHA512_CapitalSigma1(stateValues[4]) + SHA512_Choose(stateValues[4], stateValues[5], stateValues[6])
                         + g_sha512Constants[round] + word;
        u64 tempValue2 = SHA512_CapitalSigma0(stateValues[0]) + SHA512_Majority(stateValues[0], stateValues[1], stateValues[2]);

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
 * @brief      : 初始化 SHA-512 计算上下文
 * @param[in]  : 无
 * @param[out] : context -- SHA-512 上下文结构体指针
 * @return     : 无
 * @note       : 必须在第一次调用 SHA512_Update 前调用
 ******************************************************************************/
void SHA512_Init(SHA512_Context_S* context)
{
    memcpy(context->state, g_sha512InitValues, sizeof(g_sha512InitValues));
    context->bitCount[0] = 0;
    context->bitCount[1] = 0;
    context->bufferLen = 0;
}

/******************************************************************************
 * @brief      : 处理部分数据进行 SHA-512 计算
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : context -- 被修改的 SHA-512 上下文
 * @return     : 无
 * @note       : 可多次调用，最后调用 SHA512_Final 获取结果
 ******************************************************************************/
void SHA512_Update(SHA512_Context_S* context, const u8* input, size_t inputLen)
{
    if (inputLen == 0) {
        return;
    }

    u64 lowBits = (u64)inputLen << 3;
    u64 highBits = (u64)inputLen >> 61;

    if (context->bitCount[0] + lowBits < context->bitCount[0]) {
        context->bitCount[1]++;
    }
    context->bitCount[0] += lowBits;
    context->bitCount[1] += highBits;

    size_t bytesToCopy = 128 - context->bufferLen;
    size_t offset = 0;

    if (inputLen >= bytesToCopy) {
        memcpy(&context->buffer[context->bufferLen], input, bytesToCopy);
        SHA512_ProcessBlock(context->buffer, context);

        for (offset = bytesToCopy; offset + 127 < inputLen; offset += 128) {
            SHA512_ProcessBlock(&input[offset], context);
        }
        context->bufferLen = 0;
    }

    memcpy(&context->buffer[context->bufferLen], &input[offset], inputLen - offset);
    context->bufferLen += inputLen - offset;
}

/******************************************************************************
 * @brief      : 结束 SHA-512 计算并输出 512-bit 摘要
 * @param[in]  : context -- 已处理数据的 SHA-512 上下文
 * @param[out] : digest -- 接收 64 字节 SHA-512 摘要的缓冲区
 * @return     : 无
 * @note       : 调用后 context 不可再用于 Update，需重新 Init
 ******************************************************************************/
void SHA512_Final(u8 digest[64], SHA512_Context_S* context)
{
    u64 highBitCount = context->bitCount[1];
    u64 lowBitCount = context->bitCount[0];

    u8 paddingByte = 0x80;
    SHA512_Update(context, &paddingByte, 1);

    while (context->bufferLen != 112) {
        paddingByte = 0x00;
        SHA512_Update(context, &paddingByte, 1);
    }

    u8 lengthBytes[16];
    lengthBytes[0] = (u8)((highBitCount >> 56) & 0xFF);
    lengthBytes[1] = (u8)((highBitCount >> 48) & 0xFF);
    lengthBytes[2] = (u8)((highBitCount >> 40) & 0xFF);
    lengthBytes[3] = (u8)((highBitCount >> 32) & 0xFF);
    lengthBytes[4] = (u8)((highBitCount >> 24) & 0xFF);
    lengthBytes[5] = (u8)((highBitCount >> 16) & 0xFF);
    lengthBytes[6] = (u8)((highBitCount >> 8) & 0xFF);
    lengthBytes[7] = (u8)(highBitCount & 0xFF);
    lengthBytes[8] = (u8)((lowBitCount >> 56) & 0xFF);
    lengthBytes[9] = (u8)((lowBitCount >> 48) & 0xFF);
    lengthBytes[10] = (u8)((lowBitCount >> 40) & 0xFF);
    lengthBytes[11] = (u8)((lowBitCount >> 32) & 0xFF);
    lengthBytes[12] = (u8)((lowBitCount >> 24) & 0xFF);
    lengthBytes[13] = (u8)((lowBitCount >> 16) & 0xFF);
    lengthBytes[14] = (u8)((lowBitCount >> 8) & 0xFF);
    lengthBytes[15] = (u8)(lowBitCount & 0xFF);

    SHA512_Update(context, lengthBytes, 16);

    for (int i = 0; i < 8; ++i) {
        SHA512_WordToBytes(&digest[i * 8], context->state[i]);
    }
}

/******************************************************************************
 * @brief      : 一步计算 SHA-512 摘要
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : digest -- 接收 64 字节 SHA-512 摘要的缓冲区
 * @return     : 无
 * @note       : 对于短消息或不需要分块处理的场景
 ******************************************************************************/
void SHA512_Hash(const u8* input, size_t inputLen, u8 digest[64])
{
    SHA512_Context_S context;
    SHA512_Init(&context);
    SHA512_Update(&context, input, inputLen);
    SHA512_Final(digest, &context);
}
