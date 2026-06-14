/******************************************************************************
 * File Name : md5.c
 * Function  : MD5 哈希算法实现 (RFC 1321)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <string.h>
#include "include/md5.h"

/* MD5 初始状态值 */
static const u32 g_md5InitA = 0x67452301UL;
static const u32 g_md5InitB = 0xEFCDAB89UL;
static const u32 g_md5InitC = (u32)0x98BADCFEUL;
static const u32 g_md5InitD = 0x10325476UL;

/* MD5 正弦表（第 i 项值为 floor(2^32 * abs(sin(i+1)))）*/
static const u32 g_md5SineTable[64] = {0xD76AA478UL, 0xE8C7B756UL, 0x242070DBUL, 0xC1BDCEEEUL, 0xF57C0FAFUL, 0x4787C62AUL, 0xA8304613UL, 0xFD469501UL,
                                       0x698098D8UL, 0x8B44F7AFUL, 0xFFFF5BB1UL, 0x895CD7BEUL, 0x6B901122UL, 0xFD987193UL, 0xA679438EUL, 0x49B40821UL,
                                       0xF61E2562UL, 0xC040B340UL, 0x265E5A51UL, 0xE9B6C7AAUL, 0xD62F105DUL, 0x02441453UL, 0xD8A1E681UL, 0xE7D3FBC8UL,
                                       0x21E1CDE6UL, 0xC33707D6UL, 0xF4D50D87UL, 0x455A14EDUL, 0xA9E3E905UL, 0xFCEFA3F8UL, 0x676F02D9UL, 0x8D2A4C8AUL,
                                       0xFFFA3942UL, 0x8771F681UL, 0x6D9D6122UL, 0xFDE5380CUL, 0xA4BEEA44UL, 0x4BDECFA9UL, 0xF6BB4B60UL, 0xBEBFBC70UL,
                                       0x289B7EC6UL, 0xEAA127FAUL, 0xD4EF3085UL, 0x04881D05UL, 0xD9D4D039UL, 0xE6DB99E5UL, 0x1FA27CF8UL, 0xC4AC5665UL,
                                       0xF4292244UL, 0x432AFF97UL, 0xAB9423A7UL, 0xFC93A039UL, 0x655B59C3UL, 0x8F0CCC92UL, 0xFFEFF47DUL, 0x85845DD1UL,
                                       0x6FA87E4FUL, 0xFE2CE6E0UL, 0xA3014314UL, 0x4E0811A1UL, 0xF7537E82UL, 0xBD3AF235UL, 0x2AD7D2BBUL, 0xEB86D391UL};

/* MD5 轮次中的 k 索引（指示消息字块 X[k]）*/
static const int g_md5RoundIndices[64] = {0, 1, 2,  3,  4, 5, 6, 7,  8,  9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5,  10, 15, 4, 9, 14, 3, 8,  13, 2,  7, 12,
                                          5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3,  6,  9,  12, 15, 2,  0, 7, 14, 5, 12, 3,  10, 1, 8, 15, 6, 13, 4,  11, 2, 9};

/* MD5 移位计数表 */
static const int g_md5ShiftCounts[64] = {7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 5,  9,  14, 20, 5,  9,
                                         14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23,
                                         4,  11, 16, 23, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21};

/******************************************************************************
 * @brief      : 32-bit 循环左移操作
 * @param[in]  : value -- 被移位的值, count -- 移位数
 * @param[out] : 无
 * @return     : 循环左移后的结果
 * @note       : 无
 ******************************************************************************/
static inline u32 MD5_LeftRotate(u32 value, int count)
{
    return (value << count) | (value >> (32 - count));
}

/******************************************************************************
 * @brief      : MD5 辅助函数 F(X,Y,Z) = (X & Y) | (~X & Z)
 * @param[in]  : valX, valY, valZ -- 输入值
 * @param[out] : 无
 * @return     : 计算结果
 * @note       : 第 0-15 轮使用
 ******************************************************************************/
static inline u32 MD5_F(u32 valX, u32 valY, u32 valZ)
{
    return (valX & valY) | (~valX & valZ);
}

/******************************************************************************
 * @brief      : MD5 辅助函数 G(X,Y,Z) = (X & Z) | (Y & ~Z)
 * @param[in]  : valX, valY, valZ -- 输入值
 * @param[out] : 无
 * @return     : 计算结果
 * @note       : 第 16-31 轮使用
 ******************************************************************************/
static inline u32 MD5_G(u32 valX, u32 valY, u32 valZ)
{
    return (valX & valZ) | (valY & ~valZ);
}

/******************************************************************************
 * @brief      : MD5 辅助函数 H(X,Y,Z) = X ^ Y ^ Z
 * @param[in]  : valX, valY, valZ -- 输入值
 * @param[out] : 无
 * @return     : 计算结果
 * @note       : 第 32-47 轮使用
 ******************************************************************************/
static inline u32 MD5_H(u32 valX, u32 valY, u32 valZ)
{
    return valX ^ valY ^ valZ;
}

/******************************************************************************
 * @brief      : MD5 辅助函数 I(X,Y,Z) = Y ^ (X | ~Z)
 * @param[in]  : valX, valY, valZ -- 输入值
 * @param[out] : 无
 * @return     : 计算结果
 * @note       : 第 48-63 轮使用
 ******************************************************************************/
static inline u32 MD5_I(u32 valX, u32 valY, u32 valZ)
{
    return valY ^ (valX | ~valZ);
}

/******************************************************************************
 * @brief      : 将小端 32-bit 值数组转换为大端表示（用于初始化）
 * @param[in]  : input -- 输入缓冲区 (4 字节)
 * @param[out] : 无
 * @return     : 转换后的 32-bit 值
 * @note       : MD5 使用小端表示
 ******************************************************************************/
static inline u32 MD5_BytesToWord(const u8 input[4])
{
    return ((u32)input[0]) | (((u32)input[1]) << 8) | (((u32)input[2]) << 16) | (((u32)input[3]) << 24);
}

/******************************************************************************
 * @brief      : 将 32-bit 值转换为小端字节数组
 * @param[in]  : value -- 输入值
 * @param[out] : output -- 输出缓冲区 (4 字节)
 * @return     : 无
 * @note       : 用于最终摘要输出
 ******************************************************************************/
static inline void MD5_WordToBytes(u8 output[4], u32 value)
{
    output[0] = (u8)(value & 0xFF);
    output[1] = (u8)((value >> 8) & 0xFF);
    output[2] = (u8)((value >> 16) & 0xFF);
    output[3] = (u8)((value >> 24) & 0xFF);
}

/******************************************************************************
 * @brief      : 处理单个 512-bit (64 字节) MD5 数据块
 * @param[in]  : data -- 64 字节数据块指针
 * @param[out] : context -- 被修改的 MD5 上下文
 * @return     : 无
 * @note       : 内部函数，执行 MD5 主循环 64 轮
 ******************************************************************************/
static void MD5_ProcessBlock(u8 data[64], MD5_Context_S* context)
{
    u32 msgWord[16];
    for (int i = 0; i < 16; ++i) {
        msgWord[i] = MD5_BytesToWord(&data[i * 4]);
    }

    u32 stateA = context->state[0];
    u32 stateB = context->state[1];
    u32 stateC = context->state[2];
    u32 stateD = context->state[3];

    /* 64 轮主循环 */
    for (int round = 0; round < 64; ++round) {
        u32 tempValue;
        int shiftCount = g_md5ShiftCounts[round];
        int roundIndex = g_md5RoundIndices[round];

        if (round < 16) {
            tempValue = MD5_F(stateB, stateC, stateD);
        } else if (round < 32) {
            tempValue = MD5_G(stateB, stateC, stateD);
        } else if (round < 48) {
            tempValue = MD5_H(stateB, stateC, stateD);
        } else {
            tempValue = MD5_I(stateB, stateC, stateD);
        }

        tempValue = stateA + tempValue + g_md5SineTable[round] + msgWord[roundIndex];
        tempValue = MD5_LeftRotate(tempValue, shiftCount);
        tempValue = tempValue + stateB;

        stateA = stateD;
        stateD = stateC;
        stateC = stateB;
        stateB = tempValue;
    }

    context->state[0] += stateA;
    context->state[1] += stateB;
    context->state[2] += stateC;
    context->state[3] += stateD;
}

/******************************************************************************
 * @brief      : 初始化 MD5 计算上下文
 * @param[in]  : 无
 * @param[out] : context -- MD5 上下文结构体指针
 * @return     : 无
 * @note       : 必须在第一次调用 MD5_Update 前调用
 ******************************************************************************/
void MD5_Init(MD5_Context_S* context)
{
    context->state[0] = g_md5InitA;
    context->state[1] = g_md5InitB;
    context->state[2] = g_md5InitC;
    context->state[3] = g_md5InitD;
    context->count[0] = 0;
    context->count[1] = 0;
}

/******************************************************************************
 * @brief      : 处理部分数据进行 MD5 计算
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : context -- 被修改的 MD5 上下文
 * @return     : 无
 * @note       : 可多次调用，最后调用 MD5_Final 获取结果
 ******************************************************************************/
void MD5_Update(MD5_Context_S* context, const u8* input, size_t inputLen)
{
    if (inputLen == 0) {
        return;
    }

    u32 bitCount[2];
    bitCount[0] = (u32)(inputLen << 3);
    bitCount[1] = (u32)(inputLen >> 29);

    if (context->count[0] + bitCount[0] < context->count[0]) {
        context->count[1]++;
    }
    context->count[0] += bitCount[0];
    context->count[1] += bitCount[1];

    int bufferIndex = (context->count[0] >> 3) & 0x3F;
    size_t bytesToCopy = 64 - bufferIndex;

    size_t offset = 0;
    if (inputLen >= bytesToCopy) {
        memcpy(&context->buffer[bufferIndex], input, bytesToCopy);
        MD5_ProcessBlock(context->buffer, context);

        for (offset = bytesToCopy; offset + 63 < inputLen; offset += 64) {
            MD5_ProcessBlock((u8*)&input[offset], context);
        }
        bufferIndex = 0;
    }

    memcpy(&context->buffer[bufferIndex], &input[offset], inputLen - offset);
}

/******************************************************************************
 * @brief      : 结束 MD5 计算并输出 128-bit 摘要
 * @param[in]  : context -- 已处理数据的 MD5 上下文
 * @param[out] : digest -- 接收 16 字节 MD5 摘要的缓冲区
 * @return     : 无
 * @note       : 调用后 context 不可再用于 Update，需重新 Init
 ******************************************************************************/
void MD5_Final(u8 digest[16], MD5_Context_S* context)
{
    u8 bits[8];
    for (int i = 0; i < 4; ++i) {
        MD5_WordToBytes(&bits[i * 4], context->count[i < 2 ? 0 : 1]);
    }

    int bufferIndex = (context->count[0] >> 3) & 0x3F;
    int paddingLength = (bufferIndex < 56) ? (56 - bufferIndex) : (120 - bufferIndex);

    u8 paddingByte[1] = {0x80};
    MD5_Update(context, paddingByte, 1);

    u8 zeroPadding[64] = {0};
    if (paddingLength > 1) {
        MD5_Update(context, zeroPadding, paddingLength - 1);
    }

    MD5_Update(context, bits, 8);

    for (int i = 0; i < 4; ++i) {
        MD5_WordToBytes(&digest[i * 4], context->state[i]);
    }
}

/******************************************************************************
 * @brief      : 一步计算 MD5 摘要
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : digest -- 接收 16 字节 MD5 摘要的缓冲区
 * @return     : 无
 * @note       : 对于短消息或不需要分块处理的场景
 ******************************************************************************/
void MD5_Hash(const u8* input, size_t inputLen, u8 digest[16])
{
    MD5_Context_S context;
    MD5_Init(&context);
    MD5_Update(&context, input, inputLen);
    MD5_Final(digest, &context);
}
