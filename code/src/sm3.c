/******************************************************************************
 * File Name : sm3.c
 * Function  : SM3 密码杂凑算法实现 (GB/T 32905-2016)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <string.h>
#include "include/sm3.h"

/* SM3 初始值 */
static const u32 g_sm3InitValues[8] = {0x7380166FUL, 0x4914B2B9UL, 0x172442D7UL, 0xDA8A0600UL, 0xA96F30BCUL, 0x163138AAUL, 0xE38DEE4DUL, 0xB0FB0E4EUL};

/* SM3 常数 T(j) */
static const u32 g_sm3Constants[64] = {0x79CC4519UL, 0xF3988A32UL, 0xE7311465UL, 0xCE6228CBUL, 0x9CA4F5A0UL, 0xAB2EFF1DUL, 0x83CD5650UL, 0x36222E44UL,
                                       0xF2C6F453UL, 0x164C183CUL, 0x8F890BD8UL, 0x58AAF535UL, 0x27823A0DUL, 0xDF7664E1UL, 0x86F040CDUL, 0x4D298D32UL,
                                       0xD0ACE675UL, 0xE4FF4E62UL, 0x5DFFCCC6UL, 0x9FD566CCUL, 0x21540F76UL, 0xC1D89F94UL, 0xB69318D2UL, 0x9226F629UL,
                                       0x661D9D61UL, 0x2A74E118UL, 0xE60C8D25UL, 0x112E8A93UL, 0x72F36E3CUL, 0xA9E3F0AAUL, 0x28D7AED2UL, 0x623B814CUL,
                                       0x2BBCA692UL, 0x8BAC1B33UL, 0xC8141D8DUL, 0x7CA0236FUL, 0x5AC82965UL, 0x6F48F191UL, 0x763C0B37UL, 0xD38A92D5UL,
                                       0xBE2B5460UL, 0xEC614B85UL, 0x353EF551UL, 0xC3B5FBECUL, 0x5FBEE065UL, 0xF69D5E3AUL, 0x2955459EUL, 0x7B52A457UL,
                                       0xC2E7661DUL, 0x3FA20066UL, 0x5A6AB0AAUL, 0x50D6B031UL, 0x8151CCA0UL, 0xE0AC69ACUL, 0xB4C11951UL, 0x84D34C51UL,
                                       0xD405CDA6UL, 0xF209B6D5UL, 0x44EB5E0DUL, 0x4772E20EUL, 0xA60B6F88UL, 0x26D092D9UL, 0x91A79253UL, 0x2D2523F3UL};

/******************************************************************************
 * @brief      : 32-bit 循环左移操作
 * @param[in]  : value -- 被移位的值, count -- 移位数
 * @param[out] : 无
 * @return     : 循环左移后的结果
 * @note       : 无
 ******************************************************************************/
static inline u32 SM3_LeftRotate(u32 value, int count)
{
    return (value << count) | (value >> (32 - count));
}

/******************************************************************************
 * @brief      : SM3 压缩函数中的置换函数 P0
 * @param[in]  : value -- 输入值
 * @param[out] : 无
 * @return     : P0(value) = value ^ ROTL(9,value) ^ ROTL(17,value)
 * @note       : 无
 ******************************************************************************/
static inline u32 SM3_P0(u32 value)
{
    return value ^ SM3_LeftRotate(value, 9) ^ SM3_LeftRotate(value, 17);
}

/******************************************************************************
 * @brief      : SM3 密钥扩展中的置换函数 P1
 * @param[in]  : value -- 输入值
 * @param[out] : 无
 * @return     : P1(value) = value ^ ROTL(15,value) ^ ROTL(23,value)
 * @note       : 无
 ******************************************************************************/
static inline u32 SM3_P1(u32 value)
{
    return value ^ SM3_LeftRotate(value, 15) ^ SM3_LeftRotate(value, 23);
}

/******************************************************************************
 * @brief      : SM3 压缩函数中的选择函数 F
 * @param[in]  : roundIdx -- 轮数索引, valX, valY, valZ -- 输入值
 * @param[out] : 无
 * @return     : j在0-15时返回 x^y^z，j在16-63时返回 (x&y)|(x&~z)|(y&z)
 * @note       : 无
 ******************************************************************************/
static inline u32 SM3_SelectFunction(int roundIdx, u32 valX, u32 valY, u32 valZ)
{
    if (roundIdx < 16) {
        return valX ^ valY ^ valZ;
    } else {
        return (valX & valY) | (valX & ~valZ) | (valY & valZ);
    }
}

/******************************************************************************
 * @brief      : 将大端字节转换为 32-bit 值
 * @param[in]  : data -- 4 字节数据指针
 * @param[out] : 无
 * @return     : 转换后的值
 * @note       : SM3 使用大端表示
 ******************************************************************************/
static inline u32 SM3_BytesToWord(const u8 data[4])
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
static inline void SM3_WordToBytes(u8 data[4], u32 value)
{
    data[0] = (u8)((value >> 24) & 0xFF);
    data[1] = (u8)((value >> 16) & 0xFF);
    data[2] = (u8)((value >> 8) & 0xFF);
    data[3] = (u8)(value & 0xFF);
}

/******************************************************************************
 * @brief      : 处理单个 512-bit (64 字节) SM3 数据块
 * @param[in]  : blockData -- 64 字节数据块指针
 * @param[out] : context -- 被修改的 SM3 上下文
 * @return     : 无
 * @note       : 内部函数，执行 SM3 主循环 64 轮
 ******************************************************************************/
static void SM3_ProcessBlock(const u8 blockData[64], SM3_Context_S* context)
{
    u32 messageWordW[68];
    u32 messageWordW1[64];

    /* 扩展消息 W 和 W1 */
    for (int i = 0; i < 16; ++i) {
        messageWordW[i] = SM3_BytesToWord(&blockData[i * 4]);
    }

    for (int i = 16; i < 68; ++i) {
        messageWordW[i] = SM3_P1(messageWordW[i - 16] ^ messageWordW[i - 9] ^ SM3_LeftRotate(messageWordW[i - 3], 15)) ^ SM3_LeftRotate(messageWordW[i - 13], 7)
                          ^ messageWordW[i - 6];
    }

    for (int i = 0; i < 64; ++i) {
        messageWordW1[i] = messageWordW[i] ^ messageWordW[i + 4];
    }

    u32 stateValues[8];
    memcpy(stateValues, context->state, sizeof(stateValues));

    /* 64 轮主循环 */
    for (int round = 0; round < 64; ++round) {
        u32 ss1Value = SM3_LeftRotate((SM3_LeftRotate(stateValues[0], 12) + stateValues[4] + SM3_LeftRotate(g_sm3Constants[round], round % 32)) % 32, 7);
        u32 ss2Value = ss1Value ^ SM3_LeftRotate(stateValues[0], 12);
        u32 tt1Value = (SM3_SelectFunction(round, stateValues[0], stateValues[1], stateValues[2]) + stateValues[3] + ss2Value + messageWordW1[round])
                       & 0xFFFFFFFFUL;
        u32 tt2Value = (SM3_P0(stateValues[4]) + stateValues[5] + ss1Value + messageWordW[round]) & 0xFFFFFFFFUL;

        stateValues[3] = stateValues[2];
        stateValues[2] = SM3_LeftRotate(stateValues[1], 9);
        stateValues[1] = stateValues[0];
        stateValues[0] = tt1Value;
        stateValues[7] = stateValues[6];
        stateValues[6] = SM3_LeftRotate(stateValues[5], 19);
        stateValues[5] = stateValues[4];
        stateValues[4] = SM3_P0(tt2Value);
    }

    for (int i = 0; i < 8; ++i) {
        context->state[i] ^= stateValues[i];
    }
}

/******************************************************************************
 * @brief      : 初始化 SM3 计算上下文
 * @param[in]  : 无
 * @param[out] : context -- SM3 上下文结构体指针
 * @return     : 无
 * @note       : 必须在第一次调用 SM3_Update 前调用
 ******************************************************************************/
void SM3_Init(SM3_Context_S* context)
{
    memcpy(context->state, g_sm3InitValues, sizeof(g_sm3InitValues));
    context->bitCount = 0;
    context->bufferLen = 0;
}

/******************************************************************************
 * @brief      : 处理部分数据进行 SM3 计算
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : context -- 被修改的 SM3 上下文
 * @return     : 无
 * @note       : 可多次调用，最后调用 SM3_Final 获取结果
 ******************************************************************************/
void SM3_Update(SM3_Context_S* context, const u8* input, size_t inputLen)
{
    if (inputLen == 0) {
        return;
    }

    context->bitCount += inputLen * 8;

    size_t bytesToCopy = 64 - context->bufferLen;
    size_t offset = 0;

    if (inputLen >= bytesToCopy) {
        memcpy(&context->buffer[context->bufferLen], input, bytesToCopy);
        SM3_ProcessBlock(context->buffer, context);

        for (offset = bytesToCopy; offset + 63 < inputLen; offset += 64) {
            SM3_ProcessBlock(&input[offset], context);
        }
        context->bufferLen = 0;
    }

    memcpy(&context->buffer[context->bufferLen], &input[offset], inputLen - offset);
    context->bufferLen += inputLen - offset;
}

/******************************************************************************
 * @brief      : 结束 SM3 计算并输出 256-bit 摘要
 * @param[in]  : context -- 已处理数据的 SM3 上下文
 * @param[out] : digest -- 接收 32 字节 SM3 摘要的缓冲区
 * @return     : 无
 * @note       : 调用后 context 不可再用于 Update，需重新 Init
 ******************************************************************************/
void SM3_Final(u8 digest[32], SM3_Context_S* context)
{
    u8 paddingByte = 0x80;
    SM3_Update(context, &paddingByte, 1);

    while (context->bufferLen != 56) {
        paddingByte = 0x00;
        SM3_Update(context, &paddingByte, 1);
    }

    u8 lengthBytes[8];
    u64 bitCountBig = context->bitCount;
    for (int i = 7; i >= 0; --i) {
        lengthBytes[i] = (u8)(bitCountBig & 0xFF);
        bitCountBig >>= 8;
    }
    SM3_Update(context, lengthBytes, 8);

    for (int i = 0; i < 8; ++i) {
        SM3_WordToBytes(&digest[i * 4], context->state[i]);
    }
}

/******************************************************************************
 * @brief      : 一步计算 SM3 摘要
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : digest -- 接收 32 字节 SM3 摘要的缓冲区
 * @return     : 无
 * @note       : 对于短消息或不需要分块处理的场景
 ******************************************************************************/
void SM3_Hash(const u8* input, size_t inputLen, u8 digest[32])
{
    SM3_Context_S context;
    SM3_Init(&context);
    SM3_Update(&context, input, inputLen);
    SM3_Final(digest, &context);
}
