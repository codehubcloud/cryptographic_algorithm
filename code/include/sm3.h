#ifndef CODE_SM3_H
#define CODE_SM3_H

/******************************************************************************
 * File Name : sm3.h
 * Function  : SM3 密码杂凑算法 (国标 GB/T 32905-2016)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

/* SM3 上下文结构体 */
typedef struct {
    u32 state[8];     /* SM3 状态变量 (V0-V7) */
    u64 bitCount;     /* 已处理的总比特数 */
    u8 buffer[64];    /* 数据缓冲区 */
    size_t bufferLen; /* 缓冲区中的字节数 */
} SM3_Context_S;

/******************************************************************************
 * @brief      : 初始化 SM3 计算上下文
 * @param[in]  : 无
 * @param[out] : context -- SM3 上下文结构体指针
 * @return     : 无
 * @note       : 必须在第一次调用 SM3_Update 前调用
 ******************************************************************************/
void SM3_Init(SM3_Context_S* context);

/******************************************************************************
 * @brief      : 处理部分数据进行 SM3 计算
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : context -- 被修改的 SM3 上下文
 * @return     : 无
 * @note       : 可多次调用，最后调用 SM3_Final 获取结果
 ******************************************************************************/
void SM3_Update(SM3_Context_S* context, const u8* input, size_t inputLen);

/******************************************************************************
 * @brief      : 结束 SM3 计算并输出 256-bit 摘要
 * @param[in]  : context -- 已处理数据的 SM3 上下文
 * @param[out] : digest -- 接收 32 字节 SM3 摘要的缓冲区
 * @return     : 无
 * @note       : 调用后 context 不可再用于 Update，需重新 Init
 ******************************************************************************/
void SM3_Final(u8 digest[32], SM3_Context_S* context);

/******************************************************************************
 * @brief      : 一步计算 SM3 摘要
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : digest -- 接收 32 字节 SM3 摘要的缓冲区
 * @return     : 无
 * @note       : 对于短消息或不需要分块处理的场景
 ******************************************************************************/
void SM3_Hash(const u8* input, size_t inputLen, u8 digest[32]);

#endif /* CODE_SM3_H */
