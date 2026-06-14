#ifndef CODE_SHA512_H
#define CODE_SHA512_H

/******************************************************************************
 * File Name : sha512.h
 * Function  : SHA-512 哈希算法 (512-bit 输出)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

/* SHA-512 上下文结构体 */
typedef struct {
    u64 state[8];     /* SHA-512 状态变量 (H0-H7) */
    u64 bitCount[2];  /* 已处理的总比特数 (低, 高) */
    u8 buffer[128];   /* 数据缓冲区 */
    size_t bufferLen; /* 缓冲区中的字节数 */
} SHA512_Context_S;

/******************************************************************************
 * @brief      : 初始化 SHA-512 计算上下文
 * @param[in]  : 无
 * @param[out] : context -- SHA-512 上下文结构体指针
 * @return     : 无
 * @note       : 必须在第一次调用 SHA512_Update 前调用
 ******************************************************************************/
void SHA512_Init(SHA512_Context_S* context);

/******************************************************************************
 * @brief      : 处理部分数据进行 SHA-512 计算
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : context -- 被修改的 SHA-512 上下文
 * @return     : 无
 * @note       : 可多次调用，最后调用 SHA512_Final 获取结果
 ******************************************************************************/
void SHA512_Update(SHA512_Context_S* context, const u8* input, size_t inputLen);

/******************************************************************************
 * @brief      : 结束 SHA-512 计算并输出 512-bit 摘要
 * @param[in]  : context -- 已处理数据的 SHA-512 上下文
 * @param[out] : digest -- 接收 64 字节 SHA-512 摘要的缓冲区
 * @return     : 无
 * @note       : 调用后 context 不可再用于 Update，需重新 Init
 ******************************************************************************/
void SHA512_Final(u8 digest[64], SHA512_Context_S* context);

/******************************************************************************
 * @brief      : 一步计算 SHA-512 摘要
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : digest -- 接收 64 字节 SHA-512 摘要的缓冲区
 * @return     : 无
 * @note       : 对于短消息或不需要分块处理的场景
 ******************************************************************************/
void SHA512_Hash(const u8* input, size_t inputLen, u8 digest[64]);

#endif /* CODE_SHA512_H */
