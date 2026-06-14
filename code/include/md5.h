#ifndef CODE_MD5_H
#define CODE_MD5_H

/******************************************************************************
 * File Name : md5.h
 * Function  : MD5 哈希算法 (128-bit 输出)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;

/* MD5 上下文结构体 */
typedef struct {
    u32 state[4];  /* MD5 状态变量 (A,B,C,D) */
    u32 count[2];  /* 比特计数 (低, 高) */
    u8 buffer[64]; /* 数据缓冲区 */
} MD5_Context_S;

/******************************************************************************
 * @brief      : 初始化 MD5 计算上下文
 * @param[in]  : 无
 * @param[out] : context -- MD5 上下文结构体指针
 * @return     : 无
 * @note       : 必须在第一次调用 MD5_Update 前调用
 ******************************************************************************/
void MD5_Init(MD5_Context_S* context);

/******************************************************************************
 * @brief      : 处理部分数据进行 MD5 计算
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : context -- 被修改的 MD5 上下文
 * @return     : 无
 * @note       : 可多次调用，最后调用 MD5_Final 获取结果
 ******************************************************************************/
void MD5_Update(MD5_Context_S* context, const u8* input, size_t inputLen);

/******************************************************************************
 * @brief      : 结束 MD5 计算并输出 128-bit 摘要
 * @param[in]  : context -- 已处理数据的 MD5 上下文
 * @param[out] : digest -- 接收 16 字节 MD5 摘要的缓冲区
 * @return     : 无
 * @note       : 调用后 context 不可再用于 Update，需重新 Init
 ******************************************************************************/
void MD5_Final(u8 digest[16], MD5_Context_S* context);

/******************************************************************************
 * @brief      : 一步计算 MD5 摘要
 * @param[in]  : input -- 输入数据指针, inputLen -- 输入数据长度
 * @param[out] : digest -- 接收 16 字节 MD5 摘要的缓冲区
 * @return     : 无
 * @note       : 对于短消息或不需要分块处理的场景
 ******************************************************************************/
void MD5_Hash(const u8* input, size_t inputLen, u8 digest[16]);

#endif /* CODE_MD5_H */
