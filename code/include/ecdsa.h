#ifndef CODE_ECDSA_H
#define CODE_ECDSA_H

/******************************************************************************
 * File Name : ecdsa.h
 * Function  : ECDSA 数字签名算法 (P-256/secp256r1)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;

#define ECDSA_WORD_SIZE 8

typedef struct {
    u32 privateKey[ECDSA_WORD_SIZE];
    u32 publicKeyX[ECDSA_WORD_SIZE];
    u32 publicKeyY[ECDSA_WORD_SIZE];
} ECDSA_Context_S;

typedef struct {
    u32 r[ECDSA_WORD_SIZE];
    u32 s[ECDSA_WORD_SIZE];
} ECDSA_Signature_S;

/******************************************************************************
 * @brief      : 生成 ECDSA 密钥对（P-256 曲线）
 * @param[in]  : 无
 * @param[out] : context -- ECDSA 上下文结构体指针
 * @return     : 无
 * @note       : 教学演示实现
 ******************************************************************************/
void ECDSA_GenerateKey(ECDSA_Context_S* context);

/******************************************************************************
 * @brief      : ECDSA 数字签名
 * @param[in]  : hash -- 消息哈希, hashLen -- 哈希长度, context -- ECDSA 上下文
 * @param[out] : sig -- 签名结构体指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void ECDSA_Sign(const u8* hash, size_t hashLen, ECDSA_Signature_S* sig, const ECDSA_Context_S* context);

/******************************************************************************
 * @brief      : ECDSA 签名验证
 * @param[in]  : hash -- 消息哈希, hashLen -- 哈希长度, sig -- 签名, context -- ECDSA 上下文
 * @param[out] : 无
 * @return     : 验证通过返回 1，失败返回 0
 * @note       : 简化版实现
 ******************************************************************************/
int ECDSA_Verify(const u8* hash, size_t hashLen, const ECDSA_Signature_S* sig, const ECDSA_Context_S* context);

#endif /* CODE_ECDSA_H */
