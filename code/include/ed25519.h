#ifndef CODE_ED25519_H
#define CODE_ED25519_H

/******************************************************************************
 * File Name : ed25519.h
 * Function  : Ed25519 数字签名算法 (RFC 8032)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;

#define ED25519_KEY_SIZE 32
#define ED25519_SIG_SIZE 64

typedef struct {
    u8 seedKey[ED25519_KEY_SIZE];
    u8 publicKey[ED25519_KEY_SIZE];
} Ed25519_Context_S;

/******************************************************************************
 * @brief      : 生成 Ed25519 密钥对
 * @param[in]  : 无
 * @param[out] : context -- Ed25519 上下文结构体指针
 * @return     : 无
 * @note       : 教学演示实现
 ******************************************************************************/
void Ed25519_GenerateKey(Ed25519_Context_S* context);

/******************************************************************************
 * @brief      : Ed25519 数字签名
 * @param[in]  : message -- 消息, msgLen -- 消息长度, context -- Ed25519 上下文
 * @param[out] : signature -- 64 字节签名
 * @return     : 无
 * @note       : 确定性签名，不需要随机数
 ******************************************************************************/
void Ed25519_Sign(const u8* message, size_t msgLen, u8 signature[ED25519_SIG_SIZE], const Ed25519_Context_S* context);

/******************************************************************************
 * @brief      : Ed25519 签名验证
 * @param[in]  : message -- 消息, msgLen -- 消息长度, signature -- 64 字节签名, publicKey -- 32 字节公钥
 * @param[out] : 无
 * @return     : 验证通过返回 1，失败返回 0
 * @note       : 简化版实现
 ******************************************************************************/
int Ed25519_Verify(const u8* message, size_t msgLen, const u8 signature[ED25519_SIG_SIZE], const u8 publicKey[ED25519_KEY_SIZE]);

#endif /* CODE_ED25519_H */
