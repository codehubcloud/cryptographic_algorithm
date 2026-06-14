#ifndef CODE_SM2_H
#define CODE_SM2_H

/******************************************************************************
 * File Name : sm2.h
 * Function  : SM2 椭圆曲线公钥密码算法 (GB/T 32918-2016)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#define SM2_WORD_SIZE 8

typedef struct {
    u32 privateKey[SM2_WORD_SIZE];
    u32 publicKeyX[SM2_WORD_SIZE];
    u32 publicKeyY[SM2_WORD_SIZE];
} SM2_Context_S;

typedef struct {
    u32 r[SM2_WORD_SIZE];
    u32 s[SM2_WORD_SIZE];
} SM2_Signature_S;

/******************************************************************************
 * @brief      : 生成 SM2 密钥对
 * @param[in]  : 无
 * @param[out] : context -- SM2 上下文结构体指针
 * @return     : 无
 * @note       : 教学演示实现
 ******************************************************************************/
void SM2_GenerateKey(SM2_Context_S* context);

/******************************************************************************
 * @brief      : SM2 数字签名
 * @param[in]  : hash -- 消息哈希, hashLen -- 哈希长度, context -- SM2 上下文
 * @param[out] : sig -- 签名结构体指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void SM2_Sign(const u8* hash, size_t hashLen, SM2_Signature_S* sig, const SM2_Context_S* context);

/******************************************************************************
 * @brief      : SM2 签名验证
 * @param[in]  : hash -- 消息哈希, hashLen -- 哈希长度, sig -- 签名, context -- SM2 上下文
 * @param[out] : 无
 * @return     : 验证通过返回 1，失败返回 0
 * @note       : 简化版实现
 ******************************************************************************/
int SM2_Verify(const u8* hash, size_t hashLen, const SM2_Signature_S* sig, const SM2_Context_S* context);

/******************************************************************************
 * @brief      : SM2 公钥加密
 * @param[in]  : plaintext -- 明文, ptLen -- 明文长度, context -- SM2 上下文
 * @param[out] : ciphertext -- 密文, ctLen -- 密文长度指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void SM2_Encrypt(const u8* plaintext, size_t ptLen, u8* ciphertext, size_t* ctLen, const SM2_Context_S* context);

/******************************************************************************
 * @brief      : SM2 私钥解密
 * @param[in]  : ciphertext -- 密文, ctLen -- 密文长度, context -- SM2 上下文
 * @param[out] : plaintext -- 明文, ptLen -- 明文长度指针
 * @return     : 成功返回 0，失败返回 -1
 * @note       : 简化版实现
 ******************************************************************************/
int SM2_Decrypt(const u8* ciphertext, size_t ctLen, u8* plaintext, size_t* ptLen, const SM2_Context_S* context);

#endif /* CODE_SM2_H */
