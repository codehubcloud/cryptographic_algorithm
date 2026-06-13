#ifndef CODE_RSA_H
#define CODE_RSA_H

/******************************************************************************
 * File Name : rsa.h
 * Function  : RSA 公钥密码算法 (PKCS#1)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#define RSA_MAX_MODULUS_BYTES 256
#define RSA_MAX_MODULUS_WORDS (RSA_MAX_MODULUS_BYTES / 4)

typedef struct {
    u32 modulus[RSA_MAX_MODULUS_WORDS];
    u32 publicExp;
    u32 privateExp[RSA_MAX_MODULUS_WORDS];
    int keyBits;
    int wordSize;
} RSA_Context_S;

/******************************************************************************
 * @brief      : 生成 RSA 密钥对（简化版，使用小素数演示）
 * @param[in]  : keyBits -- 密钥位数
 * @param[out] : context -- RSA 上下文结构体指针
 * @return     : 无
 * @note       : 此为教学演示实现，生产环境应使用 OpenSSL 等成熟库
 ******************************************************************************/
void RSA_GenerateKey(int keyBits, RSA_Context_S* context);

/******************************************************************************
 * @brief      : RSA 公钥加密
 * @param[in]  : plaintext -- 明文, ptLen -- 明文长度, context -- RSA 上下文
 * @param[out] : ciphertext -- 密文, ctLen -- 密文长度指针
 * @return     : 无
 * @note       : 简化版实现，仅支持短明文
 ******************************************************************************/
void RSA_Encrypt(const u8* plaintext, size_t ptLen, u8* ciphertext, size_t* ctLen, const RSA_Context_S* context);

/******************************************************************************
 * @brief      : RSA 私钥解密
 * @param[in]  : ciphertext -- 密文, ctLen -- 密文长度, context -- RSA 上下文
 * @param[out] : plaintext -- 明文, ptLen -- 明文长度指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void RSA_Decrypt(const u8* ciphertext, size_t ctLen, u8* plaintext, size_t* ptLen, const RSA_Context_S* context);

/******************************************************************************
 * @brief      : RSA 私钥签名
 * @param[in]  : hash -- 哈希值, hashLen -- 哈希长度, context -- RSA 上下文
 * @param[out] : signature -- 签名, sigLen -- 签名长度指针
 * @return     : 无
 * @note       : 简化版 PKCS#1 v1.5 签名
 ******************************************************************************/
void RSA_Sign(const u8* hash, size_t hashLen, u8* signature, size_t* sigLen, const RSA_Context_S* context);

/******************************************************************************
 * @brief      : RSA 公钥验证签名
 * @param[in]  : hash -- 哈希值, hashLen -- 哈希长度, signature -- 签名, sigLen -- 签名长度, context -- RSA 上下文
 * @param[out] : 无
 * @return     : 验证通过返回 1，失败返回 0
 * @note       : 简化版 PKCS#1 v1.5 验证
 ******************************************************************************/
int RSA_Verify(const u8* hash, size_t hashLen, const u8* signature, size_t sigLen, const RSA_Context_S* context);

#endif /* CODE_RSA_H */
