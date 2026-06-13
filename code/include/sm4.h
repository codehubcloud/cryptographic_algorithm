#ifndef CODE_SM4_H
#define CODE_SM4_H

/******************************************************************************
 * File Name : sm4.h
 * Function  : SM4 分组密码算法 (国标 GB/T 32907-2016)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stddef.h>
#include <stdint.h>


typedef uint8_t u8;
typedef uint32_t u32;

/* SM4 密钥调度上下文结构体 */
typedef struct {
    u32 roundKey[32];      /* 32 轮密钥 */
} SM4_Context_S;

/******************************************************************************
 * @brief      : 初始化 SM4 加密密钥（生成 32 个轮密钥）
 * @param[in]  : key -- 指向 128-bit (16 字节) 密钥的指针
 * @param[out] : context -- SM4 上下文结构体指针
 * @return     : 无
 * @note       : SM4 只支持 128-bit 密钥
 ******************************************************************************/
void SM4_KeyExpansion(const u8 key[16], SM4_Context_S* context);

/******************************************************************************
 * @brief      : 使用生成的轮密钥加密单个 128-bit (16 字节) 明文块
 * @param[in]  : plaintext -- 16 字节明文块, context -- SM4 密钥上下文
 * @param[out] : ciphertext -- 16 字节密文块
 * @return     : 无
 * @note       : 无
 ******************************************************************************/
void SM4_EncryptBlock(const u8 plaintext[16], u8 ciphertext[16], const SM4_Context_S* context);

/******************************************************************************
 * @brief      : 使用生成的轮密钥解密单个 128-bit (16 字节) 密文块
 * @param[in]  : ciphertext -- 16 字节密文块, context -- SM4 密钥上下文
 * @param[out] : plaintext -- 16 字节明文块
 * @return     : 无
 * @note       : 无
 ******************************************************************************/
void SM4_DecryptBlock(const u8 ciphertext[16], u8 plaintext[16], const SM4_Context_S* context);

/******************************************************************************
 * @brief      : 一步加密接口
 * @param[in]  : key -- 16 字节密钥, plaintext -- 16 字节明文
 * @param[out] : ciphertext -- 16 字节密文
 * @return     : 无
 * @note       : 对于单块加密的简便接口
 ******************************************************************************/
void SM4_Encrypt(const u8 key[16], const u8 plaintext[16], u8 ciphertext[16]);

/******************************************************************************
 * @brief      : 一步解密接口
 * @param[in]  : key -- 16 字节密钥, ciphertext -- 16 字节密文
 * @param[out] : plaintext -- 16 字节明文
 * @return     : 无
 * @note       : 对于单块解密的简便接口
 ******************************************************************************/
void SM4_Decrypt(const u8 key[16], const u8 ciphertext[16], u8 plaintext[16]);

#endif /* CODE_SM4_H */
