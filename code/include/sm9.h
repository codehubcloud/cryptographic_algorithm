#ifndef CODE_SM9_H
#define CODE_SM9_H

/******************************************************************************
 * File Name : sm9.h
 * Function  : SM9 标识密码算法 (GB/T 32918-2016)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#define SM9_WORD_SIZE 8

typedef struct {
    u32 masterPrivateKey[SM9_WORD_SIZE];
    u32 masterPublicKeyX[SM9_WORD_SIZE];
    u32 masterPublicKeyY[SM9_WORD_SIZE];
} SM9_Context_S;

typedef struct {
    u32 privateKeyX[SM9_WORD_SIZE];
    u32 privateKeyY[SM9_WORD_SIZE];
} SM9_UserKey_S;

typedef struct {
    u32 h[SM9_WORD_SIZE];
    u32 pointX[SM9_WORD_SIZE];
    u32 pointY[SM9_WORD_SIZE];
} SM9_Signature_S;

/******************************************************************************
 * @brief      : 生成 SM9 主密钥对
 * @param[in]  : 无
 * @param[out] : context -- SM9 上下文结构体指针
 * @return     : 无
 * @note       : 教学演示实现
 ******************************************************************************/
void SM9_GenerateMasterKey(SM9_Context_S* context);

/******************************************************************************
 * @brief      : 提取 SM9 用户私钥
 * @param[in]  : id -- 用户标识, context -- SM9 上下文
 * @param[out] : userKey -- 用户密钥结构体指针
 * @return     : 无
 * @note       : 由 KGC 执行
 ******************************************************************************/
void SM9_ExtractUserKey(const char* id, SM9_UserKey_S* userKey, const SM9_Context_S* context);

/******************************************************************************
 * @brief      : SM9 数字签名
 * @param[in]  : message -- 消息, msgLen -- 消息长度, userKey -- 用户私钥, context -- SM9 上下文
 * @param[out] : sig -- 签名结构体指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void SM9_Sign(const u8* message, size_t msgLen, SM9_Signature_S* sig, const SM9_UserKey_S* userKey, const SM9_Context_S* context);

/******************************************************************************
 * @brief      : SM9 签名验证
 * @param[in]  : message -- 消息, msgLen -- 消息长度, sig -- 签名, id -- 签名者标识, context -- SM9 上下文
 * @param[out] : 无
 * @return     : 验证通过返回 1，失败返回 0
 * @note       : 简化版实现
 ******************************************************************************/
int SM9_Verify(const u8* message, size_t msgLen, const SM9_Signature_S* sig, const char* id, const SM9_Context_S* context);

/******************************************************************************
 * @brief      : SM9 公钥加密
 * @param[in]  : plaintext -- 明文, ptLen -- 明文长度, id -- 接收者标识, context -- SM9 上下文
 * @param[out] : ciphertext -- 密文, ctLen -- 密文长度指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void SM9_Encrypt(const u8* plaintext, size_t ptLen, u8* ciphertext, size_t* ctLen, const char* id, const SM9_Context_S* context);

/******************************************************************************
 * @brief      : SM9 私钥解密
 * @param[in]  : ciphertext -- 密文, ctLen -- 密文长度, userKey -- 用户私钥, context -- SM9 上下文
 * @param[out] : plaintext -- 明文, ptLen -- 明文长度指针
 * @return     : 成功返回 0，失败返回 -1
 * @note       : 简化版实现
 ******************************************************************************/
int SM9_Decrypt(const u8* ciphertext, size_t ctLen, u8* plaintext, size_t* ptLen, const SM9_UserKey_S* userKey, const SM9_Context_S* context);

#endif /* CODE_SM9_H */
