#ifndef CODE_AES_H
#define CODE_AES_H

/******************************************************************************
 * File Name : aes.h
 * Function  : AES public API (supports AES-128/192/256)
 * Author    : automated refactor
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stddef.h>
#include <stdint.h>


typedef uint8_t u8;
typedef uint32_t u32;

/* Key expansion and block API (keyLenBytes = 16 | 24 | 32) */
/*******************************************************************************
 * @brief      : 生成轮密钥（适用于 AES-128/192/256）
 * @param[in]  : key -- 指向原始密钥字节的指针, keyLenBytes -- 密钥长度（16/24/32）
 * @param[out] : roundKey -- 接收扩展后轮密钥的缓冲区 (需至少 16*(numRounds+1) 字节), outNumRounds -- 写入轮数 (可为 NULL)
 * @return     : 无
 * @note       : numKeyWords = keyLenBytes/4, numRounds = numKeyWords + 6
 ******************************************************************************/
void AES_KeyExpansion(const u8* key, int keyLenBytes, u8* roundKey, int* outNumRounds);

/*******************************************************************************
 * @brief      : 使用给定轮密钥对单个 16 字节明文块进行加密
 * @param[in]  : in -- 16 字节明文, roundKey -- 扩展后的轮密钥, numRounds -- 轮数
 * @param[out] : out -- 16 字节密文输出
 * @return     : 无
 * @note       : 最后一次调用时传入正确的 numRounds
 ******************************************************************************/
void AES_EncryptBlock(const u8 in[16], u8 out[16], const u8* roundKey, int numRounds);

/*******************************************************************************
 * @brief      : 使用给定轮密钥对单个 16 字节密文块进行解密
 * @param[in]  : in -- 16 字节密文, roundKey -- 扩展后的轮密钥, numRounds -- 轮数
 * @param[out] : out -- 16 字节明文输出
 * @return     : 无
 * @note       : 最后一次调用时传入正确的 numRounds
 ******************************************************************************/
void AES_DecryptBlock(const u8 in[16], u8 out[16], const u8* roundKey, int numRounds);

#endif /* CODE_AES_H */
