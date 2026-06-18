/******************************************************************************
 * File Name : sm4.c
 * Function  : SM4 分组密码算法实现 (GB/T 32907-2016)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <string.h>
#include "include/sm4.h"

/* SM4 S-Box 替代表 */
static const u8 g_sm4SBox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

/* SM4 常数 FK[j] */
static const u32 g_sm4FK[4] = {0xA3B1BAC6UL, 0x56AA3350UL, 0x677D9197UL, 0xB27022DCUL};

/* SM4 常数 CK[j] (第 j 轮的加密常数) */
static const u32 g_sm4CK[32] = {0x00070E15UL, 0x1C232A31UL, 0x383F464DUL, 0x545B6269UL, 0x70777E85UL, 0x8C939AA1UL, 0xA8AFB6BDUL, 0xC4CBD2D9UL,
                                0xE0E7EEF5UL, 0xFC030A11UL, 0x181F262DUL, 0x343B4249UL, 0x50575E65UL, 0x6C737A81UL, 0x888F9699UL, 0xA0A7AEB5UL,
                                0xBCC3CAD1UL, 0xD8DFE6EDUL, 0xF4FB0209UL, 0x10171E25UL, 0x2C333A41UL, 0x484F565DUL, 0x646B7279UL, 0x80878E95UL,
                                0x9CA3AAB1UL, 0xB8BFC6CDUL, 0xD4DBE2E9UL, 0xF0F7FE05UL, 0x0C131A21UL, 0x282F363DUL, 0x40475057UL, 0x585F666DUL};

/******************************************************************************
 * @brief      : SM4 S-Box 替代操作
 * @param[in]  : inputValue -- 输入字节
 * @param[out] : 无
 * @return     : 替代后的字节
 * @note       : 无
 ******************************************************************************/
static inline u8 SM4_SBoxSubstitute(u8 inputValue)
{
    return g_sm4SBox[inputValue];
}

/******************************************************************************
 * @brief      : SM4 线性变换 L'(X) 用于密钥扩展
 * @param[in]  : value -- 32-bit 输入值
 * @param[out] : 无
 * @return     : 线性变换结果
 * @note       : L'(X) = X ^ ROTL(13,X) ^ ROTL(23,X)
 ******************************************************************************/
static inline u32 SM4_LinearTransformL_KeySchedule(u32 value)
{
    return value ^ ((value << 13) | (value >> 19)) ^ ((value << 23) | (value >> 9));
}

/******************************************************************************
 * @brief      : SM4 线性变换 L(X) 用于加密/解密
 * @param[in]  : value -- 32-bit 输入值
 * @param[out] : 无
 * @return     : 线性变换结果
 * @note       : L(X) = X ^ ROTL(2,X) ^ ROTL(10,X) ^ ROTL(18,X) ^ ROTL(24,X)
 ******************************************************************************/
static inline u32 SM4_LinearTransformL_CipherRound(u32 value)
{
    return value ^ ((value << 2) | (value >> 30)) ^ ((value << 10) | (value >> 22)) ^ ((value << 18) | (value >> 14)) ^ ((value << 24) | (value >> 8));
}

/******************************************************************************
 * @brief      : SM4 非线性变换 T' 用于密钥扩展
 * @param[in]  : value -- 32-bit 输入值
 * @param[out] : 无
 * @return     : 非线性变换后的值
 * @note       : T'(X) = L'(tao(X))，其中 tao 是字节级 S-Box 替代
 ******************************************************************************/
static inline u32 SM4_NonLinearTransformT_KeySchedule(u32 value)
{
    u32 result = 0;
    result |= ((u32)SM4_SBoxSubstitute((u8)((value >> 24) & 0xFF))) << 24;
    result |= ((u32)SM4_SBoxSubstitute((u8)((value >> 16) & 0xFF))) << 16;
    result |= ((u32)SM4_SBoxSubstitute((u8)((value >> 8) & 0xFF))) << 8;
    result |= ((u32)SM4_SBoxSubstitute((u8)(value & 0xFF)));
    return SM4_LinearTransformL_KeySchedule(result);
}

/******************************************************************************
 * @brief      : SM4 非线性变换 T 用于加密/解密
 * @param[in]  : value -- 32-bit 输入值
 * @param[out] : 无
 * @return     : 非线性变换后的值
 * @note       : T(X) = L(tao(X))，其中 tao 是字节级 S-Box 替代
 ******************************************************************************/
static inline u32 SM4_NonLinearTransformT_CipherRound(u32 value)
{
    u32 result = 0;
    result |= ((u32)SM4_SBoxSubstitute((u8)((value >> 24) & 0xFF))) << 24;
    result |= ((u32)SM4_SBoxSubstitute((u8)((value >> 16) & 0xFF))) << 16;
    result |= ((u32)SM4_SBoxSubstitute((u8)((value >> 8) & 0xFF))) << 8;
    result |= ((u32)SM4_SBoxSubstitute((u8)(value & 0xFF)));
    return SM4_LinearTransformL_CipherRound(result);
}

/******************************************************************************
 * @brief      : 将大端字节转换为 32-bit 值
 * @param[in]  : data -- 4 字节数据指针
 * @param[out] : 无
 * @return     : 转换后的值
 * @note       : SM4 使用大端表示
 ******************************************************************************/
static inline u32 SM4_BytesToWord(const u8 data[4])
{
    return (((u32)data[0]) << 24) | (((u32)data[1]) << 16) | (((u32)data[2]) << 8) | ((u32)data[3]);
}

/******************************************************************************
 * @brief      : 将 32-bit 值转换为大端字节
 * @param[in]  : value -- 输入值
 * @param[out] : data -- 4 字节输出缓冲区
 * @return     : 无
 * @note       : 无
 ******************************************************************************/
static inline void SM4_WordToBytes(u8 data[4], u32 value)
{
    data[0] = (u8)((value >> 24) & 0xFF);
    data[1] = (u8)((value >> 16) & 0xFF);
    data[2] = (u8)((value >> 8) & 0xFF);
    data[3] = (u8)(value & 0xFF);
}

/******************************************************************************
 * @brief      : 初始化 SM4 加密密钥（生成 32 个轮密钥）
 * @param[in]  : key -- 指向 128-bit (16 字节) 密钥的指针
 * @param[out] : context -- SM4 上下文结构体指针
 * @return     : 无
 * @note       : SM4 只支持 128-bit 密钥
 ******************************************************************************/
void SM4_KeyExpansion(const u8 key[16], SM4_Context_S* context)
{
    u32 keyWords[4];
    for (int i = 0; i < 4; ++i) {
        keyWords[i] = SM4_BytesToWord(&key[i * 4]);
    }

    u32 workingValue[4];
    for (int i = 0; i < 4; ++i) {
        workingValue[i] = keyWords[i] ^ g_sm4FK[i];
    }

    /* 生成 32 个轮密钥 */
    for (int roundIdx = 0; roundIdx < 32; ++roundIdx) {
        u32 temp = workingValue[1] ^ workingValue[2] ^ workingValue[3] ^ g_sm4CK[roundIdx];
        workingValue[0] ^= SM4_NonLinearTransformT_KeySchedule(temp);
        context->roundKey[roundIdx] = workingValue[0];

        u32 rotateTemp = workingValue[0];
        workingValue[0] = workingValue[1];
        workingValue[1] = workingValue[2];
        workingValue[2] = workingValue[3];
        workingValue[3] = rotateTemp;
    }
}

/******************************************************************************
 * @brief      : 使用生成的轮密钥加密单个 128-bit (16 字节) 明文块
 * @param[in]  : plaintext -- 16 字节明文块, context -- SM4 密钥上下文
 * @param[out] : ciphertext -- 16 字节密文块
 * @return     : 无
 * @note       : 无
 ******************************************************************************/
void SM4_EncryptBlock(const u8 plaintext[16], u8 ciphertext[16], const SM4_Context_S* context)
{
    u32 stateWords[4];
    for (int i = 0; i < 4; ++i) {
        stateWords[i] = SM4_BytesToWord(&plaintext[i * 4]);
    }

    /* 32 轮加密 */
    for (int round = 0; round < 32; ++round) {
        u32 temp = stateWords[1] ^ stateWords[2] ^ stateWords[3] ^ context->roundKey[round];
        stateWords[0] ^= SM4_NonLinearTransformT_CipherRound(temp);

        u32 rotateTemp = stateWords[0];
        stateWords[0] = stateWords[1];
        stateWords[1] = stateWords[2];
        stateWords[2] = stateWords[3];
        stateWords[3] = rotateTemp;
    }

    /* 逆序输出 */
    SM4_WordToBytes(&ciphertext[0], stateWords[3]);
    SM4_WordToBytes(&ciphertext[4], stateWords[2]);
    SM4_WordToBytes(&ciphertext[8], stateWords[1]);
    SM4_WordToBytes(&ciphertext[12], stateWords[0]);
}

/******************************************************************************
 * @brief      : 使用生成的轮密钥解密单个 128-bit (16 字节) 密文块
 * @param[in]  : ciphertext -- 16 字节密文块, context -- SM4 密钥上下文
 * @param[out] : plaintext -- 16 字节明文块
 * @return     : 无
 * @note       : 无
 ******************************************************************************/
void SM4_DecryptBlock(const u8 ciphertext[16], u8 plaintext[16], const SM4_Context_S* context)
{
    u32 stateWords[4];
    for (int i = 0; i < 4; ++i) {
        stateWords[i] = SM4_BytesToWord(&ciphertext[i * 4]);
    }

    /* 32 轮解密（使用逆序轮密钥）*/
    for (int round = 31; round >= 0; --round) {
        u32 temp = stateWords[1] ^ stateWords[2] ^ stateWords[3] ^ context->roundKey[round];
        stateWords[0] ^= SM4_NonLinearTransformT_CipherRound(temp);

        u32 rotateTemp = stateWords[0];
        stateWords[0] = stateWords[1];
        stateWords[1] = stateWords[2];
        stateWords[2] = stateWords[3];
        stateWords[3] = rotateTemp;
    }

    /* 逆序输出 */
    SM4_WordToBytes(&plaintext[0], stateWords[3]);
    SM4_WordToBytes(&plaintext[4], stateWords[2]);
    SM4_WordToBytes(&plaintext[8], stateWords[1]);
    SM4_WordToBytes(&plaintext[12], stateWords[0]);
}

/******************************************************************************
 * @brief      : 一步加密接口
 * @param[in]  : key -- 16 字节密钥, plaintext -- 16 字节明文
 * @param[out] : ciphertext -- 16 字节密文
 * @return     : 无
 * @note       : 对于单块加密的简便接口
 ******************************************************************************/
void SM4_Encrypt(const u8 key[16], const u8 plaintext[16], u8 ciphertext[16])
{
    SM4_Context_S context;
    SM4_KeyExpansion(key, &context);
    SM4_EncryptBlock(plaintext, ciphertext, &context);
}

/******************************************************************************
 * @brief      : 一步解密接口
 * @param[in]  : key -- 16 字节密钥, ciphertext -- 16 字节密文
 * @param[out] : plaintext -- 16 字节明文
 * @return     : 无
 * @note       : 对于单块解密的简便接口
 ******************************************************************************/
void SM4_Decrypt(const u8 key[16], const u8 ciphertext[16], u8 plaintext[16])
{
    SM4_Context_S context;
    SM4_KeyExpansion(key, &context);
    SM4_DecryptBlock(ciphertext, plaintext, &context);
}
