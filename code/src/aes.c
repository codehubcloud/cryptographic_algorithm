/******************************************************************************
 * File Name : aes.c
 * Function  : AES implementation (KeyExpansion, Encrypt/Decrypt)
 * Author    : automated refactor
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <string.h>
#include "include/aes.h"

static const u8 g_sboxTable[256] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d,
                                    0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
                                    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
                                    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                                    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb,
                                    0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
                                    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
                                    0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                                    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
                                    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
                                    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
                                    0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                                    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const u8 g_invSboxTable[256] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82,
                                       0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
                                       0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
                                       0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                                       0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00,
                                       0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
                                       0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
                                       0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                                       0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
                                       0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
                                       0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
                                       0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                                       0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

static const u8 g_rconTable[15] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D};

/******************************************************************************
 * @brief      : 在 GF(2^8) 中计算乘以 2 的 xtime 运算
 * @param[in]  : inputByte -- 输入字节
 * @param[out] : 无
 * @return     : 返回 (inputByte * 2) mod inputByte^8 + inputByte^4 + inputByte^3 + inputByte + 1
 * @note       : 用于 MixColumns 实现
 ******************************************************************************/
static inline u8 XTime(u8 inputByte)
{
    return (u8)((inputByte << 1) ^ ((inputByte & 0x80) ? 0x1B : 0x00));
}

/******************************************************************************
 * @brief      : 在 GF(2^8) 中计算字节乘法
 * @param[in]  : multiplicand -- 被乘数, multiplier -- 乘数
 * @param[out] : 无
 * @return     : 返回 multiplicand * multiplier 在 GF(2^8) 下的结果
 * @note       : 使用循环位移与 XTime 实现
 ******************************************************************************/
static u8 Mul(u8 multiplicand, u8 multiplier)
{
    u8 result = 0;
    while (multiplier) {
        if (multiplier & 1) {
            result ^= multiplicand;
        }
        multiplicand = XTime(multiplicand);
        multiplier >>= 1;
    }
    return result;
}

/******************************************************************************
 * @brief      : 对状态矩阵应用 S-Box 替代
 * @param[in]  : state -- 4x4 字节状态矩阵
 * @param[out] : state 被原地替换为替代后的字节
 * @return     : 无
 * @note       : 用于加密轮的非线性变换
 ******************************************************************************/
static void SubBytes(u8 state[4][4])
{
    for (int rowIdx = 0; rowIdx < 4; ++rowIdx) {
        for (int colIdx = 0; colIdx < 4; ++colIdx) {
            state[rowIdx][colIdx] = g_sboxTable[state[rowIdx][colIdx]];
        }
    }
}

/******************************************************************************
 * @brief      : 对状态矩阵应用逆 S-Box 替代
 * @param[in]  : state -- 4x4 字节状态矩阵
 * @param[out] : state 被原地替换为逆替代后的字节
 * @return     : 无
 * @note       : 用于解密轮的非线性变换
 ******************************************************************************/
static void InvSubBytes(u8 state[4][4])
{
    for (int rowIdx = 0; rowIdx < 4; ++rowIdx) {
        for (int colIdx = 0; colIdx < 4; ++colIdx) {
            state[rowIdx][colIdx] = g_invSboxTable[state[rowIdx][colIdx]];
        }
    }
}

/******************************************************************************
 * @brief      : 行移位变换（左移）
 * @param[in]  : state -- 4x4 字节状态矩阵
 * @param[out] : state 被原地修改
 * @return     : 无
 * @note       : 第 r 行循环左移 r 个字节
 ******************************************************************************/
static void ShiftRows(u8 state[4][4])
{
    u8 temp[4];
    for (int rowIdx = 1; rowIdx < 4; ++rowIdx) {
        for (int colIdx = 0; colIdx < 4; ++colIdx) {
            temp[colIdx] = state[rowIdx][(colIdx + rowIdx) % 4];
        }
        for (int colIdx = 0; colIdx < 4; ++colIdx) {
            state[rowIdx][colIdx] = temp[colIdx];
        }
    }
}

/******************************************************************************
 * @brief      : 逆行移位变换（右移）
 * @param[in]  : state -- 4x4 字节状态矩阵
 * @param[out] : state 被原地修改
 * @return     : 无
 * @note       : 第 r 行循环右移 r 个字节
 ******************************************************************************/
static void InvShiftRows(u8 state[4][4])
{
    u8 temp[4];
    for (int rowIdx = 1; rowIdx < 4; ++rowIdx) {
        for (int colIdx = 0; colIdx < 4; ++colIdx) {
            temp[colIdx] = state[rowIdx][(colIdx - rowIdx + 4) % 4];
        }
        for (int colIdx = 0; colIdx < 4; ++colIdx) {
            state[rowIdx][colIdx] = temp[colIdx];
        }
    }
}

/******************************************************************************
 * @brief      : MixColumns 变换
 * @param[in]  : state -- 4x4 字节状态矩阵
 * @param[out] : state 被原地替换为列混合后的值
 * @return     : 无
 * @note       : 以固定多项式与每列相乘实现
 ******************************************************************************/
static void MixColumns(u8 state[4][4])
{
    for (int colIdx = 0; colIdx < 4; ++colIdx) {
        u8 stateByte0 = state[0][colIdx];
        u8 stateByte1 = state[1][colIdx];
        u8 stateByte2 = state[2][colIdx];
        u8 stateByte3 = state[3][colIdx];
        state[0][colIdx] = (u8)(Mul(stateByte0, 2) ^ Mul(stateByte1, 3) ^ stateByte2 ^ stateByte3);
        state[1][colIdx] = (u8)(stateByte0 ^ Mul(stateByte1, 2) ^ Mul(stateByte2, 3) ^ stateByte3);
        state[2][colIdx] = (u8)(stateByte0 ^ stateByte1 ^ Mul(stateByte2, 2) ^ Mul(stateByte3, 3));
        state[3][colIdx] = (u8)(Mul(stateByte0, 3) ^ stateByte1 ^ stateByte2 ^ Mul(stateByte3, 2));
    }
}

/******************************************************************************
 * @brief      : 逆 MixColumns 变换
 * @param[in]  : state -- 4x4 字节状态矩阵
 * @param[out] : state 被原地替换为逆列混合后的值
 * @return     : 无
 * @note       : 使用常量矩阵（0x0e/0x0b/0x0d/0x09）实现
 ******************************************************************************/
static void InvMixColumns(u8 state[4][4])
{
    for (int colIdx = 0; colIdx < 4; ++colIdx) {
        u8 stateByte0 = state[0][colIdx];
        u8 stateByte1 = state[1][colIdx];
        u8 stateByte2 = state[2][colIdx];
        u8 stateByte3 = state[3][colIdx];
        state[0][colIdx] = (u8)(Mul(stateByte0, 0x0e) ^ Mul(stateByte1, 0x0b) ^ Mul(stateByte2, 0x0d) ^ Mul(stateByte3, 0x09));
        state[1][colIdx] = (u8)(Mul(stateByte0, 0x09) ^ Mul(stateByte1, 0x0e) ^ Mul(stateByte2, 0x0b) ^ Mul(stateByte3, 0x0d));
        state[2][colIdx] = (u8)(Mul(stateByte0, 0x0d) ^ Mul(stateByte1, 0x09) ^ Mul(stateByte2, 0x0e) ^ Mul(stateByte3, 0x0b));
        state[3][colIdx] = (u8)(Mul(stateByte0, 0x0b) ^ Mul(stateByte1, 0x0d) ^ Mul(stateByte2, 0x09) ^ Mul(stateByte3, 0x0e));
    }
}

/******************************************************************************
 * @brief      : 将轮密钥与状态进行异或 (AddRoundKey)
 * @param[in]  : state -- 4x4 字节状态矩阵, roundKey -- 扩展轮密钥, round -- 轮索引
 * @param[out] : state 被原地修改
 * @return     : 无
 * @note       : roundKey 按 16 字节一轮排列
 ******************************************************************************/
static void AddRoundKey(u8 state[4][4], const u8* roundKey, int round)
{
    for (int colIdx = 0; colIdx < 4; ++colIdx) {
        for (int rowIdx = 0; rowIdx < 4; ++rowIdx) {
            state[rowIdx][colIdx] ^= roundKey[round * 16 + colIdx * 4 + rowIdx];
        }
    }
}

/******************************************************************************
 * @brief      : 32-bit 字循环左移 8 位（RotWord）
 * @param[in]  : wordValue -- 包含 4 字节的数组
 * @param[out] : wordValue 被原地修改
 * @return     : 无
 * @note       : 用于密钥扩展
 ******************************************************************************/
static void RotWord(u8 wordValue[4])
{
    u8 tempByte = wordValue[0];
    wordValue[0] = wordValue[1];
    wordValue[1] = wordValue[2];
    wordValue[2] = wordValue[3];
    wordValue[3] = tempByte;
}

/******************************************************************************
 * @brief      : 对 4 字节执行 S-Box 替代（SubWord）
 * @param[in]  : wordValue -- 包含 4 字节的数组
 * @param[out] : wordValue 被原地替换
 * @return     : 无
 * @note       : 用于密钥扩展
 ******************************************************************************/
static void SubWord(u8 wordValue[4])
{
    for (int i = 0; i < 4; ++i) {
        wordValue[i] = g_sboxTable[wordValue[i]];
    }
}

/******************************************************************************
 * @brief      : Generate round keys for AES (supports 16/24/32 byte keys)
 * @param[in]  : key - pointer to key bytes, keyLenBytes - key length in bytes (16/24/32)
 * @param[out] : roundKey - buffer to receive expanded round keys (must be >=16*(Nr+1))
 * @return     : none (Nr written to outNr if non-NULL)
 * @note       : Follows standard AES key schedule; Nk = keyLenBytes/4; Nr = Nk + 6
 ******************************************************************************/
void AES_KeyExpansion(const u8* key, int keyLenBytes, u8* roundKey, int* outNumRounds)
{
    int numKeyWords = keyLenBytes / 4;
    int numRounds = numKeyWords + 6;
    int numBlockWords = 4;
    int words = numBlockWords * (numRounds + 1);

    memcpy(roundKey, key, keyLenBytes);
    u8 temp[4];
    for (int i = numKeyWords; i < words; ++i) {
        memcpy(temp, &roundKey[(i - 1) * 4], 4);
        if (i % numKeyWords == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= g_rconTable[i / numKeyWords];
        } else if (numKeyWords > 6 && (i % numKeyWords) == 4) {
            SubWord(temp);
        }
        for (int j = 0; j < 4; ++j) {
            roundKey[i * 4 + j] = roundKey[(i - numKeyWords) * 4 + j] ^ temp[j];
        }
    }
    if (outNumRounds) {
        *outNumRounds = numRounds;
    }
}

/******************************************************************************
 * @brief      : Encrypt one 16-byte block with provided round keys
 * @param[in]  : in - 16-byte plaintext, roundKey - expanded round keys, numRounds - number of rounds
 * @param[out] : out - 16-byte ciphertext
 * @return     : none
 * @note       : none
 ******************************************************************************/
void AES_EncryptBlock(const u8 in[16], u8 out[16], const u8* roundKey, int numRounds)
{
    u8 state[4][4];
    for (int rowIdx = 0; rowIdx < 4; ++rowIdx) {
        for (int colIdx = 0; colIdx < 4; ++colIdx) {
            state[rowIdx][colIdx] = in[colIdx * 4 + rowIdx];
        }
    }

    AddRoundKey(state, roundKey, 0);
    for (int round = 1; round <= numRounds - 1; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKey, round);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKey, numRounds);

    for (int rowIdx = 0; rowIdx < 4; ++rowIdx) {
        for (int colIdx = 0; colIdx < 4; ++colIdx) {
            out[colIdx * 4 + rowIdx] = state[rowIdx][colIdx];
        }
    }
}

/******************************************************************************
 * @brief      : Decrypt one 16-byte block with provided round keys
 * @param[in]  : in - 16-byte ciphertext, roundKey - expanded round keys, numRounds - number of rounds
 * @param[out] : out - 16-byte plaintext
 * @return     : none
 * @note       : none
 ******************************************************************************/
void AES_DecryptBlock(const u8 in[16], u8 out[16], const u8* roundKey, int numRounds)
{
    u8 state[4][4];
    for (int rowIdx = 0; rowIdx < 4; ++rowIdx) {
        for (int colIdx = 0; colIdx < 4; ++colIdx) {
            state[rowIdx][colIdx] = in[colIdx * 4 + rowIdx];
        }
    }

    AddRoundKey(state, roundKey, numRounds);
    for (int round = numRounds - 1; round >= 1; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKey, round);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKey, 0);

    for (int rowIdx = 0; rowIdx < 4; ++rowIdx) {
        for (int colIdx = 0; colIdx < 4; ++colIdx) {
            out[colIdx * 4 + rowIdx] = state[rowIdx][colIdx];
        }
    }
}
