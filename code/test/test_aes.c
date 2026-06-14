/******************************************************************************
 * File Name : test_aes.c
 * Function  : Self-test for AES-128/192/256 using known vectors
 * Author    : automated refactor
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include "include/aes.h"

/******************************************************************************
 * @brief      : 将十六进制字符串转换为字节数组
 * @param[in]  : hex -- 十六进制字符串
 * @param[out] : out -- 输出缓冲区, outLen -- 输出缓冲区长度
 * @return     : 成功返回 1, 失败返回 0
 * @note       : 输出缓冲区需足够大以容纳 hex 长度的一半
 ******************************************************************************/
static int HexToBytes(const char* hex, u8* out, size_t outLen)
{
    size_t hexlen = strlen(hex);
    if (hexlen % 2 != 0 || outLen < hexlen / 2) {
        return 0;
    }
    for (size_t i = 0; i < hexlen / 2; ++i) {
        unsigned int hexValue;
        if (sscanf(&hex[i * 2], "%2x", &hexValue) != 1) {
            return 0;
        }
        out[i] = (u8)hexValue;
    }
    return 1;
}

/******************************************************************************
 * @brief      : 使用给定向量测试 AES 的单向加解密正确性
 * @param[in]  : keyHex -- 密钥的十六进制字符串, keyLen -- 密钥字节长度， ptHex -- 明文十六进制字符串, ctHex -- 期望密文十六进制字符串
 * @param[out] : 无
 * @return     : 成功返回 1, 失败返回 0
 * @note       : 使用 AES_KeyExpansion/AES_EncryptBlock/AES_DecryptBlock 验证
 ******************************************************************************/
static int TestAESVariant(const char* keyHex, int keyLen, const char* ptHex, const char* ctHex, int expectedNumRounds)
{
    u8 key[32] = {0};
    u8 pt[16] = {0};
    u8 expectedCt[16] = {0};
    if (!HexToBytes(keyHex, key, keyLen)) {
        return 0;
    }
    if (!HexToBytes(ptHex, pt, sizeof(pt))) {
        return 0;
    }
    if (!HexToBytes(ctHex, expectedCt, sizeof(expectedCt))) {
        return 0;
    }

    u8 roundKey[240] = {0};
    int numRounds = 0;
    AES_KeyExpansion(key, keyLen, roundKey, &numRounds);
    if (numRounds != expectedNumRounds) {
        printf("KeyExpansion returned numRounds=%d (expected %d)\n", numRounds, expectedNumRounds);
        return 0;
    }

    u8 ct[16];
    u8 dec[16];
    AES_EncryptBlock(pt, ct, roundKey, numRounds);
    if (memcmp(ct, expectedCt, 16) != 0) {
        printf("Encryption mismatch for keyLen=%d\n", keyLen);
        return 0;
    }
    AES_DecryptBlock(ct, dec, roundKey, numRounds);
    if (memcmp(pt, dec, 16) != 0) {
        printf("Decrypt roundtrip failed for keyLen=%d\n", keyLen);
        return 0;
    }
    return 1;
}

int main(void)
{
    /* NIST SP 800-38A test vectors (single block) */
    const char* ptHex = "6bc1bee22e409f96e93d7e117393172a";

    /* AES-128 */
    const char* key128 = "2b7e151628aed2a6abf7158809cf4f3c";
    const char* ct128 = "3ad77bb40d7a3660a89ecaf32466ef97";

    /* AES-192 */
    const char* key192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"; /* 24 bytes */
    const char* ct192 = "bd334f1d6e45f25ff712a214571fa5cc";

    /* AES-256 */
    const char* key256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"; /* 32 bytes */
    const char* ct256 = "f3eed1bdb5d2a03c064b5a7e3db181f8";

    if (!TestAESVariant(key128, 16, ptHex, ct128, 10)) {
        return 1;
    }
    printf("AES-128 test passed\n");

    if (!TestAESVariant(key192, 24, ptHex, ct192, 12)) {
        return 1;
    }
    printf("AES-192 test passed\n");

    if (!TestAESVariant(key256, 32, ptHex, ct256, 14)) {
        return 1;
    }
    printf("AES-256 test passed\n");

    return 0;
}
