/******************************************************************************
 * File Name : test_sm4.c
 * Function  : SM4 加密/解密标准测试向量自检
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include "include/sm4.h"

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
 * @brief      : 打印字节数组
 * @param[in]  : label -- 标签, data -- 数据, len -- 长度
 * @param[out] : 无
 * @return     : 无
 * @note       : 无
 ******************************************************************************/
static void PrintBytes(const char* label, const u8* data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

/******************************************************************************
 * @brief      : 主测试入口
 * @param[in]  : 无
 * @param[out] : 无
 * @return     : 测试通过返回 0，失败返回 1
 * @note       : 无
 ******************************************************************************/
int main(void)
{
    const char* keyHex = "0123456789abcdeffedcba9876543210";
    const char* ptHex = "0123456789abcdeffedcba9876543210";
    const char* ctHex = "681edf34d206965e86b3e94f536e4246";

    u8 key[16] = {0};
    u8 pt[16] = {0};
    u8 expectedCt[16] = {0};

    if (!HexToBytes(keyHex, key, sizeof(key))) {
        printf("Failed to parse key hex\n");
        return 1;
    }
    if (!HexToBytes(ptHex, pt, sizeof(pt))) {
        printf("Failed to parse plaintext hex\n");
        return 1;
    }
    if (!HexToBytes(ctHex, expectedCt, sizeof(expectedCt))) {
        printf("Failed to parse ciphertext hex\n");
        return 1;
    }

    SM4_Context_S context;
    SM4_KeyExpansion(key, &context);

    u8 ct[16] = {0};
    SM4_EncryptBlock(pt, ct, &context);

    PrintBytes("Plaintext ", pt, 16);
    PrintBytes("Ciphertext", ct, 16);
    PrintBytes("Expected  ", expectedCt, 16);

    if (memcmp(ct, expectedCt, 16) == 0) {
        printf("SM4 encryption test passed\n");
    } else {
        printf("SM4 encryption test FAILED\n");
        return 1;
    }

    u8 dec[16] = {0};
    SM4_DecryptBlock(ct, dec, &context);

    if (memcmp(dec, pt, 16) == 0) {
        printf("SM4 decryption test passed\n");
    } else {
        printf("SM4 decryption test FAILED\n");
        return 1;
    }

    u8 ct2[16] = {0};
    SM4_Encrypt(key, pt, ct2);
    if (memcmp(ct2, expectedCt, 16) == 0) {
        printf("SM4 one-step encrypt test passed\n");
    } else {
        printf("SM4 one-step encrypt test FAILED\n");
        return 1;
    }

    u8 dec2[16] = {0};
    SM4_Decrypt(key, ct2, dec2);
    if (memcmp(dec2, pt, 16) == 0) {
        printf("SM4 one-step decrypt test passed\n");
    } else {
        printf("SM4 one-step decrypt test FAILED\n");
        return 1;
    }

    return 0;
}
