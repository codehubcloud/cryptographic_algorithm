/******************************************************************************
 * File Name : test_sha256.c
 * Function  : SHA-256 哈希算法已知向量测试 (FIPS 180-4)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include "include/sha256.h"

/******************************************************************************
 * @brief      : 将摘要转换为十六进制字符串用于打印
 * @param[in]  : digest -- 32 字节 SHA-256 摘要指针
 * @param[out] : 无
 * @return     : 无
 * @note       : 直接打印到标准输出
 ******************************************************************************/
static void SHA256_PrintDigest(const u8 digest[32])
{
    for (int i = 0; i < 32; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

/******************************************************************************
 * @brief      : 比较两个 SHA-256 摘要是否相等
 * @param[in]  : digestA, digestB -- 两个 32 字节摘要
 * @param[out] : 无
 * @return     : 相等返回 1，不相等返回 0
 * @note       : 无
 ******************************************************************************/
static int SHA256_CompareDigest(const u8 digestA[32], const u8 digestB[32])
{
    return memcmp(digestA, digestB, 32) == 0;
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
    /* FIPS 180-4 测试向量 */
    struct {
        const char* input;
        const u8 expectedDigest[32];
    } testVectors[] = {/* "abc" */
                       {"abc", {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x87, 0x9a, 0x2d, 0xea, 0x0e, 0xc6, 0x00, 0x65, 0x84, 0xe3}},
                       /* "" (空字符串) */
                       {"", {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                             0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}},
                       /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
                       {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                        {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
                         0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1}}};

    int testCount = sizeof(testVectors) / sizeof(testVectors[0]);
    int passCount = 0;

    for (int i = 0; i < testCount; ++i) {
        u8 digestResult[32];
        SHA256_Hash((const u8*)testVectors[i].input, strlen(testVectors[i].input), digestResult);

        printf("Test %d (\"%s\"): ", i + 1, testVectors[i].input);
        SHA256_PrintDigest(digestResult);

        if (SHA256_CompareDigest(digestResult, testVectors[i].expectedDigest)) {
            printf("  PASS\n");
            passCount++;
        } else {
            printf("  FAIL - Expected: ");
            SHA256_PrintDigest(testVectors[i].expectedDigest);
        }
    }

    printf("\nResults: %d/%d tests passed\n", passCount, testCount);
    return (passCount == testCount) ? 0 : 1;
}
