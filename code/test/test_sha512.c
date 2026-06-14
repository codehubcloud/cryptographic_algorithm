/******************************************************************************
 * File Name : test_sha512.c
 * Function  : SHA-512 哈希算法已知向量测试 (FIPS 180-4)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include "include/sha512.h"

/******************************************************************************
 * @brief      : 将摘要转换为十六进制字符串用于打印
 * @param[in]  : digest -- 64 字节 SHA-512 摘要指针
 * @param[out] : 无
 * @return     : 无
 * @note       : 直接打印到标准输出
 ******************************************************************************/
static void SHA512_PrintDigest(const u8 digest[64])
{
    for (int i = 0; i < 64; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

/******************************************************************************
 * @brief      : 比较两个 SHA-512 摘要是否相等
 * @param[in]  : digestA, digestB -- 两个 64 字节摘要
 * @param[out] : 无
 * @return     : 相等返回 1，不相等返回 0
 * @note       : 无
 ******************************************************************************/
static int SHA512_CompareDigest(const u8 digestA[64], const u8 digestB[64])
{
    return memcmp(digestA, digestB, 64) == 0;
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
        const u8 expectedDigest[64];
    } testVectors[] = {/* "abc" */
                       {"abc",
                        {0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA, 0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31, 0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9,
                         0x7E, 0xA2, 0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A, 0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8, 0x36, 0xBA, 0x3C, 0x23,
                         0xA3, 0xFE, 0xEB, 0xBD, 0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0x69, 0x89, 0xB9, 0x15, 0x9C, 0xAB, 0xD8, 0x23, 0x08, 0x70, 0x02, 0x1A}},
                       /* "" (空字符串) */
                       {"", {0xCF, 0x83, 0xE1, 0x35, 0x7E, 0xEF, 0xB8, 0xBD, 0xF1, 0x54, 0x28, 0x50, 0xD6, 0x6C, 0x46, 0x5C, 0xB0, 0x66, 0xC9, 0x30, 0x16, 0x70,
                             0x88, 0x14, 0xF4, 0xFC, 0x3E, 0xEC, 0x4E, 0x3D, 0x63, 0xA7, 0x12, 0x85, 0x33, 0xEE, 0x4B, 0x65, 0x53, 0xF9, 0x35, 0xC2, 0x40, 0x08,
                             0xB1, 0x88, 0x25, 0xB2, 0x97, 0x6F, 0xAB, 0x9F, 0x88, 0x7C, 0x9E, 0x33, 0xDC, 0x72, 0x4B, 0x3B, 0x5E, 0xEB, 0x73, 0x42}}};

    int testCount = sizeof(testVectors) / sizeof(testVectors[0]);
    int passCount = 0;

    for (int i = 0; i < testCount; ++i) {
        u8 digestResult[64];
        SHA512_Hash((const u8*)testVectors[i].input, strlen(testVectors[i].input), digestResult);

        printf("Test %d (\"%s\"): ", i + 1, testVectors[i].input);
        SHA512_PrintDigest(digestResult);

        if (SHA512_CompareDigest(digestResult, testVectors[i].expectedDigest)) {
            printf("  PASS\n");
            passCount++;
        } else {
            printf("  FAIL - Expected: ");
            SHA512_PrintDigest(testVectors[i].expectedDigest);
        }
    }

    printf("\nResults: %d/%d tests passed\n", passCount, testCount);
    return (passCount == testCount) ? 0 : 1;
}
