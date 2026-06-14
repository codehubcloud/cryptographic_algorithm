/******************************************************************************
 * File Name : test_sm3.c
 * Function  : SM3 杂凑算法已知向量测试 (GB/T 32905-2016)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include "include/sm3.h"

/******************************************************************************
 * @brief      : 将摘要转换为十六进制字符串用于打印
 * @param[in]  : digest -- 32 字节 SM3 摘要指针
 * @param[out] : 无
 * @return     : 无
 * @note       : 直接打印到标准输出
 ******************************************************************************/
static void SM3_PrintDigest(const u8 digest[32])
{
    for (int i = 0; i < 32; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

/******************************************************************************
 * @brief      : 比较两个 SM3 摘要是否相等
 * @param[in]  : digestA, digestB -- 两个 32 字节摘要
 * @param[out] : 无
 * @return     : 相等返回 1，不相等返回 0
 * @note       : 无
 ******************************************************************************/
static int SM3_CompareDigest(const u8 digestA[32], const u8 digestB[32])
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
    /* GB/T 32905-2016 测试向量 */
    struct {
        const char* input;
        const u8 expectedDigest[32];
    } testVectors[] = {/* "abc" */
                       {"abc", {0x66, 0xC7, 0xF0, 0xF4, 0x61, 0x86, 0xF8, 0x06, 0x14, 0x2B, 0xD1, 0x0D, 0xF7, 0x41, 0x6B, 0x39,
                                0xFF, 0xB1, 0xBE, 0x85, 0x1E, 0xFD, 0x5C, 0x0F, 0xC7, 0x9E, 0x88, 0xC5, 0x14, 0xB5, 0x1B, 0xFB}},
                       /* "" (空字符串) */
                       {"", {0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F, 0x8E, 0x61, 0x19, 0x48, 0x31, 0xE8, 0x1A, 0x8F,
                             0x40, 0xA0, 0x64, 0x28, 0x9E, 0x06, 0x95, 0x1F, 0xD5, 0xFA, 0x28, 0x82, 0x4B, 0x1D, 0x36, 0x7B}}};

    int testCount = sizeof(testVectors) / sizeof(testVectors[0]);
    int passCount = 0;

    for (int i = 0; i < testCount; ++i) {
        u8 digestResult[32];
        SM3_Hash((const u8*)testVectors[i].input, strlen(testVectors[i].input), digestResult);

        printf("Test %d (\"%s\"): ", i + 1, testVectors[i].input);
        SM3_PrintDigest(digestResult);

        if (SM3_CompareDigest(digestResult, testVectors[i].expectedDigest)) {
            printf("  PASS\n");
            passCount++;
        } else {
            printf("  FAIL - Expected: ");
            SM3_PrintDigest(testVectors[i].expectedDigest);
        }
    }

    printf("\nResults: %d/%d tests passed\n", passCount, testCount);
    return (passCount == testCount) ? 0 : 1;
}
