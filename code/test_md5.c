/******************************************************************************
 * File Name : test_md5.c
 * Function  : MD5 哈希算法已知向量测试 (RFC 1321)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include "include/md5.h"

/******************************************************************************
 * @brief      : 将摘要转换为十六进制字符串用于打印
 * @param[in]  : digest -- 16 字节 MD5 摘要指针
 * @param[out] : 无
 * @return     : 无
 * @note       : 直接打印到标准输出
 ******************************************************************************/
static void MD5_PrintDigest(const u8 digest[16])
{
    for (int i = 0; i < 16; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

/******************************************************************************
 * @brief      : 比较两个 MD5 摘要是否相等
 * @param[in]  : digestA, digestB -- 两个 16 字节摘要
 * @param[out] : 无
 * @return     : 相等返回 1，不相等返回 0
 * @note       : 无
 ******************************************************************************/
static int MD5_CompareDigest(const u8 digestA[16], const u8 digestB[16])
{
    return memcmp(digestA, digestB, 16) == 0;
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
    /* RFC 1321 测试向量 */
    struct {
        const char* input;
        const u8 expectedDigest[16];
    } testVectors[] = {
        /* 空字符串 */
        {"", {0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e}},
        /* "a" */
        {"a", {0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61}},
        /* "abc" */
        {"abc", {0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72}},
        /* "message digest" */
        {"message digest", {0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0}},
        /* "abcdefghijklmnopqrstuvwxyz" */
        {"abcdefghijklmnopqrstuvwxyz", {0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b}}
    };

    int testCount = sizeof(testVectors) / sizeof(testVectors[0]);
    int passCount = 0;

    for (int i = 0; i < testCount; ++i) {
        u8 digestResult[16];
        MD5_Hash((const u8*)testVectors[i].input, strlen(testVectors[i].input), digestResult);

        printf("Test %d (\"%s\"): ", i + 1, testVectors[i].input);
        MD5_PrintDigest(digestResult);

        if (MD5_CompareDigest(digestResult, testVectors[i].expectedDigest)) {
            printf("  PASS\n");
            passCount++;
        } else {
            printf("  FAIL - Expected: ");
            MD5_PrintDigest(testVectors[i].expectedDigest);
        }
    }

    printf("\nResults: %d/%d tests passed\n", passCount, testCount);
    return (passCount == testCount) ? 0 : 1;
}
