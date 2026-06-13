/******************************************************************************
 * File Name : test_ed25519.c
 * Function  : Ed25519 签名/验证自检
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include "include/ed25519.h"

/******************************************************************************
 * @brief      : 打印十六进制数据
 * @param[in]  : label -- 标签, data -- 数据, len -- 长度
 * @param[out] : 无
 * @return     : 无
 * @note       : 无
 ******************************************************************************/
static void PrintHex(const char* label, const u8* data, size_t len)
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
    Ed25519_Context_S context;
    Ed25519_GenerateKey(&context);
    printf("Ed25519 key generated\n");
    PrintHex("Public key", context.publicKey, ED25519_KEY_SIZE);

    const u8 message[] = "Hello Ed25519!";
    u8 signature[ED25519_SIG_SIZE] = {0};
    Ed25519_Sign(message, strlen((const char*)message), signature, &context);
    PrintHex("Signature ", signature, ED25519_SIG_SIZE);

    if (Ed25519_Verify(message, strlen((const char*)message), signature, context.publicKey)) {
        printf("Ed25519 sign/verify test passed\n");
    } else {
        printf("Ed25519 sign/verify test FAILED\n");
        return 1;
    }

    return 0;
}
