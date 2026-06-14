/******************************************************************************
 * File Name : test_sm2.c
 * Function  : SM2 签名/验证与加密/解密自检
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include "include/sm2.h"

/******************************************************************************
 * @brief      : 主测试入口
 * @param[in]  : 无
 * @param[out] : 无
 * @return     : 测试通过返回 0，失败返回 1
 * @note       : 无
 ******************************************************************************/
int main(void)
{
    SM2_Context_S context;
    SM2_GenerateKey(&context);
    printf("SM2 key generated\n");

    u8 hash[] = {0x01, 0x23, 0x45, 0x67};
    SM2_Signature_S sig;
    SM2_Sign(hash, sizeof(hash), &sig, &context);
    printf("SM2 signature: r=0x%08X, s=0x%08X\n", sig.r[0], sig.s[0]);

    if (SM2_Verify(hash, sizeof(hash), &sig, &context)) {
        printf("SM2 sign/verify test passed\n");
    } else {
        printf("SM2 sign/verify test FAILED\n");
        return 1;
    }

    u8 plaintext[] = "Hello SM2!";
    u8 ciphertext[256] = {0};
    size_t ctLen = 0;
    SM2_Encrypt(plaintext, strlen((const char*)plaintext), ciphertext, &ctLen, &context);
    printf("SM2 encryption done, ctLen=%zu\n", ctLen);

    u8 decrypted[256] = {0};
    size_t ptLen = 0;
    if (SM2_Decrypt(ciphertext, ctLen, decrypted, &ptLen, &context) == 0) {
        decrypted[ptLen] = '\0';
        printf("SM2 decrypted: %s\n", decrypted);
        if (memcmp(plaintext, decrypted, strlen((const char*)plaintext)) == 0) {
            printf("SM2 encrypt/decrypt test passed\n");
        } else {
            printf("SM2 encrypt/decrypt test FAILED\n");
            return 1;
        }
    } else {
        printf("SM2 decrypt FAILED\n");
        return 1;
    }

    return 0;
}
