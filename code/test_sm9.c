/******************************************************************************
 * File Name : test_sm9.c
 * Function  : SM9 签名/验证与加密/解密自检
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include "include/sm9.h"

/******************************************************************************
 * @brief      : 主测试入口
 * @param[in]  : 无
 * @param[out] : 无
 * @return     : 测试通过返回 0，失败返回 1
 * @note       : 无
 ******************************************************************************/
int main(void)
{
    SM9_Context_S context;
    SM9_GenerateMasterKey(&context);
    printf("SM9 master key generated\n");

    const char* userId = "alice@example.com";
    SM9_UserKey_S userKey;
    SM9_ExtractUserKey(userId, &userKey, &context);
    printf("SM9 user key extracted for: %s\n", userId);

    const u8 message[] = "Hello SM9!";
    SM9_Signature_S sig;
    SM9_Sign(message, strlen((const char*)message), &sig, &userKey, &context);
    printf("SM9 signature: h=0x%08X\n", sig.h[0]);

    if (SM9_Verify(message, strlen((const char*)message), &sig, userId, &context)) {
        printf("SM9 sign/verify test passed\n");
    } else {
        printf("SM9 sign/verify test FAILED\n");
        return 1;
    }

    const char* recipientId = "bob@example.com";
    u8 plaintext[] = "Hello SM9 Encryption!";
    u8 ciphertext[256] = {0};
    size_t ctLen = 0;
    SM9_Encrypt(plaintext, strlen((const char*)plaintext), ciphertext, &ctLen, recipientId, &context);
    printf("SM9 encryption done, ctLen=%zu\n", ctLen);

    SM9_UserKey_S recipientKey;
    SM9_ExtractUserKey(recipientId, &recipientKey, &context);

    u8 decrypted[256] = {0};
    size_t ptLen = 0;
    if (SM9_Decrypt(ciphertext, ctLen, decrypted, &ptLen, &recipientKey, &context) == 0) {
        decrypted[ptLen] = '\0';
        printf("SM9 decrypted: %s\n", decrypted);
        if (memcmp(plaintext, decrypted, strlen((const char*)plaintext)) == 0) {
            printf("SM9 encrypt/decrypt test passed\n");
        } else {
            printf("SM9 encrypt/decrypt test FAILED\n");
            return 1;
        }
    } else {
        printf("SM9 decrypt FAILED\n");
        return 1;
    }

    return 0;
}
