/******************************************************************************
 * File Name : test_rsa.c
 * Function  : RSA 加密/解密与签名/验证自检
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include "include/rsa.h"

/******************************************************************************
 * @brief      : 主测试入口
 * @param[in]  : 无
 * @param[out] : 无
 * @return     : 测试通过返回 0，失败返回 1
 * @note       : 无
 ******************************************************************************/
int main(void)
{
    RSA_Context_S context;
    RSA_GenerateKey(32, &context);

    printf("RSA key generated: n=0x%08X, e=%u, d=0x%08X\n", context.modulus[0], context.publicExp, context.privateExp[0]);

    u8 plaintext[] = {0x00, 0x01, 0x02, 0x03};
    u8 ciphertext[4] = {0};
    size_t ctLen = 0;
    RSA_Encrypt(plaintext, sizeof(plaintext), ciphertext, &ctLen, &context);

    u8 decrypted[4] = {0};
    size_t ptLen = 0;
    RSA_Decrypt(ciphertext, ctLen, decrypted, &ptLen, &context);

    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("RSA encrypt/decrypt test passed\n");
    } else {
        printf("RSA encrypt/decrypt test FAILED\n");
        return 1;
    }

    u8 hash[] = {0xAA, 0xBB, 0xCC, 0xDD};
    u8 signature[4] = {0};
    size_t sigLen = 0;
    RSA_Sign(hash, sizeof(hash), signature, &sigLen, &context);

    if (RSA_Verify(hash, sizeof(hash), signature, sigLen, &context)) {
        printf("RSA sign/verify test passed\n");
    } else {
        printf("RSA sign/verify test FAILED\n");
        return 1;
    }

    return 0;
}
