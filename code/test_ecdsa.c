/******************************************************************************
 * File Name : test_ecdsa.c
 * Function  : ECDSA 签名/验证自检
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include "include/ecdsa.h"

/******************************************************************************
 * @brief      : 主测试入口
 * @param[in]  : 无
 * @param[out] : 无
 * @return     : 测试通过返回 0，失败返回 1
 * @note       : 无
 ******************************************************************************/
int main(void)
{
    ECDSA_Context_S context;
    ECDSA_GenerateKey(&context);
    printf("ECDSA key generated\n");

    u8 hash[] = {0xAB, 0xCD, 0xEF, 0x01};
    ECDSA_Signature_S sig;
    ECDSA_Sign(hash, sizeof(hash), &sig, &context);
    printf("ECDSA signature: r=0x%08X, s=0x%08X\n", sig.r[0], sig.s[0]);

    if (ECDSA_Verify(hash, sizeof(hash), &sig, &context)) {
        printf("ECDSA sign/verify test passed\n");
    } else {
        printf("ECDSA sign/verify test FAILED\n");
        return 1;
    }

    u8 wrongHash[] = {0xAB, 0xCD, 0xEF, 0x02};
    if (!ECDSA_Verify(wrongHash, sizeof(wrongHash), &sig, &context)) {
        printf("ECDSA wrong hash rejection test passed\n");
    } else {
        printf("ECDSA wrong hash rejection test FAILED\n");
        return 1;
    }

    return 0;
}
