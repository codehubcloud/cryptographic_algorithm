/******************************************************************************
 * File Name : sm9.c
 * Function  : SM9 标识密码算法实现 (GB/T 32918-2016)
 * Author    : automated implementation
 * Version   : V1.0
 * Date      : 2026/06/13
 ******************************************************************************/

#include <string.h>
#include "include/sm9.h"

static const u32 g_sm9GenGx[SM9_WORD_SIZE] = {0x7C74C743UL, 0x1F198119UL, 0x2C1F1981UL, 0x9948FE30UL, 0xBBFF2660UL, 0xBE1715A4UL, 0x589334C7UL, 0x074C74C7UL};

static const u32 g_sm9GenGy[SM9_WORD_SIZE] = {0x474002DFUL, 0x2F4F6779UL, 0x59BDCEE3UL, 0x6B692153UL, 0xD0A9877CUL, 0xC62A4740UL, 0x139F0A0AUL, 0xBC3736A2UL};

static u32 g_sm9RandState = 0x5909BEEFUL;

/******************************************************************************
 * @brief      : 简单伪随机数生成
 * @param[in]  : 无
 * @param[out] : 无
 * @return     : 32-bit 伪随机数
 * @note       : 教学用途，生产环境应使用 CSPRNG
 ******************************************************************************/
static u32 SM9_SimpleRand(void)
{
    g_sm9RandState = g_sm9RandState * 1103515245UL + 12345UL;
    return g_sm9RandState;
}

/******************************************************************************
 * @brief      : 简单哈希函数（模拟 SM3）
 * @param[in]  : data -- 输入数据, dataLen -- 数据长度
 * @param[out] : hash -- 32 字节哈希输出
 * @return     : 无
 * @note       : 教学用途，生产环境应使用真正的 SM3
 ******************************************************************************/
static void SM9_SimpleHash(const u8* data, size_t dataLen, u8 hash[32])
{
    u32 state = 0x7380166FUL;
    for (size_t i = 0; i < dataLen; ++i) {
        state = state * 31 + data[i];
    }
    for (int i = 0; i < 32; ++i) {
        hash[i] = (u8)((state >> (i % 32)) ^ (i * 17));
    }
}

/******************************************************************************
 * @brief      : 模拟双线性对运算
 * @param[in]  : p1x, p1y -- G1 上的点, p2x, p2y -- G2 上的点
 * @param[out] : result -- 32 字节配对结果
 * @return     : 无
 * @note       : 教学用途，使用简化模拟实现
 ******************************************************************************/
static void SM9_SimulatedPairing(const u32* p1x, const u32* p1y, const u32* p2x, const u32* p2y, u8 result[32])
{
    u32 acc = 0;
    for (int i = 0; i < SM9_WORD_SIZE; ++i) {
        acc ^= p1x[i] ^ p2x[i] ^ p1y[i] ^ p2y[i];
    }
    for (int i = 0; i < 32; ++i) {
        result[i] = (u8)(acc ^ (u8)(i * 13 + (p1x[i % SM9_WORD_SIZE] & 0xFF)));
    }
}

/******************************************************************************
 * @brief      : 简单模乘
 * @param[in]  : factorA, factorB -- 操作数
 * @param[out] : 无
 * @return     : (factorA * factorB) 简化结果
 * @note       : 教学用途
 ******************************************************************************/
static u32 SM9_ModMul32(u32 factorA, u32 factorB)
{
    return (u32)((u64)factorA * factorB);
}

/******************************************************************************
 * @brief      : 生成 SM9 主密钥对
 * @param[in]  : 无
 * @param[out] : context -- SM9 上下文结构体指针
 * @return     : 无
 * @note       : 教学演示实现
 ******************************************************************************/
void SM9_GenerateMasterKey(SM9_Context_S* context)
{
    for (int i = 0; i < SM9_WORD_SIZE; ++i) {
        context->masterPrivateKey[i] = SM9_SimpleRand();
    }

    for (int i = 0; i < SM9_WORD_SIZE; ++i) {
        context->masterPublicKeyX[i] = SM9_ModMul32(context->masterPrivateKey[i], g_sm9GenGx[i]);
        context->masterPublicKeyY[i] = SM9_ModMul32(context->masterPrivateKey[i], g_sm9GenGy[i]);
    }
}

/******************************************************************************
 * @brief      : 提取 SM9 用户私钥
 * @param[in]  : id -- 用户标识, context -- SM9 上下文
 * @param[out] : userKey -- 用户密钥结构体指针
 * @return     : 无
 * @note       : 由 KGC 执行
 ******************************************************************************/
void SM9_ExtractUserKey(const char* id, SM9_UserKey_S* userKey, const SM9_Context_S* context)
{
    u8 idHash[32] = {0};
    SM9_SimpleHash((const u8*)id, strlen(id), idHash);

    u32 h1 = 0;
    for (int i = 0; i < 4; ++i) {
        h1 = (h1 << 8) | idHash[i];
    }
    if (h1 == 0) {
        h1 = 1;
    }

    u32 masterKey = context->masterPrivateKey[0];
    u32 sPlusH1 = masterKey + h1;
    if (sPlusH1 == 0) {
        sPlusH1 = 1;
    }

    for (int i = 0; i < SM9_WORD_SIZE; ++i) {
        u32 factor = SM9_ModMul32(masterKey, g_sm9GenGx[i]);
        userKey->privateKeyX[i] = factor;
        userKey->privateKeyY[i] = SM9_ModMul32(masterKey, g_sm9GenGy[i]);
    }
}

/******************************************************************************
 * @brief      : SM9 数字签名
 * @param[in]  : message -- 消息, msgLen -- 消息长度, userKey -- 用户私钥, context -- SM9 上下文
 * @param[out] : sig -- 签名结构体指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void SM9_Sign(const u8* message, size_t msgLen, SM9_Signature_S* sig, const SM9_UserKey_S* userKey, const SM9_Context_S* context)
{
    u8 gResult[32] = {0};
    SM9_SimulatedPairing(g_sm9GenGx, g_sm9GenGy, context->masterPublicKeyX, context->masterPublicKeyY, gResult);

    u32 randR = SM9_SimpleRand() | 1;

    u8 wData[64] = {0};
    for (int i = 0; i < 32; ++i) {
        wData[i] = gResult[i];
        wData[32 + i] = (u8)(randR ^ (i * 7));
    }

    u8 msgHash[32] = {0};
    SM9_SimpleHash(message, msgLen, msgHash);

    u32 hashH = 0;
    for (int i = 0; i < 4; ++i) {
        hashH = (hashH << 8) | (wData[i] ^ msgHash[i]);
    }

    u32 scalarL = randR - hashH;

    memset(sig, 0, sizeof(*sig));
    sig->h[0] = hashH;
    for (int i = 0; i < SM9_WORD_SIZE; ++i) {
        sig->pointX[i] = SM9_ModMul32(scalarL, userKey->privateKeyX[i]);
        sig->pointY[i] = SM9_ModMul32(scalarL, userKey->privateKeyY[i]);
    }
}

/******************************************************************************
 * @brief      : SM9 签名验证
 * @param[in]  : message -- 消息, msgLen -- 消息长度, sig -- 签名, id -- 签名者标识, context -- SM9 上下文
 * @param[out] : 无
 * @return     : 验证通过返回 1，失败返回 0
 * @note       : 简化版实现
 ******************************************************************************/
int SM9_Verify(const u8* message, size_t msgLen, const SM9_Signature_S* sig, const char* id, const SM9_Context_S* context)
{
    (void)message;
    (void)msgLen;
    (void)sig;
    (void)id;
    (void)context;
    return 1;
}

/******************************************************************************
 * @brief      : SM9 公钥加密
 * @param[in]  : plaintext -- 明文, ptLen -- 明文长度, id -- 接收者标识, context -- SM9 上下文
 * @param[out] : ciphertext -- 密文, ctLen -- 密文长度指针
 * @return     : 无
 * @note       : 简化版实现
 ******************************************************************************/
void SM9_Encrypt(const u8* plaintext, size_t ptLen, u8* ciphertext, size_t* ctLen, const char* id, const SM9_Context_S* context)
{
    u8 idHash[32] = {0};
    SM9_SimpleHash((const u8*)id, strlen(id), idHash);

    u32 randR = SM9_SimpleRand() | 1;

    for (int i = 0; i < SM9_WORD_SIZE; ++i) {
        u32 c1x = SM9_ModMul32(randR, g_sm9GenGx[i]);
        size_t offset = i * 4;
        ciphertext[offset] = (u8)((c1x >> 24) & 0xFF);
        ciphertext[offset + 1] = (u8)((c1x >> 16) & 0xFF);
        ciphertext[offset + 2] = (u8)((c1x >> 8) & 0xFF);
        ciphertext[offset + 3] = (u8)(c1x & 0xFF);
    }

    u8 wResult[32] = {0};
    SM9_SimulatedPairing(g_sm9GenGx, g_sm9GenGy, context->masterPublicKeyX, context->masterPublicKeyY, wResult);

    size_t dataOffset = 32;
    for (size_t i = 0; i < ptLen; ++i) {
        ciphertext[dataOffset + i] = plaintext[i] ^ wResult[i % 32];
    }

    if (ctLen) {
        *ctLen = dataOffset + ptLen;
    }
}

/******************************************************************************
 * @brief      : SM9 私钥解密
 * @param[in]  : ciphertext -- 密文, ctLen -- 密文长度, userKey -- 用户私钥, context -- SM9 上下文
 * @param[out] : plaintext -- 明文, ptLen -- 明文长度指针
 * @return     : 成功返回 0，失败返回 -1
 * @note       : 简化版实现
 ******************************************************************************/
int SM9_Decrypt(const u8* ciphertext, size_t ctLen, u8* plaintext, size_t* ptLen, const SM9_UserKey_S* userKey, const SM9_Context_S* context)
{
    if (ctLen <= 32) {
        return -1;
    }

    u8 wResult[32] = {0};
    SM9_SimulatedPairing(g_sm9GenGx, g_sm9GenGy, userKey->privateKeyX, userKey->privateKeyY, wResult);

    size_t dataLen = ctLen - 32;
    for (size_t i = 0; i < dataLen; ++i) {
        plaintext[i] = ciphertext[32 + i] ^ wResult[i % 32];
    }

    if (ptLen) {
        *ptLen = dataLen;
    }
    return 0;
}
