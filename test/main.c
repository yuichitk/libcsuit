#include <stdlib.h>
#include "csuit/csuit.h"
#include <CUnit/CUnit.h>
#include <CUnit/Console.h>

void test_csuit_rollback(void);

int main(int argc, char *argv[]) {
    CU_pSuite suite;
    CU_initialize_registry();
    suite = CU_add_suite("SUIT", NULL, NULL);
    CU_add_test(suite, "test_csuit_rollback", test_csuit_rollback);
    CU_console_run_tests();
    CU_cleanup_registry();
    return 0;
}

size_t test_csuit_rollback_buf(const uint8_t *buf, const size_t len) {
    QCBORDecodeContext context;
    QCBORItem item;
    QCBORDecode_Init(&context, (UsefulBufC){buf, len}, QCBOR_DECODE_MODE_NORMAL);
    int32_t result = suit_qcbor_get_next(&context, &item, QCBOR_TYPE_ANY);
    size_t cursor = UsefulInputBuf_Tell(&context.InBuf);
    QCBORDecode_Finish(&context);
    CU_ASSERT(result == SUIT_SUCCESS);
    return suit_qcbor_calc_rollback(&item) - cursor;
}

void test_csuit_rollback(void) {
    uint8_t bufu0[] = {0x17}; // unsigned(23)
    CU_ASSERT(test_csuit_rollback_buf(bufu0, sizeof(bufu0)) == 0);
    uint8_t bufu1[] = {0x18, 0x18}; // unsigned(24)
    CU_ASSERT(test_csuit_rollback_buf(bufu1, sizeof(bufu1)) == 0);
    uint8_t bufu2[] = {0x18, 0xFF}; // unsigned(255)
    CU_ASSERT(test_csuit_rollback_buf(bufu2, sizeof(bufu2)) == 0);
    uint8_t bufu3[] = {0x19, 0x01, 0x00}; // unsigned(256)
    CU_ASSERT(test_csuit_rollback_buf(bufu3, sizeof(bufu3)) == 0);
    uint8_t bufu4[] = {0x19, 0xFF, 0xFF}; // unsigned(65535)
    CU_ASSERT(test_csuit_rollback_buf(bufu4, sizeof(bufu4)) == 0);
    uint8_t bufu5[] = {0x1A, 0x00, 0x01, 0x00, 0x00}; // unsigned(65536)
    CU_ASSERT(test_csuit_rollback_buf(bufu5, sizeof(bufu5)) == 0);
    uint8_t bufu6[] = {0x1A, 0xFF, 0xFF, 0xFF, 0xFF}; // unsigned(4294967295)
    CU_ASSERT(test_csuit_rollback_buf(bufu6, sizeof(bufu6)) == 0);
    uint8_t bufu7[] = {0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    CU_ASSERT(test_csuit_rollback_buf(bufu7, sizeof(bufu7)) == 0);
    uint8_t bufu8[] = {0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // unsigned(18446744073709551615)
    CU_ASSERT(test_csuit_rollback_buf(bufu8, sizeof(bufu8)) == 0);

    uint8_t bufn0[] = {0x37}; // negative(23) = -24
    CU_ASSERT(test_csuit_rollback_buf(bufn0, sizeof(bufn0)) == 0);
    uint8_t bufn1[] = {0x38, 0x18}; // negative(24) = -25
    CU_ASSERT(test_csuit_rollback_buf(bufn1, sizeof(bufn1)) == 0);
    uint8_t bufn2[] = {0x38, 0xFF}; // negative(255) = -256
    CU_ASSERT(test_csuit_rollback_buf(bufn2, sizeof(bufn2)) == 0);
    uint8_t bufn3[] = {0x39, 0x01, 0x00}; // negative(256) = -257
    CU_ASSERT(test_csuit_rollback_buf(bufn3, sizeof(bufn3)) == 0);
    uint8_t bufn4[] = {0x39, 0xFF, 0xFF}; // negative(65535) = -65536
    CU_ASSERT(test_csuit_rollback_buf(bufn4, sizeof(bufn4)) == 0);
    uint8_t bufn5[] = {0x3A, 0x00, 0x01, 0x00, 0x00}; // negative(65536) = -65537
    CU_ASSERT(test_csuit_rollback_buf(bufn5, sizeof(bufn5)) == 0);
    uint8_t bufn6[] = {0x3A, 0xFF, 0xFF, 0xFF, 0xFF}; // negative(4294967295) = -4294967296
    CU_ASSERT(test_csuit_rollback_buf(bufn6, sizeof(bufn6)) == 0);
    uint8_t bufn7[] = {0x3B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}; // negative(4294967296)
    CU_ASSERT(test_csuit_rollback_buf(bufn7, sizeof(bufn7)) == 0);
    uint8_t bufn8[] = {0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // negative(9223372036854775807) = -9223372036854775808
    CU_ASSERT(test_csuit_rollback_buf(bufn8, sizeof(bufn8)) == 0);

    uint8_t buft0[] = {0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77};
    CU_ASSERT(test_csuit_rollback_buf(buft0, sizeof(buft0)) == 0);
    uint8_t buft1[] = {0x78, 0x18, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78};
    CU_ASSERT(test_csuit_rollback_buf(buft1, sizeof(buft1)) == 0);
    uint8_t buft2[259]; // text(255)
    buft2[0] = 0x78;
    buft2[1] = 0xFF;
    memset(&buft2[2], 'a', 259 - 2);
    CU_ASSERT(test_csuit_rollback_buf(buft2, 2 + 255) == 0);
    buft2[0] = 0x79; // text(256)
    buft2[1] = 0x01;
    buft2[2] = 0x00;
    CU_ASSERT(test_csuit_rollback_buf(buft2, 259) == 0);
    uint8_t *buft3 = (uint8_t *)malloc(UINT16_MAX + 6);
    buft3[0] = 0x79;
    buft3[1] = 0xFF;
    buft3[2] = 0xFF;
    memset(&buft3[3], 'a', UINT16_MAX + 6 - 3);
    CU_ASSERT(test_csuit_rollback_buf(buft3, UINT16_MAX + 3) == 0);
    buft3[0] = 0x7A;
    buft3[1] = 0x00;
    buft3[2] = 0x01;
    buft3[3] = 0x00;
    buft3[4] = 0x00;
    CU_ASSERT(test_csuit_rollback_buf(buft3, UINT16_MAX + 6) == 0);
    free(buft3);

    uint8_t bufa0[26];
    bufa0[0] = 0x97; // array(23)
    memset(&bufa0[1], 0, 26 - 1);
    CU_ASSERT(test_csuit_rollback_buf(bufa0, 24) == 0);
    bufa0[0] = 0x98; // array(24)
    bufa0[1] = 0x18;
    CU_ASSERT(test_csuit_rollback_buf(bufa0, 26) == 0);
}

