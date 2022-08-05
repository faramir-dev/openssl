/*
 * Copyright 2018-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/trace.h>

#include "testutil.h"

static const int NO_ENGINE =
#ifndef OPENSSL_NO_ENGINE
    0;
#else
    1;
#endif



static int test_trace_categories(void)
{
    for (int cat_num = -1; cat_num <= OSSL_TRACE_CATEGORY_NUM; ++cat_num) {
        const char *cat_name = OSSL_trace_get_category_name(cat_num);

        switch (cat_num) {
        case OSSL_TRACE_CATEGORY_ALL:
            if(!TEST_str_eq(cat_name, "ALL"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_TRACE:
            if(!TEST_str_eq(cat_name, "TRACE"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_INIT:
            if(!TEST_str_eq(cat_name, "INIT"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_TLS:
            if(!TEST_str_eq(cat_name, "TLS"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_TLS_CIPHER:
            if(!TEST_str_eq(cat_name, "TLS_CIPHER"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_CONF:
            if(!TEST_str_eq(cat_name, "CONF"))
                return 0;
            break;
#ifndef OPENSSL_NO_ENGINE
        case OSSL_TRACE_CATEGORY_ENGINE_TABLE:
            if(!TEST_str_eq(cat_name, "ENGINE_TABLE"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_ENGINE_REF_COUNT:
            if(!TEST_str_eq(cat_name, "ENGINE_REF_COUNT"))
                return 0;
            break;
#endif
        case OSSL_TRACE_CATEGORY_PKCS5V2:
            if(!TEST_str_eq(cat_name, "PKCS5V2"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_PKCS12_KEYGEN:
            if(!TEST_str_eq(cat_name, "PKCS12_KEYGEN"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_PKCS12_DECRYPT:
            if(!TEST_str_eq(cat_name, "PKCS12_DECRYPT"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_X509V3_POLICY:
            if(!TEST_str_eq(cat_name, "X509V3_POLICY"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_BN_CTX:
            if(!TEST_str_eq(cat_name, "BN_CTX"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_CMP:
            if(!TEST_str_eq(cat_name, "CMP"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_STORE:
            if(!TEST_str_eq(cat_name, "STORE"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_DECODER:
            if(!TEST_str_eq(cat_name, "DECODER"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_ENCODER:
            if(!TEST_str_eq(cat_name, "ENCODER"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_REF_COUNT:
            if(!TEST_str_eq(cat_name, "REF_COUNT"))
                return 0;
            break;
        case OSSL_TRACE_CATEGORY_HTTP:
            if(!TEST_str_eq(cat_name, "HTTP"))
                return 0;
            break;
        default:
            if (!TEST_ptr_null(cat_name))
                return 0;
            break;
        }

        const int ret_cat_num =
            OSSL_trace_get_category_num(cat_name);
        const int expected_ret = cat_name != NULL ? cat_num : -1;
        if (!TEST_int_eq(expected_ret, ret_cat_num))
            return 0;
    }
    return 1;
}

OPT_TEST_DECLARE_USAGE("\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

/*
    if (!TEST_ptr(certin = test_get_argument(0))
            || !TEST_ptr(privkeyin = test_get_argument(1))
            || !TEST_ptr(derin = test_get_argument(2)))
        return 0;
*/

    ADD_TEST(test_trace_categories);
    return 1;
}

void cleanup_tests(void)
{
}
