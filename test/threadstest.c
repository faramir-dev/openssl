/*
 * Copyright 2016-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * The test_multi_downgrade_shared_pkey function tests the thread safety of a
 * deprecated function.
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
# define OPENSSL_SUPPRESS_DEPRECATED
#endif

#if defined(_WIN32)
# include <windows.h>
#endif

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include "internal/tsan_assist.h"
#include "internal/nelem.h"
#include "testutil.h"
#include "threadstest.h"

/* Limit the maximum number of threads */
#define MAXIMUM_THREADS     32

/* Limit the maximum number of providers loaded into a library context */
#define MAXIMUM_PROVIDERS   4

static int do_fips = 0;
static char *privkey;
static char *config_file = NULL;
static int multidefault_run = 0;

static const char *default_provider[] = { "default", NULL };
static const char *fips_provider[] = { "fips", NULL };
static const char *fips_and_default_providers[] = { "default", "fips", NULL };

#ifdef TSAN_REQUIRES_LOCKING
static CRYPTO_RWLOCK *tsan_lock;
#endif

/* Grab a globally unique integer value, return 0 on failure */
static int get_new_uid(void)
{
    /*
     * Start with a nice large number to avoid potential conflicts when
     * we generate a new OID.
     */
    static TSAN_QUALIFIER int current_uid = 1 << (sizeof(int) * 8 - 2);
#ifdef TSAN_REQUIRES_LOCKING
    int r;

    if (!TEST_true(CRYPTO_THREAD_write_lock(tsan_lock)))
        return 0;
    r = ++current_uid;
    if (!TEST_true(CRYPTO_THREAD_unlock(tsan_lock)))
        return 0;
    return r;

#else
    return tsan_counter(&current_uid);
#endif
}

static int test_lock(void)
{
    CRYPTO_RWLOCK *lock = CRYPTO_THREAD_lock_new();
    int res;

    res = TEST_true(CRYPTO_THREAD_read_lock(lock))
          && TEST_true(CRYPTO_THREAD_unlock(lock))
          && TEST_true(CRYPTO_THREAD_write_lock(lock))
          && TEST_true(CRYPTO_THREAD_unlock(lock));

    CRYPTO_THREAD_lock_free(lock);

    return res;
}

static CRYPTO_ONCE once_run = CRYPTO_ONCE_STATIC_INIT;
static unsigned once_run_count = 0;

static void once_do_run(void)
{
    once_run_count++;
}

static void once_run_thread_cb(void)
{
    CRYPTO_THREAD_run_once(&once_run, once_do_run);
}

static int test_once(void)
{
    thread_t thread;

    if (!TEST_true(run_thread(&thread, once_run_thread_cb))
        || !TEST_true(wait_for_thread(thread))
        || !CRYPTO_THREAD_run_once(&once_run, once_do_run)
        || !TEST_int_eq(once_run_count, 1))
        return 0;
    return 1;
}

static CRYPTO_THREAD_LOCAL thread_local_key;
static unsigned destructor_run_count = 0;
static int thread_local_thread_cb_ok = 0;

static void thread_local_destructor(void *arg)
{
    unsigned *count;

    if (arg == NULL)
        return;

    count = arg;

    (*count)++;
}

static void thread_local_thread_cb(void)
{
    void *ptr;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr)
        || !TEST_true(CRYPTO_THREAD_set_local(&thread_local_key,
                                              &destructor_run_count)))
        return;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_eq(ptr, &destructor_run_count))
        return;

    thread_local_thread_cb_ok = 1;
}

static int test_thread_local(void)
{
    thread_t thread;
    void *ptr = NULL;

    if (!TEST_true(CRYPTO_THREAD_init_local(&thread_local_key,
                                            thread_local_destructor)))
        return 0;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr)
        || !TEST_true(run_thread(&thread, thread_local_thread_cb))
        || !TEST_true(wait_for_thread(thread))
        || !TEST_int_eq(thread_local_thread_cb_ok, 1))
        return 0;

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr))
        return 0;

# if !defined(OPENSSL_SYS_WINDOWS)
    if (!TEST_int_eq(destructor_run_count, 1))
        return 0;
# endif
#endif

    if (!TEST_true(CRYPTO_THREAD_cleanup_local(&thread_local_key)))
        return 0;
    return 1;
}

static int test_atomic(void)
{
    int val = 0, ret = 0, testresult = 0;
    uint64_t val64 = 1, ret64 = 0;
    CRYPTO_RWLOCK *lock = CRYPTO_THREAD_lock_new();

    if (!TEST_ptr(lock))
        return 0;

    if (CRYPTO_atomic_add(&val, 1, &ret, NULL)) {
        /* This succeeds therefore we're on a platform with lockless atomics */
        if (!TEST_int_eq(val, 1) || !TEST_int_eq(val, ret))
            goto err;
    } else {
        /* This failed therefore we're on a platform without lockless atomics */
        if (!TEST_int_eq(val, 0) || !TEST_int_eq(val, ret))
            goto err;
    }
    val = 0;
    ret = 0;

    if (!TEST_true(CRYPTO_atomic_add(&val, 1, &ret, lock)))
        goto err;
    if (!TEST_int_eq(val, 1) || !TEST_int_eq(val, ret))
        goto err;

    if (CRYPTO_atomic_or(&val64, 2, &ret64, NULL)) {
        /* This succeeds therefore we're on a platform with lockless atomics */
        if (!TEST_uint_eq((unsigned int)val64, 3)
                || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
            goto err;
    } else {
        /* This failed therefore we're on a platform without lockless atomics */
        if (!TEST_uint_eq((unsigned int)val64, 1)
                || !TEST_int_eq((unsigned int)ret64, 0))
            goto err;
    }
    val64 = 1;
    ret64 = 0;

    if (!TEST_true(CRYPTO_atomic_or(&val64, 2, &ret64, lock)))
        goto err;

    if (!TEST_uint_eq((unsigned int)val64, 3)
            || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
        goto err;

    ret64 = 0;
    if (CRYPTO_atomic_load(&val64, &ret64, NULL)) {
        /* This succeeds therefore we're on a platform with lockless atomics */
        if (!TEST_uint_eq((unsigned int)val64, 3)
                || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
            goto err;
    } else {
        /* This failed therefore we're on a platform without lockless atomics */
        if (!TEST_uint_eq((unsigned int)val64, 3)
                || !TEST_int_eq((unsigned int)ret64, 0))
            goto err;
    }

    ret64 = 0;
    if (!TEST_true(CRYPTO_atomic_load(&val64, &ret64, lock)))
        goto err;

    if (!TEST_uint_eq((unsigned int)val64, 3)
            || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
        goto err;

    testresult = 1;
 err:
    CRYPTO_THREAD_lock_free(lock);
    return testresult;
}

static OSSL_LIB_CTX *multi_libctx = NULL;
static int multi_success;
static OSSL_PROVIDER *multi_provider[MAXIMUM_PROVIDERS + 1];
static size_t multi_num_threads;
static thread_t multi_threads[MAXIMUM_THREADS];

static void multi_intialise(void)
{
    multi_success = 1;
    multi_libctx = NULL;
    multi_num_threads = 0;
    memset(multi_threads, 0, sizeof(multi_threads));
    memset(multi_provider, 0, sizeof(multi_provider));
}

static void thead_teardown_libctx(void)
{
    OSSL_PROVIDER **p;

    for (p = multi_provider; *p != NULL; p++)
        OSSL_PROVIDER_unload(*p);
    OSSL_LIB_CTX_free(multi_libctx);
    multi_intialise();
}

static int thread_setup_libctx(int libctx, const char *providers[])
{
    size_t n;

    if (libctx && !TEST_true(test_get_libctx(&multi_libctx, NULL, config_file,
                                             NULL, NULL)))
        return 0;

    if (providers != NULL)
        for (n = 0; providers[n] != NULL; n++)
            if (!TEST_size_t_lt(n, MAXIMUM_PROVIDERS)
                || !TEST_ptr(multi_provider[n] = OSSL_PROVIDER_load(multi_libctx,
                                                                    providers[n]))) {
                thead_teardown_libctx();
                return 0;
            }
    return 1;
}

static int teardown_threads(void)
{
    size_t i;

    for (i = 0; i < multi_num_threads; i++)
        if (!TEST_true(wait_for_thread(multi_threads[i])))
            return 0;
    return 1;
}

static int start_threads(size_t n, void (*thread_func)(void))
{
    size_t i;

    if (!TEST_size_t_le(multi_num_threads + n, MAXIMUM_THREADS))
        return 0;

    for (i = 0 ; i < n; i++)
        if (!TEST_true(run_thread(multi_threads + multi_num_threads++, thread_func)))
            return 0;
    return 1;
}

/* Template multi-threaded test function */
static int thread_run_test(void (*main_func)(void),
                           size_t num_threads, void (*thread_func)(void),
                           int libctx, const char *providers[])
{
    int testresult = 0;

    multi_intialise();
    if (!thread_setup_libctx(libctx, providers)
            || !start_threads(num_threads, thread_func))
        goto err;

    if (main_func != NULL)
        main_func();

    if (!teardown_threads()
            || !TEST_true(multi_success))
        goto err;
    testresult = 1;
 err:
    thead_teardown_libctx();
    return testresult;
}

static void thread_general_worker(void)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_MD *md = EVP_MD_fetch(multi_libctx, "SHA2-256", NULL);
    EVP_CIPHER_CTX *cipherctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER *ciph = EVP_CIPHER_fetch(multi_libctx, "AES-128-CBC", NULL);
    const char *message = "Hello World";
    size_t messlen = strlen(message);
    /* Should be big enough for encryption output too */
    unsigned char out[EVP_MAX_MD_SIZE];
    const unsigned char key[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned int mdoutl;
    int ciphoutl;
    EVP_PKEY *pkey = NULL;
    int testresult = 0;
    int i, isfips;

    isfips = OSSL_PROVIDER_available(multi_libctx, "fips");

    if (!TEST_ptr(mdctx)
            || !TEST_ptr(md)
            || !TEST_ptr(cipherctx)
            || !TEST_ptr(ciph))
        goto err;

    /* Do some work */
    for (i = 0; i < 5; i++) {
        if (!TEST_true(EVP_DigestInit_ex(mdctx, md, NULL))
                || !TEST_true(EVP_DigestUpdate(mdctx, message, messlen))
                || !TEST_true(EVP_DigestFinal(mdctx, out, &mdoutl)))
            goto err;
    }
    for (i = 0; i < 5; i++) {
        if (!TEST_true(EVP_EncryptInit_ex(cipherctx, ciph, NULL, key, iv))
                || !TEST_true(EVP_EncryptUpdate(cipherctx, out, &ciphoutl,
                                                (unsigned char *)message,
                                                messlen))
                || !TEST_true(EVP_EncryptFinal(cipherctx, out, &ciphoutl)))
            goto err;
    }

    /*
     * We want the test to run quickly - not securely.
     * Therefore we use an insecure bit length where we can (512).
     * In the FIPS module though we must use a longer length.
     */
    pkey = EVP_PKEY_Q_keygen(multi_libctx, NULL, "RSA", isfips ? 2048 : 512);
    if (!TEST_ptr(pkey))
        goto err;

    testresult = 1;
 err:
    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);
    EVP_CIPHER_CTX_free(cipherctx);
    EVP_CIPHER_free(ciph);
    EVP_PKEY_free(pkey);
    if (!testresult)
        multi_success = 0;
}

static void thread_multi_simple_fetch(void)
{
    EVP_MD *md = EVP_MD_fetch(multi_libctx, "SHA2-256", NULL);

    if (md != NULL)
        EVP_MD_free(md);
    else
        multi_success = 0;
}

static EVP_PKEY *shared_evp_pkey = NULL;

static void thread_shared_evp_pkey(void)
{
    char *msg = "Hello World";
    unsigned char ctbuf[256];
    unsigned char ptbuf[256];
    size_t ptlen, ctlen = sizeof(ctbuf);
    EVP_PKEY_CTX *ctx = NULL;
    int success = 0;
    int i;

    for (i = 0; i < 1 + do_fips; i++) {
        if (i > 0)
            EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(multi_libctx, shared_evp_pkey,
                                         i == 0 ? "provider=default"
                                                : "provider=fips");
        if (!TEST_ptr(ctx))
            goto err;

        if (!TEST_int_ge(EVP_PKEY_encrypt_init(ctx), 0)
                || !TEST_int_ge(EVP_PKEY_encrypt(ctx, ctbuf, &ctlen,
                                                (unsigned char *)msg, strlen(msg)),
                                                0))
            goto err;

        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(multi_libctx, shared_evp_pkey, NULL);

        if (!TEST_ptr(ctx))
            goto err;

        ptlen = sizeof(ptbuf);
        if (!TEST_int_ge(EVP_PKEY_decrypt_init(ctx), 0)
                || !TEST_int_gt(EVP_PKEY_decrypt(ctx, ptbuf, &ptlen, ctbuf, ctlen),
                                                0)
                || !TEST_mem_eq(msg, strlen(msg), ptbuf, ptlen))
            goto err;
    }

    success = 1;

 err:
    EVP_PKEY_CTX_free(ctx);
    if (!success)
        multi_success = 0;
}

static void thread_provider_load_unload(void)
{
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(multi_libctx, "default");

    if (!TEST_ptr(deflt)
            || !TEST_true(OSSL_PROVIDER_available(multi_libctx, "default")))
        multi_success = 0;

    OSSL_PROVIDER_unload(deflt);
}

static int test_multi_general_worker_default_provider(void)
{
    return thread_run_test(&thread_general_worker, 2, &thread_general_worker,
                           1, default_provider);
}

static int test_multi_general_worker_fips_provider(void)
{
    if (!do_fips)
        return TEST_skip("FIPS not supported");
    return thread_run_test(&thread_general_worker, 2, &thread_general_worker,
                           1, fips_provider);
}

static int test_multi_fetch_worker(void)
{
    return thread_run_test(&thread_multi_simple_fetch,
                           2, &thread_multi_simple_fetch, 1, default_provider);
}

static int test_multi_shared_pkey_common(void (*worker)(void))
{
    int testresult = 0;

    multi_intialise();
    if (!thread_setup_libctx(1, do_fips ? fips_and_default_providers
                                        : default_provider)
            || !TEST_ptr(shared_evp_pkey = load_pkey_pem(privkey, multi_libctx))
            || !start_threads(1, &thread_shared_evp_pkey)
            || !start_threads(1, worker))
        goto err;

    thread_shared_evp_pkey();

    if (!teardown_threads()
            || !TEST_true(multi_success))
        goto err;
    testresult = 1;
 err:
    EVP_PKEY_free(shared_evp_pkey);
    thead_teardown_libctx();
    return testresult;
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
static void thread_downgrade_shared_evp_pkey(void)
{
    /*
     * This test is only relevant for deprecated functions that perform
     * downgrading
     */
    if (EVP_PKEY_get0_RSA(shared_evp_pkey) == NULL)
        multi_success = 0;
}

static int test_multi_downgrade_shared_pkey(void)
{
    return test_multi_shared_pkey_common(&thread_downgrade_shared_evp_pkey);
}
#endif

static int test_multi_shared_pkey(void)
{
    return test_multi_shared_pkey_common(&thread_shared_evp_pkey);
}

static int test_multi_load_unload_provider(void)
{
    EVP_MD *sha256 = NULL;
    OSSL_PROVIDER *prov = NULL;
    int testresult = 0;

    multi_intialise();
    if (!thread_setup_libctx(1, NULL)
            || !TEST_ptr(prov = OSSL_PROVIDER_load(multi_libctx, "default"))
            || !TEST_ptr(sha256 = EVP_MD_fetch(multi_libctx, "SHA2-256", NULL))
            || !TEST_true(OSSL_PROVIDER_unload(prov)))
        goto err;
    prov = NULL;

    if (!start_threads(2, &thread_provider_load_unload))
        goto err;

    thread_provider_load_unload();

    if (!teardown_threads()
            || !TEST_true(multi_success))
        goto err;
    testresult = 1;
 err:
    OSSL_PROVIDER_unload(prov);
    EVP_MD_free(sha256);
    thead_teardown_libctx();
    return testresult;
}

static char *multi_load_provider = "legacy";
/*
 * This test attempts to load several providers at the same time, and if
 * run with a thread sanitizer, should crash if the core provider code
 * doesn't synchronize well enough.
 */
static void test_multi_load_worker(void)
{
    OSSL_PROVIDER *prov;

    if (!TEST_ptr(prov = OSSL_PROVIDER_load(multi_libctx, multi_load_provider))
            || !TEST_true(OSSL_PROVIDER_unload(prov)))
        multi_success = 0;
}

static int test_multi_default(void)
{
    /* Avoid running this test twice */
    if (multidefault_run) {
        TEST_skip("multi default test already run");
        return 1;
    }
    multidefault_run = 1;

    return thread_run_test(&thread_multi_simple_fetch,
                           2, &thread_multi_simple_fetch, 0, default_provider);
}

static int test_multi_load(void)
{
    int res = 1;
    OSSL_PROVIDER *prov;

    /* The multidefault test must run prior to this test */
    if (!multidefault_run) {
        TEST_info("Running multi default test first");
        res = test_multi_default();
    }

    /*
     * We use the legacy provider in test_multi_load_worker because it uses a
     * child libctx that might hit more codepaths that might be sensitive to
     * threading issues. But in a no-legacy build that won't be loadable so
     * we use the default provider instead.
     */
    prov = OSSL_PROVIDER_load(NULL, "legacy");
    if (prov == NULL) {
        TEST_info("Cannot load legacy provider - assuming this is a no-legacy build");
        multi_load_provider = "default";
    }
    OSSL_PROVIDER_unload(prov);

    return thread_run_test(NULL, MAXIMUM_THREADS, &test_multi_load_worker, 0,
                          NULL) && res;
}

static void test_obj_create_one(void)
{
    char tids[12], oid[40], sn[30], ln[30];
    int id = get_new_uid();

    BIO_snprintf(tids, sizeof(tids), "%d", id);
    BIO_snprintf(oid, sizeof(oid), "1.3.6.1.4.1.16604.%s", tids);
    BIO_snprintf(sn, sizeof(sn), "short-name-%s", tids);
    BIO_snprintf(ln, sizeof(ln), "long-name-%s", tids);
    if (!TEST_int_ne(id, 0)
            || !TEST_true(id = OBJ_create(oid, sn, ln))
            || !TEST_true(OBJ_add_sigid(id, NID_sha3_256, NID_rsa)))
        multi_success = 0;
}

static int test_obj_add(void)
{
    return thread_run_test(&test_obj_create_one,
                           MAXIMUM_THREADS, &test_obj_create_one,
                           1, default_provider);
}

static void test_lib_ctx_load_config_worker(void)
{
    if (!TEST_int_eq(OSSL_LIB_CTX_load_config(multi_libctx, config_file), 1))
        multi_success = 0;
}

static int test_lib_ctx_load_config(void)
{
    return thread_run_test(&test_lib_ctx_load_config_worker,
                           MAXIMUM_THREADS, &test_lib_ctx_load_config_worker,
                           1, default_provider);
}

# include <openssl/hmac.h>
# include <openssl/sha.h>
# ifndef OPENSSL_NO_MD5
#  include <openssl/md5.h>
# endif

# ifndef OPENSSL_NO_MD5
static struct test_st {
    const char key[16];
    int key_len;
    const unsigned char data[64];
    int data_len;
    const char *digest;
} const test[8] = {
    {
        "", 0, "More text test vectors to stuff up EBCDIC machines :-)", 54,
        "e9139d1e6ee064ef8cf514fc7dc83e86",
    },
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        16, "Hi There", 8,
        "9294727a3638bb1c13f48ef8158bfc9d",
    },
    {
        "Jefe", 4, "what do ya want for nothing?", 28,
        "750c783e6ab0b503eaa86e310a5db738",
    },
    {
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
        16, {
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd
        }, 50, "56be34521d144c88dbb8c733f0e8b3f6",
    },
    {
        "", 0, "My test data", 12,
        "61afdecb95429ef494d61fdee15990cabf0826fc"
    },
    {
        "", 0, "My test data", 12,
        "2274b195d90ce8e03406f4b526a47e0787a88a65479938f1a5baa3ce0f079776"
    },
    {
        "123456", 6, "My test data", 12,
        "bab53058ae861a7f191abe2d0145cbb123776a6369ee3f9d79ce455667e411dd"
    },
    {
        "12345", 5, "My test data again", 18,
        "a12396ceddd2a85f4c656bc1e0aa50c78cffde3e"
    }
};
# endif

static int test_18222_hmac_worker(void)
{
    int ret = 0;
    HMAC_CTX *ctx = NULL;
    ctx = HMAC_CTX_new();
    if (!TEST_ptr(ctx)
        || !TEST_ptr_null(HMAC_CTX_get_md(ctx))
        || !TEST_false(HMAC_Init_ex(ctx, NULL, 0, NULL, NULL))
        || !TEST_false(HMAC_Update(ctx, test[4].data, test[4].data_len))
        || !TEST_false(HMAC_Init_ex(ctx, NULL, 0, EVP_sha1(), NULL))
        || !TEST_false(HMAC_Update(ctx, test[4].data, test[4].data_len)))
        goto err;

    ret = 1;
err:
    HMAC_CTX_free(ctx);

    return ret;
}

#include <openssl/evp.h>
static int test_18222_evp_worker(void)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *dgst = NULL;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    const char *password = "password";
    const unsigned char *salt = (const unsigned char*)"01234567";

    ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(ctx))
        goto err;

    cipher = EVP_CIPHER_fetch(multi_libctx, "aes-256-cbc", NULL); //EVP_get_cipherbyname("aes-256-cbc");
    if (!TEST_ptr(cipher))
        goto err;

    dgst = EVP_MD_fetch(multi_libctx, "md5", NULL); //EVP_get_digestbyname("md5");
    if (!TEST_ptr(dgst))
        goto err;

    if(!TEST_int_gt(EVP_BytesToKey(cipher, dgst, salt,
                       (const unsigned char*)password,
                       (int)strlen(password), 1, key, iv),
                    0))
        goto err;

    if(!TEST_true(EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)))
        goto err;

    ret = 1;
err:
    // FIXME: Daniel: Free everything
    ERR_print_errors_fp(stderr);
    (void)0;
    return ret;
}

static void test_18222_init(void)
{
    //test_18222_evp_worker();
}

static int counter_18222 = 0;
static int passed_18222 = 0;
static void test_18222_worker(void)
{
    int ret = 0;
    int index = 0;
    //OSSL_LIB_CTX *oldctx = OSSL_LIB_CTX_set0_default(multi_libctx);

    if (!TEST_true(CRYPTO_atomic_add(&counter_18222, 1, &index, NULL)))
        goto err;

    switch (counter_18222 % 4) {
        case 0:
        case 1:
            ret = test_18222_evp_worker();
            break;
        case 2:
        case 3:
            ret = test_18222_hmac_worker();
            break;
    }

err:
    if (TEST_true(ret))
    {
        int passed;
        TEST_true(CRYPTO_atomic_add(&passed_18222, 1, &passed, NULL));
    }

    //OSSL_LIB_CTX_set0_default(oldctx);
}

static int test_18222(void)
{
    const int ret = thread_run_test(&test_18222_init,
                                    MAXIMUM_THREADS, &test_18222_worker,
                                    1, default_provider);
    return TEST_true(ret) &&
           TEST_int_eq(counter_18222, MAXIMUM_THREADS) &&
           TEST_int_eq(passed_18222, MAXIMUM_THREADS);
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_FIPS, OPT_CONFIG_FILE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "fips", OPT_FIPS, '-', "Test the FIPS provider" },
        { "config", OPT_CONFIG_FILE, '<',
          "The configuration file to use for the libctx" },
        { NULL }
    };
    return options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;
    char *datadir;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_FIPS:
            do_fips = 1;
            break;
        case OPT_CONFIG_FILE:
            config_file = opt_arg();
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    if (!TEST_ptr(datadir = test_get_argument(0)))
        return 0;

    privkey = test_mk_file_path(datadir, "rsakey.pem");
    if (!TEST_ptr(privkey))
        return 0;

#ifdef TSAN_REQUIRES_LOCKING
    if (!TEST_ptr(tsan_lock = CRYPTO_THREAD_lock_new()))
        return 0;
#endif

    /* Keep first to validate auto creation of default library context */
    ADD_TEST(test_multi_default);

    ADD_TEST(test_lock);
    ADD_TEST(test_once);
    ADD_TEST(test_thread_local);
    ADD_TEST(test_atomic);
    ADD_TEST(test_multi_load);
    ADD_TEST(test_multi_general_worker_default_provider);
    ADD_TEST(test_multi_general_worker_fips_provider);
    ADD_TEST(test_multi_fetch_worker);
    ADD_TEST(test_multi_shared_pkey);
#ifndef OPENSSL_NO_DEPRECATED_3_0
    ADD_TEST(test_multi_downgrade_shared_pkey);
#endif
    ADD_TEST(test_multi_load_unload_provider);
    ADD_TEST(test_obj_add);
    ADD_TEST(test_lib_ctx_load_config);
    ADD_TEST(test_18222);
    return 1;
}

void cleanup_tests(void)
{
    OPENSSL_free(privkey);
#ifdef TSAN_REQUIRES_LOCKING
    CRYPTO_THREAD_lock_free(tsan_lock);
#endif
}
