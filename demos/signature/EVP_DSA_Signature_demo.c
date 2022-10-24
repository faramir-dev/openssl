/*-
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * An example that uses the EVP_MD*, EVP_DigestSign* and EVP_DigestVerify*
 * methods to calculate and verify a signature of two static buffers.
 */

#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <openssl/dsa.h>

/*
 * This demonstration will calculate and verify a signature of data using
 * the soliloquy from Hamlet scene 1 act 3
 */

static const char *hamlet_1 =
    "To be, or not to be, that is the question,\n"
    "Whether tis nobler in the minde to suffer\n"
    "The slings and arrowes of outragious fortune,\n"
    "Or to take Armes again in a sea of troubles,\n"
;
static const char *hamlet_2 =
    "And by opposing, end them, to die to sleep;\n"
    "No more, and by a sleep, to say we end\n"
    "The heart-ache, and the thousand natural shocks\n"
    "That flesh is heir to? tis a consumation\n"
;

static const char ALG[] = "DSA";
static const char DIGEST[] = "SHA256";
static const int NUMBITS = 1024;
static const char * const PROPQUERY = NULL;

static int generate_dsa_key(OSSL_LIB_CTX *libctx,
                            EVP_PKEY **p_private_key,
                            EVP_PKEY **p_public_key)
{
    int result = 0;

    EVP_PKEY *params = NULL, *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    /* Generate Public Key */
    ctx = EVP_PKEY_CTX_new_from_name(libctx, ALG, PROPQUERY);
    if (ctx == NULL)
        goto end;

    //EVP_PKEY_CTX_set_app_data(ctx, bio_err);
    if (EVP_PKEY_paramgen_init(ctx) <= 0)
        goto end;

    if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, NUMBITS) <= 0)
        goto end;
    if (EVP_PKEY_paramgen(ctx, &params) <= 0)
        goto end;
    if (params == NULL)
        goto end;

    /* Generate Private Key */
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, params,
                                     NULL);
    if (ctx == NULL)
        goto end;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto end;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto end;
    if (pkey == NULL)
        goto end;

    result = 1;
end:
    if(!result) {
        EVP_PKEY_free(params);
        params = NULL;
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    *p_public_key = params;
    *p_private_key = pkey;
    fprintf(stdout, "Generating keys:\n");
    fprintf(stdout, "  Params:\n");
    EVP_PKEY_print_public_fp(stdout, params, 4, NULL);
    EVP_PKEY_print_private_fp(stdout, params, 4, NULL);
    EVP_PKEY_print_params_fp(stdout, params, 4, NULL);
    fprintf(stdout, "  PKEY:\n");
    EVP_PKEY_print_public_fp(stdout, pkey, 4, NULL);
    EVP_PKEY_print_private_fp(stdout, pkey, 4, NULL);
    EVP_PKEY_print_params_fp(stdout, pkey, 4, NULL);

    return result;
}

static int demo_sign(OSSL_LIB_CTX *libctx,
                     size_t *p_sig_len, unsigned char **p_sig_value,
                     EVP_PKEY *pkey)
{
    int result = 0;
    size_t sig_len = 0;
    unsigned char *sig_value = NULL;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = NULL;

    ctx = EVP_MD_CTX_create();
    if (ctx == NULL)
        goto end;

    md = EVP_get_digestbyname(DIGEST);
    if (md == NULL)
        goto end;

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1)
        goto end;

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1)
        goto end;

   if (EVP_DigestSignUpdate(ctx, hamlet_1, sizeof(hamlet_1)) != 1)
        goto end;

   if (EVP_DigestSignUpdate(ctx, hamlet_2, sizeof(hamlet_2)) != 1)
        goto end;

    if (EVP_DigestSignFinal(ctx, NULL, &sig_len) != 1)
        goto end;
    if (sig_len <= 0)
        goto end;

    sig_value = OPENSSL_malloc(sig_len);
    if (sig_value == NULL)
        goto end;

    if (EVP_DigestSignFinal(ctx, sig_value, &sig_len) != 1)
        goto end;

    result = 1;
end:
    EVP_MD_CTX_destroy(ctx);
    if (!result) {
        OPENSSL_free(sig_value);
        sig_len = 0;
        sig_value = NULL;
    }
    *p_sig_len = sig_len;
    *p_sig_value = sig_value;
    fprintf(stdout, "Generating signature:\n");
    BIO_dump_indent_fp(stdout, sig_value, sig_len, 2);
    fprintf(stdout, "\n");
    return result;
}

static int demo_verify(OSSL_LIB_CTX *libctx,
                       size_t sig_len, unsigned char *sig_value,
                       EVP_PKEY *pkey)
{
    int result = 0;

    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = NULL;

    ctx = EVP_MD_CTX_create();
    if(ctx == NULL)
        goto end;

    md = EVP_get_digestbyname(DIGEST);
    if(md == NULL)
        goto end;

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1)
        goto end;

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) != 1)
        goto end;

    if (EVP_DigestVerifyUpdate(ctx, hamlet_1, sizeof(hamlet_1)) != 1)
        goto end;

    if (EVP_DigestVerifyUpdate(ctx, hamlet_2, sizeof(hamlet_2)) != 1)
        goto end;

    /* Clear any errors for the call below */
    ERR_clear_error();

    if (EVP_DigestVerifyFinal(ctx, sig_value, sig_len) != 1)
        goto end;

    result = 1;
end:
    EVP_MD_CTX_destroy(ctx);
    return result;
}

int main(void)
{
    int result = 0;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *pub_key = NULL;
    EVP_PKEY *priv_key = NULL;
    size_t sig_len = 0;
    unsigned char *sig_value = NULL;

    libctx = OSSL_LIB_CTX_new();

    if (!generate_dsa_key(libctx, &priv_key, &pub_key))
        goto end;

    if (!demo_sign(libctx, &sig_len, &sig_value, priv_key))
        goto end;

    if (!demo_verify(libctx, sig_len, sig_value, priv_key))
        goto end;

    result = 1;
end:
    if (!result)
        ERR_print_errors_fp(stderr);

    OPENSSL_free(sig_value);
    EVP_PKEY_free(pub_key);
    EVP_PKEY_free(priv_key);
    OSSL_LIB_CTX_free(libctx);

    return result ? 0 : 1;
#if 0
    OSSL_LIB_CTX *libctx = NULL;
    //const char *sig_name = "SHA3-512";
    const char *sig_name = "DSA";
    size_t sig_len = 0;
    unsigned char *sig_value = NULL;
    int result = 0;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
        goto cleanup;
    }
    if (!demo_sign(libctx, sig_name, &sig_len, &sig_value)) {
        fprintf(stderr, "demo_sign failed.\n");
        goto cleanup;
    }
    if (!demo_verify(libctx, sig_name, sig_len, sig_value)) {
        fprintf(stderr, "demo_verify failed.\n");
        goto cleanup;
    }
    result = 1;

cleanup:
    if (result != 1)
        ERR_print_errors_fp(stderr);
    /* OpenSSL free functions will ignore NULL arguments */
    OSSL_LIB_CTX_free(libctx);
    OPENSSL_free(sig_value);
    return result == 0;
#endif
}
