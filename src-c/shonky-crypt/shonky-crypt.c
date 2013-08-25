#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "shonky-crypt.h"

typedef unsigned char uc;

struct shonky_crypt_context {
    shonky_crypt_key_t key;
    off_t offset;
};

char *sc_encrypt_new(const shonky_crypt_key_t key,
                     const char *plain,
                     size_t sz)
{
    char *out = malloc(sz);
    if (out) {
        shonky_crypt_context_t ctx = sc_alloc_context_with_key(key);
        sc_encrypt_inplace(ctx, plain, out, sz);
        sc_release_context(ctx);
    }
    return out;
}

char *sc_decrypt_new(const shonky_crypt_key_t key,
                     const char *scrambled,
                     size_t sz)
{
    char *out = malloc(sz);
    if (out) {
        shonky_crypt_context_t ctx = sc_alloc_context_with_key(key);
        sc_decrypt_inplace(ctx, scrambled, out, sz);
        sc_release_context(ctx);
    }
    return out;
}

shonky_crypt_context_t sc_alloc_context_with_key(const shonky_crypt_key_t key)
{
    shonky_crypt_context_t ctx = malloc(sizeof(struct shonky_crypt_context));
    ctx->key = malloc(sizeof(struct shonky_crypt_key));
    *ctx->key = *key;
    ctx->offset = 0;
    return ctx;
}

shonky_crypt_context_t sc_copy_context(const shonky_crypt_context_t ctx)
{
    shonky_crypt_context_t new_ctx = sc_alloc_context_with_key(ctx->key);
    if (new_ctx) {
        new_ctx->offset = ctx->offset;
    }
    return new_ctx;
}

void sc_release_context(shonky_crypt_context_t ctx)
{
    free(ctx->key);
    free(ctx);
}

static inline uc _crypt_byte(uc in,
                            off_t key_start,
                            off_t key_inc,
                            off_t offset,
                            off_t mul,
                            bool only_alnum)
{
    uc min;
    uc max;
    if (only_alnum) {
        if ('0' <= in && in <= '9') {
            min = '0';
            max = '9';
        } else if ('a' <= in && in <= 'z') {
            min = 'a';
            max = 'z';
        } else if ('A' <= in && in <= 'Z') {
            min = 'A';
            max = 'Z';
        } else {
            return in;
        }
    } else {
        min = 0;
        max = 255;
    }

    {
        off_t mod = max - min + 1;
        off_t total_rot = mul * (key_start + (key_inc * offset));
        uc pos_rot;
        if (total_rot >= 0) {
            pos_rot = (uc)(total_rot % mod);
        } else {
            pos_rot = (uc)mod - (uc)(-total_rot % mod);
        }

        return ((in - min + pos_rot) % mod) + min;
    }
}

static inline uc crypt_byte(uc in,
                            off_t key_start,
                            off_t key_inc,
                            off_t offset,
                            off_t mul,
                            bool only_alnum)
{
    uc r = _crypt_byte(in, key_start, key_inc, offset, mul, only_alnum);
    // printf("%s[%2lld] %d -> %d \n", mul > 0 ? "ENC" : "DEC", offset, in, r);
    return r;
}

void sc_encrypt_inplace(shonky_crypt_context_t ctx,
                        const char *in_plain,
                        char *out_scrambled,
                        size_t sz)
{
    struct shonky_crypt_key key = *ctx->key;
    for (off_t i=0; i<sz; i++, ctx->offset++) {
        out_scrambled[i] = crypt_byte(in_plain[i],
                                      key.key_start,
                                      key.key_inc,
                                      ctx->offset,
                                      1,
                                      key.only_alnum);
    }
}

void sc_decrypt_inplace(shonky_crypt_context_t ctx,
                        const char *in_scrambled,
                        char *out_plain,
                        size_t sz)
{
    struct shonky_crypt_key key = *ctx->key;
    for (off_t i=0; i<sz; i++, ctx->offset++) {
        out_plain[i] = crypt_byte(in_scrambled[i],
                                  key.key_start,
                                  key.key_inc,
                                  ctx->offset,
                                  -1,
                                  key.only_alnum);
    }
}

shonky_crypt_key_t sc_new_crypt_key_with(char key_start,
                                         char key_inc,
                                         SC_BOOL only_alnum)
{
    shonky_crypt_key_t key = malloc(sizeof(struct shonky_crypt_key));
    if (key) {
        key->key_start = key_start;
        key->key_inc = key_inc;
        key->only_alnum = only_alnum;
    }
    return key;
}
