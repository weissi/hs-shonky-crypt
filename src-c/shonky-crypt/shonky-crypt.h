#ifndef SHONKY_CRYPT_H

#include <sys/types.h>

#define SC_EXPORT extern
#define SC_BOOL char

/**
 * A shonky encryption key.
 *
 * key_start:  Each byte is "encrypted" by adding `key_start` (modulo 256) to its
 *             byte value.
 * key_inc:    To "enhance" "encryption", `key_inc` can be used to add an
 *             additional value of `key_inc * n` for the `n`th byte.
 * only_alnum: Only apply the encryption for alphanumeric characters (0-9, a-z,
 *             A-Z). Additionally, the encryption of a byte will stay in its
 *             respective group. In other words, every number's encryption will
 *             be a number, every lower case character's encryption will be
 *             some lower case character and every upper case character will be
 *             encrypted to another upper case character. Non alphanumeric
 *             characters (such as space) will not be encrypted at all.
 */
typedef struct shonky_crypt_key {
    char key_start;
    char key_inc;
    SC_BOOL only_alnum;
} *shonky_crypt_key_t;

/**
 * An opaque type representing an encryptions state.
 */
struct shonky_crypt_context;

/**
 * An opaque type representing an encryptions state.
 */
typedef struct shonky_crypt_context *shonky_crypt_context_t;

/**
 * Encrypt `plain` (having the length `sz` bytes) with encryption key `key`.
 * The function returns a new byte string of length `sz` which was allocated
 * using the `malloc(3)` function and has therefore be released using `free(3)`
 * when the caller does not need it anymore.
 */
SC_EXPORT char *sc_encrypt_new(const shonky_crypt_key_t key,
                               const char *plain,
                               size_t sz);

/**
 * Decrypt `scrambled` (having the length `sz` bytes) with encryption key `key`.
 * The function returns a new byte string of length `sz` which was allocated
 * using the `malloc(3)` function and has therefore be released using `free(3)`
 * when the caller does not need it anymore.
 */
SC_EXPORT char *sc_decrypt_new(const shonky_crypt_key_t key,
                               const char *scrambled,
                               size_t sz);

/**
 * Construct a new encryption key. Allocated on the heap using `malloc(3)`.
 */
SC_EXPORT shonky_crypt_key_t sc_new_crypt_key_with(char key_start,
                                                   char key_inc,
                                                   SC_BOOL only_alnum);

/**
 * Construct an encryption context using an encryption key.
 *
 * The encryption context is allocated by the callee in some
 * implementation-specific way. It has to be released using `sc_release_context`.
 * Releasing using `free(3)` is not allowed and will lead to crashed and/or memory
 * leaks.
 */
SC_EXPORT shonky_crypt_context_t sc_alloc_context_with_key(const shonky_crypt_key_t key);

/**
 * Copies an encryption context. Caller has to release the newly created context
 * using `sc_release_context`.
 */
SC_EXPORT shonky_crypt_context_t sc_copy_context(const shonky_crypt_context_t ctx);

/**
 * Release the memory occupied by the provided encryption context.
 */
SC_EXPORT void sc_release_context(shonky_crypt_context_t ctx);

/**
 * Encrypt the first `sz` bytes `in_plain` into the first `sz` bytes of
 * `out_scrambled`. The callee will alter the provided encryption context `ctx`.
 */
SC_EXPORT void sc_encrypt_inplace(shonky_crypt_context_t ctx,
                                  const char *in_plain,
                                  char *out_scrambled,
                                  size_t sz);

/**
 * Decrypt the first `sz` bytes `in_scrambled` into the first `sz` bytes of
 * `out_plain`. The callee will alter the provided encryption context `ctx`.
 */
SC_EXPORT void sc_decrypt_inplace(shonky_crypt_context_t ctx,
                                  const char *in_scrambled,
                                  char *out_plain,
                                  size_t sz);

/**
 * Calculate the entropy of the byte string `str` (lenght `len` bytes).
 */
SC_EXPORT double sc_entropy(const char *str, size_t len);

#endif
