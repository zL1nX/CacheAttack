#include <fcntl.h>  
#include <math.h>
#include <stdint.h> 
#include <stdlib.h> 
#include <stdio.h>   
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h> 
#include <openssl/objects.h> 
#include <openssl/err.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include "ec_lcl.h"

// #include "ecs_locl.h"
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include <openssl/rand.h>
#include "cache_details.h" /*Cache architecture details*/

#define mfence()  __asm__ volatile("mfence;"); 
#define lfence()  __asm__ volatile("lfence;");
#define SLOT_BUF_SIZE 10000
#define MAX_QUIET_PERIOD 10000
#define MAX_PROBES 32
#define PROBE_COUNT 2
#define RELOAD_THRESHOLD

typedef struct SlotState {
    unsigned long long start;
    unsigned long missed;
    unsigned long probe_time[PROBE_COUNT];
} slot_t;

typedef struct Probe {
    unsigned long virtual_address;
    char name;
} probe_t;

typedef struct ec_pre_comp_st {
    const EC_GROUP *group;      /* parent EC_GROUP object */
    size_t blocksize;           /* block size for wNAF splitting */
    size_t numblocks;           /* max. number of blocks for which we have
                                 * precomputation */
    size_t w;                   /* window size */
    EC_POINT **points;          /* array with pre-calculated multiples of
                                 * generator: 'num' pointers to EC_POINT
                                 * objects followed by a NULL */
    size_t num;                 /* numblocks * 2^(w-1) */
    int references;
} EC_PRE_COMP;



/*Useful functions for attackss*/
unsigned long int timestamp(void);
int access_timed_flush(long int *pos_data);


ECDSA_SIG *_ECDSA_do_sign(const unsigned char *dgst, int dlen, EC_KEY *eckey);
ECDSA_SIG *_ECDSA_do_sign_ex(const unsigned char *dgst, int dlen,
                            const BIGNUM *kinv, const BIGNUM *rp,
                            EC_KEY *eckey);
int _ECDSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char
               *sig, unsigned int *siglen, EC_KEY *eckey);
int _ECDSA_sign_ex(int type, const unsigned char *dgst, int dlen, unsigned char
                  *sig, unsigned int *siglen, const BIGNUM *kinv,
                  const BIGNUM *r, EC_KEY *eckey);
int _ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                     BIGNUM **rp);
int _ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                            BIGNUM **rp);
ECDSA_SIG *_ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
                                const BIGNUM *in_kinv, const BIGNUM *in_r,
                                EC_KEY *eckey);
void *ec_pre_comp_dup(void *src_);
void ec_pre_comp_free(void *pre_);
void ec_pre_comp_clear_free(void *pre_);
void *_EC_EX_DATA_get_data(const EC_EXTRA_DATA *ex_data,
                          void *(*dup_func) (void *),
                          void (*free_func) (void *),
                          void (*clear_free_func) (void *));
signed char *compute_wNAF(const BIGNUM *scalar, int w, size_t *ret_len);
int _ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
                BN_CTX *ctx);
int _EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                  size_t num, const EC_POINT *points[],
                  const BIGNUM *scalars[], BN_CTX *ctx);
int MY_EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
                 const EC_POINT *point, const BIGNUM *p_scalar, BN_CTX *ctx);