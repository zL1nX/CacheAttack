#include "cache_utils.h"

/*Get the value of rdtsc*/
unsigned long int timestamp(void)
{
    unsigned long int result;
    unsigned int bottom;
    unsigned int top;
    asm volatile("rdtsc"
                 : "=a"(bottom), "=d"(top));
    result = top;
    result = (result << 32) & 0xFFFFFFFF00000000UL;
    return (result | bottom);
}

/* parity and addr2lice_linear functions are the ones defined in the Mastik tool */
/* Mastik is available in https://cs.adelaide.edu.au/~yval/Mastik/ */



/*Measure read time and flush data afterwards*/
int access_timed_flush(long int *pos_data)
{
    volatile unsigned int time;
    asm __volatile__(
        " mfence \n"
        " lfence \n"
        " rdtsc \n"
        " lfence \n"
        " movl %%eax, %%esi \n"
        " movl (%1), %%eax \n"
        " lfence \n"
        //" mfence \n"
        " rdtsc \n"
        " subl %%esi, %%eax \n"
        " clflush 0(%1) \n"
        : "=a"(time)
        : "c"(pos_data)
        : "%esi", "%edx");
    return time;
}



void *ec_pre_comp_dup(void *src_)
{
    EC_PRE_COMP *src = src_;

    /* no need to actually copy, these objects never change! */

    CRYPTO_add(&src->references, 1, CRYPTO_LOCK_EC_PRE_COMP);

    return src_;
}

void ec_pre_comp_free(void *pre_)
{
    int i;
    EC_PRE_COMP *pre = pre_;

    if (!pre)
        return;

    i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
    if (i > 0)
        return;

    if (pre->points) {
        EC_POINT **p;

        for (p = pre->points; *p != NULL; p++)
            EC_POINT_free(*p);
        OPENSSL_free(pre->points);
    }
    OPENSSL_free(pre);
}

void ec_pre_comp_clear_free(void *pre_)
{
    int i;
    EC_PRE_COMP *pre = pre_;

    if (!pre)
        return;

    i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
    if (i > 0)
        return;

    if (pre->points) {
        EC_POINT **p;

        for (p = pre->points; *p != NULL; p++) {
            EC_POINT_clear_free(*p);
            OPENSSL_cleanse(p, sizeof *p);
        }
        OPENSSL_free(pre->points);
    }
    OPENSSL_cleanse(pre, sizeof *pre);
    OPENSSL_free(pre);
}

void *_EC_EX_DATA_get_data(const EC_EXTRA_DATA *ex_data,
                          void *(*dup_func) (void *),
                          void (*free_func) (void *),
                          void (*clear_free_func) (void *))
{
    const EC_EXTRA_DATA *d;

    for (d = ex_data; d != NULL; d = d->next) {
        if (d->dup_func == dup_func && d->free_func == free_func
            && d->clear_free_func == clear_free_func)
            return d->data;
    }

    return NULL;
}


signed char *compute_wNAF(const BIGNUM *scalar, int w, size_t *ret_len)
{
    int window_val;
    int ok = 0;
    signed char *r = NULL;
    int sign = 1;
    int bit, next_bit, mask;
    size_t len = 0, j;

    if (BN_is_zero(scalar)) {
        r = OPENSSL_malloc(1);
        if (!r) {
            ECerr(EC_F_COMPUTE_WNAF, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        r[0] = 0;
        *ret_len = 1;
        return r;
    }

    if (w <= 0 || w > 7) {      /* 'signed char' can represent integers with
                                 * absolute values less than 2^7 */
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    bit = 1 << w;               /* at most 128 */
    next_bit = bit << 1;        /* at most 256 */
    mask = next_bit - 1;        /* at most 255 */

    if (BN_is_negative(scalar)) {
        sign = -1;
    }

    if (scalar->d == NULL || scalar->top == 0) {
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    len = BN_num_bits(scalar);
    r = OPENSSL_malloc(len + 1); /* modified wNAF may be one digit longer
                                  * than binary representation (*ret_len will
                                  * be set to the actual length, i.e. at most
                                  * BN_num_bits(scalar) + 1) */
    if (r == NULL) {
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    window_val = scalar->d[0] & mask;
    j = 0;
    while ((window_val != 0) || (j + w + 1 < len)) { /* if j+w+1 >= len,
                                                      * window_val will not
                                                      * increase */
        int digit = 0;

        /* 0 <= window_val <= 2^(w+1) */

        if (window_val & 1) {
            /* 0 < window_val < 2^(w+1) */

            if (window_val & bit) {
                digit = window_val - next_bit; /* -2^w < digit < 0 */

#if 1                           /* modified wNAF */
                if (j + w + 1 >= len) {
                    /*
                     * special case for generating modified wNAFs: no new
                     * bits will be added into window_val, so using a
                     * positive digit here will decrease the total length of
                     * the representation
                     */

                    digit = window_val & (mask >> 1); /* 0 < digit < 2^w */
                }
#endif
            } else {
                digit = window_val; /* 0 < digit < 2^w */
            }

            if (digit <= -bit || digit >= bit || !(digit & 1)) {
                ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            window_val -= digit;

            /*
             * now window_val is 0 or 2^(w+1) in standard wNAF generation;
             * for modified window NAFs, it may also be 2^w
             */
            if (window_val != 0 && window_val != next_bit
                && window_val != bit) {
                ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        r[j++] = sign * digit;

        window_val >>= 1;
        window_val += bit * BN_is_bit_set(scalar, j + w);

        if (window_val > next_bit) {
            ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if (j > len + 1) {
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    len = j;
    ok = 1;

 err:
    if (!ok) {
        OPENSSL_free(r);
        r = NULL;
    }
    if (ok)
        *ret_len = len;
    return r;
}

/*
 * TODO: table should be optimised for the wNAF-based implementation,
 * sometimes smaller windows will give better performance (thus the
 * boundaries should be increased)
 */
#define EC_window_bits_for_scalar_size(b) \
                ((size_t) \
                 ((b) >= 2000 ? 6 : \
                  (b) >=  800 ? 5 : \
                  (b) >=  300 ? 4 : \
                  (b) >=   70 ? 3 : \
                  (b) >=   20 ? 2 : \
                  1))



int _ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
                BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    const EC_POINT *generator = NULL;
    EC_POINT *tmp = NULL;
    size_t totalnum;
    size_t blocksize = 0, numblocks = 0; /* for wNAF splitting */
    size_t pre_points_per_block = 0;
    size_t i, j;
    int k;
    int r_is_inverted = 0;
    int r_is_at_infinity = 1;
    size_t *wsize = NULL;       /* individual window sizes */
    signed char **wNAF = NULL;  /* individual wNAFs */
    size_t *wNAF_len = NULL;
    size_t max_len = 0;
    size_t num_val;
    EC_POINT **val = NULL;      /* precomputation */
    EC_POINT **v;
    EC_POINT ***val_sub = NULL; /* pointers to sub-arrays of 'val' or
                                 * 'pre_comp->points' */
    const EC_PRE_COMP *pre_comp = NULL;
    int num_scalar = 0;         /* flag: will be set to 1 if 'scalar' must be
                                 * treated like other scalars, i.e.
                                 * precomputation is not available */
    int ret = 0;

    if ((scalar == NULL) && (num == 0)) {
        return EC_POINT_set_to_infinity(group, r);
    }

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            goto err;
    }

    if (scalar != NULL) {
        generator = EC_GROUP_get0_generator(group);
        if (generator == NULL) {
            ECerr(EC_F_EC_WNAF_MUL, EC_R_UNDEFINED_GENERATOR);
            goto err;
        }

        /* look if we can use precomputed multiples of generator */

        pre_comp =
            _EC_EX_DATA_get_data(group->extra_data, ec_pre_comp_dup,
                                ec_pre_comp_free, ec_pre_comp_clear_free);

        if (pre_comp && pre_comp->numblocks
            && (EC_POINT_cmp(group, generator, pre_comp->points[0], ctx) ==
                0)) {
            blocksize = pre_comp->blocksize;

            /*
             * determine maximum number of blocks that wNAF splitting may
             * yield (NB: maximum wNAF length is bit length plus one)
             */
            numblocks = (BN_num_bits(scalar) / blocksize) + 1;

            /*
             * we cannot use more blocks than we have precomputation for
             */
            if (numblocks > pre_comp->numblocks)
                numblocks = pre_comp->numblocks;

            pre_points_per_block = (size_t)1 << (pre_comp->w - 1);

            /* check that pre_comp looks sane */
            if (pre_comp->num != (pre_comp->numblocks * pre_points_per_block)) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            /* can't use precomputation */
            pre_comp = NULL;
            numblocks = 1;
            num_scalar = 1;     /* treat 'scalar' like 'num'-th element of
                                 * 'scalars' */
        }
    }

    totalnum = num + numblocks;

    wsize = OPENSSL_malloc(totalnum * sizeof wsize[0]);
    wNAF_len = OPENSSL_malloc(totalnum * sizeof wNAF_len[0]);
    wNAF = OPENSSL_malloc((totalnum + 1) * sizeof wNAF[0]); /* includes space
                                                             * for pivot */
    val_sub = OPENSSL_malloc(totalnum * sizeof val_sub[0]);

    /* Ensure wNAF is initialised in case we end up going to err */
    if (wNAF)
        wNAF[0] = NULL;         /* preliminary pivot */

    if (!wsize || !wNAF_len || !wNAF || !val_sub) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * num_val will be the total number of temporarily precomputed points
     */
    num_val = 0;

    for (i = 0; i < num + num_scalar; i++) {
        size_t bits;

        bits = i < num ? BN_num_bits(scalars[i]) : BN_num_bits(scalar);
        wsize[i] = EC_window_bits_for_scalar_size(bits);
        num_val += (size_t)1 << (wsize[i] - 1);
        wNAF[i + 1] = NULL;     /* make sure we always have a pivot */
        wNAF[i] =
            compute_wNAF((i < num ? scalars[i] : scalar), wsize[i],
                         &wNAF_len[i]);
        if (wNAF[i] == NULL)
            goto err;
        if (wNAF_len[i] > max_len)
            max_len = wNAF_len[i];
    }

	

    if (numblocks) {
        /* we go here iff scalar != NULL */

        if (pre_comp == NULL) {
            if (num_scalar != 1) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /* we have already generated a wNAF for 'scalar' */
        } else {
            signed char *tmp_wNAF = NULL;
            size_t tmp_len = 0;

            if (num_scalar != 0) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            /*
             * use the window size for which we have precomputation
             */
            wsize[num] = pre_comp->w;
            tmp_wNAF = compute_wNAF(scalar, wsize[num], &tmp_len);
            if (!tmp_wNAF)
                goto err;

            if (tmp_len <= max_len) {
                /*
                 * One of the other wNAFs is at least as long as the wNAF
                 * belonging to the generator, so wNAF splitting will not buy
                 * us anything.
                 */

                numblocks = 1;
                totalnum = num + 1; /* don't use wNAF splitting */
                wNAF[num] = tmp_wNAF;
                wNAF[num + 1] = NULL;
                wNAF_len[num] = tmp_len;
                if (tmp_len > max_len)
                    max_len = tmp_len;
                /*
                 * pre_comp->points starts with the points that we need here:
                 */
                val_sub[num] = pre_comp->points;
            } else {
                /*
                 * don't include tmp_wNAF directly into wNAF array - use wNAF
                 * splitting and include the blocks
                 */

                signed char *pp;
                EC_POINT **tmp_points;

                if (tmp_len < numblocks * blocksize) {
                    /*
                     * possibly we can do with fewer blocks than estimated
                     */
                    numblocks = (tmp_len + blocksize - 1) / blocksize;
                    if (numblocks > pre_comp->numblocks) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                        goto err;
                    }
                    totalnum = num + numblocks;
                }

                /* split wNAF in 'numblocks' parts */
                pp = tmp_wNAF;
                tmp_points = pre_comp->points;

                for (i = num; i < totalnum; i++) {
                    if (i < totalnum - 1) {
                        wNAF_len[i] = blocksize;
                        if (tmp_len < blocksize) {
                            ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                            goto err;
                        }
                        tmp_len -= blocksize;
                    } else
                        /*
                         * last block gets whatever is left (this could be
                         * more or less than 'blocksize'!)
                         */
                        wNAF_len[i] = tmp_len;

                    wNAF[i + 1] = NULL;
                    wNAF[i] = OPENSSL_malloc(wNAF_len[i]);
                    if (wNAF[i] == NULL) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
                        OPENSSL_free(tmp_wNAF);
                        goto err;
                    }
                    memcpy(wNAF[i], pp, wNAF_len[i]);
                    if (wNAF_len[i] > max_len)
                        max_len = wNAF_len[i];

                    if (*tmp_points == NULL) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                        OPENSSL_free(tmp_wNAF);
                        goto err;
                    }
                    val_sub[i] = tmp_points;
                    tmp_points += pre_points_per_block;
                    pp += blocksize;
                }
                OPENSSL_free(tmp_wNAF);
            }
        }
    }

    /*
     * All points we precompute now go into a single array 'val'.
     * 'val_sub[i]' is a pointer to the subarray for the i-th point, or to a
     * subarray of 'pre_comp->points' if we already have precomputation.
     */
    val = OPENSSL_malloc((num_val + 1) * sizeof val[0]);
    if (val == NULL) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    val[num_val] = NULL;        /* pivot element */

    /* allocate points for precomputation */
    v = val;
    for (i = 0; i < num + num_scalar; i++) {
        val_sub[i] = v;
        for (j = 0; j < ((size_t)1 << (wsize[i] - 1)); j++) {
            *v = EC_POINT_new(group);
            if (*v == NULL)
                goto err;
            v++;
        }
    }
    if (!(v == val + num_val)) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!(tmp = EC_POINT_new(group)))
        goto err;

    /*-
     * prepare precomputed values:
     *    val_sub[i][0] :=     points[i]
     *    val_sub[i][1] := 3 * points[i]
     *    val_sub[i][2] := 5 * points[i]
     *    ...
     */
	//printf("times: %ld\n", num + num_scalar);
    for (i = 0; i < num + num_scalar; i++) {
        if (i < num) {
            if (!EC_POINT_copy(val_sub[i][0], points[i]))
                goto err;
        } else {
            if (!EC_POINT_copy(val_sub[i][0], generator))
                goto err;
        }

        if (wsize[i] > 1) {
            if (!EC_POINT_dbl(group, tmp, val_sub[i][0], ctx))
                goto err;
            for (j = 1; j < ((size_t)1 << (wsize[i] - 1)); j++) {
                if (!EC_POINT_add
                    (group, val_sub[i][j], val_sub[i][j - 1], tmp, ctx))
                    goto err;
            }
        }
    }

#if 1                           /* optional; EC_window_bits_for_scalar_size
                                 * assumes we do this step */
    if (!EC_POINTs_make_affine(group, num_val, val, ctx))
        goto err;
#endif

    r_is_at_infinity = 1;

    for (k = max_len - 1; k >= 0; k--) {
        if (!r_is_at_infinity) {
            if (!EC_POINT_dbl(group, r, r, ctx))
                goto err;
        }
        for (i = 0; i < totalnum; i++) {
            if (wNAF_len[i] > (size_t)k) {
                int digit = wNAF[i][k];
                int is_neg;
                if (digit) {
                    is_neg = digit < 0;

                    if (is_neg)
                        digit = -digit;

                    if (is_neg != r_is_inverted) {
                        if (!r_is_at_infinity) {
                            if (!EC_POINT_invert(group, r, ctx))
                                goto err;
                        }
                        r_is_inverted = !r_is_inverted;
                    }

                    /* digit > 0 */

                    if (r_is_at_infinity) {
                        if (!EC_POINT_copy(r, val_sub[i][digit >> 1]))
                            goto err;
                        r_is_at_infinity = 0;
                    } else {
                        if (!EC_POINT_add
                            (group, r, r, val_sub[i][digit >> 1], ctx))
                            goto err;
                    }

                }
            }
            
        }
    }


    if (r_is_at_infinity) {
        if (!EC_POINT_set_to_infinity(group, r))
            goto err;
    } else {
        if (r_is_inverted)
            if (!EC_POINT_invert(group, r, ctx))
                goto err;
    }
    // printf("\n");
    ret = 1;

 err:
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
    if (tmp != NULL)
        EC_POINT_free(tmp);
    if (wsize != NULL)
        OPENSSL_free(wsize);
    if (wNAF_len != NULL)
        OPENSSL_free(wNAF_len);
    if (wNAF != NULL) {
        signed char **w;

        for (w = wNAF; *w != NULL; w++)
            OPENSSL_free(*w);

        OPENSSL_free(wNAF);
    }
    if (val != NULL) {
        for (v = val; *v != NULL; v++)
            EC_POINT_clear_free(*v);

        OPENSSL_free(val);
    }
    if (val_sub != NULL) {
        OPENSSL_free(val_sub);
    }
    return ret;
}

int _EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                  size_t num, const EC_POINT *points[],
                  const BIGNUM *scalars[], BN_CTX *ctx)
{
    return _ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx);
}

int MY_EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
                 const EC_POINT *point, const BIGNUM *p_scalar, BN_CTX *ctx)
{
    /* just a convenient interface to EC_POINTs_mul() */

    const EC_POINT *points[1];
    const BIGNUM *scalars[1];

    points[0] = point;
    scalars[0] = p_scalar;

    return _EC_POINTs_mul(group, r, g_scalar,
                         (point != NULL
                          && p_scalar != NULL), points, scalars, ctx);
}




ECDSA_SIG *_ECDSA_do_sign(const unsigned char *dgst, int dlen, EC_KEY *eckey)
{
    return _ECDSA_do_sign_ex(dgst, dlen, NULL, NULL, eckey);
}

ECDSA_SIG *_ECDSA_do_sign_ex(const unsigned char *dgst, int dlen,
                            const BIGNUM *kinv, const BIGNUM *rp,
                            EC_KEY *eckey)
{
    return _ecdsa_do_sign(dgst, dlen, kinv, rp, eckey);
}

int _ECDSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char
               *sig, unsigned int *siglen, EC_KEY *eckey)
{
    return _ECDSA_sign_ex(type, dgst, dlen, sig, siglen, NULL, NULL, eckey);
}

int _ECDSA_sign_ex(int type, const unsigned char *dgst, int dlen, unsigned char
                  *sig, unsigned int *siglen, const BIGNUM *kinv,
                  const BIGNUM *r, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    RAND_seed(dgst, dlen);
    s = _ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
    if (s == NULL) {
        *siglen = 0;
        return 0;
    }
    *siglen = i2d_ECDSA_SIG(s, &sig);
    ECDSA_SIG_free(s);
    return 1;
}

int _ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                     BIGNUM **rp)
{
    return _ecdsa_sign_setup(eckey, ctx_in, kinvp, rp);
}

int _ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                            BIGNUM **rp)
{
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL, *r = NULL, *order = NULL, *X = NULL;
    EC_POINT *tmp_point = NULL;
    const EC_GROUP *group;
    int ret = 0;

    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (ctx_in == NULL) {
        if ((ctx = BN_CTX_new()) == NULL) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    } else
        ctx = ctx_in;

    k = BN_new();               /* this value is later returned in *kinvp */
    r = BN_new();               /* this value is later returned in *rp */
    order = BN_new();
    X = BN_new();
    if (!k || !r || !order || !X) {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((tmp_point = EC_POINT_new(group)) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_GROUP_get_order(group, order, ctx)) {
        ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        goto err;
    }
	const char* hexk = "C153540D8D7DE635EC4C2BCE25DD9AE7B7D5FB8974E1ACDB997D41C223FEF231";
	if(!BN_hex2bn(&k, hexk))
	{
		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,
					ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED);
		goto err;
	}

    do {
        /*
         * We do not want timing information to leak the length of k, so we
         * compute G*k using an equivalent scalar of fixed bit-length.
         */

        if (!BN_add(k, k, order))
            goto err;
        if (BN_num_bits(k) <= BN_num_bits(order))
            if (!BN_add(k, k, order))
                goto err;

        /* compute r the x-coordinate of generator * k */
        if (!MY_EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
            goto err;
        }
        if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
            NID_X9_62_prime_field) {
            if (!EC_POINT_get_affine_coordinates_GFp
                (group, tmp_point, X, NULL, ctx)) {
                ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
                goto err;
            }
        }
#ifndef OPENSSL_NO_EC2M
        else {                  /* NID_X9_62_characteristic_two_field */

            if (!EC_POINT_get_affine_coordinates_GF2m(group,
                                                      tmp_point, X, NULL,
                                                      ctx)) {
                ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
                goto err;
            }
        }
#endif
        if (!BN_nnmod(r, X, order, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
    }
    while (BN_is_zero(r));

    /* compute the inverse of k */
    if (EC_GROUP_get_mont_data(group) != NULL) {
        /*
         * We want inverse in constant time, therefore we utilize the fact
         * order must be prime and use Fermats Little Theorem instead.
         */
        if (!BN_set_word(X, 2)) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
        if (!BN_mod_sub(X, order, X, order, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
        BN_set_flags(X, BN_FLG_CONSTTIME);
        if (!BN_mod_exp_mont_consttime
            (k, k, X, order, ctx, EC_GROUP_get_mont_data(group))) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
    } else {
        if (!BN_mod_inverse(k, k, order, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
            goto err;
        }
    }

    /* clear old values if necessary */
    if (*rp != NULL)
        BN_clear_free(*rp);
    if (*kinvp != NULL)
        BN_clear_free(*kinvp);
    /* save the pre-computed values  */
    *rp = r;
    *kinvp = k;
    ret = 1;
 err:
    if (!ret) {
        if (k != NULL)
            BN_clear_free(k);
        if (r != NULL)
            BN_clear_free(r);
    }
    if (ctx_in == NULL)
        BN_CTX_free(ctx);
    if (order != NULL)
        BN_free(order);
    if (tmp_point != NULL)
        EC_POINT_free(tmp_point);
    if (X)
        BN_clear_free(X);
    return (ret);
}

ECDSA_SIG *_ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
                                const BIGNUM *in_kinv, const BIGNUM *in_r,
                                EC_KEY *eckey)
{
    int ok = 0, i;
    BIGNUM *kinv = NULL, *s, *m = NULL, *tmp = NULL, *order = NULL;
    const BIGNUM *ckinv;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group;
    ECDSA_SIG *ret;
    const BIGNUM *priv_key;

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);

    if (group == NULL || priv_key == NULL ) 
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ret = ECDSA_SIG_new();
    if (!ret) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    s = ret->s;

    if ((ctx = BN_CTX_new()) == NULL || (order = BN_new()) == NULL ||
        (tmp = BN_new()) == NULL || (m = BN_new()) == NULL) 
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx)) 
    {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        goto err;
    }
    i = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;
    if (!BN_bin2bn(dgst, dgst_len, m)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }
    do {
        if (in_kinv == NULL || in_r == NULL) {
            if (!_ECDSA_sign_setup(eckey, ctx, &kinv, &ret->r)) {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_ECDSA_LIB);
                goto err;
            }
            ckinv = kinv;
        } else {
            ckinv = in_kinv;
            if (BN_copy(ret->r, in_r) == NULL) {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }

        if (!BN_mod_mul(tmp, priv_key, ret->r, order, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        if (!BN_mod_add_quick(s, tmp, m, order)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        if (!BN_mod_mul(s, s, ckinv, order, ctx)) {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
            goto err;
        }
        if (BN_is_zero(s)) {
            /*
             * if kinv and r have been supplied by the caller don't to
             * generate new kinv and r values
             */
            if (in_kinv != NULL && in_r != NULL) {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN,
                         ECDSA_R_NEED_NEW_SETUP_VALUES);
                goto err;
            }
        } else
            /* s != 0 => we have a valid signature */
            break;
    }
    while (1);

    ok = 1;
 err:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    if (ctx)
        BN_CTX_free(ctx);
    if (m)
        BN_clear_free(m);
    if (tmp)
        BN_clear_free(tmp);
    if (order)
        BN_free(order);
    if (kinv)
        BN_clear_free(kinv);
    return ret;
}