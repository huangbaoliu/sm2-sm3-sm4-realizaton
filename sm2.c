#include "sm3.h"
#include "sm2.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef unsigned int uint;

#define CONCAT1(a, b) a##b
#define CONCAT(a, b) CONCAT1(a, b)

#define Curve_A_32 {0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF}

#define Curve_P_32 {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF}

#define Curve_B_32 {0x93, 0x0E, 0x94, 0x4D, 0x41, 0xBD, 0xBC, 0xDD, 0x92, 0x8F, 0xAB, 0x15, 0xF5, 0x89, 0x97, 0xF3, 0xA7, 0x09, 0x65, 0xCF, 0x4B, 0x9E, 0x5A, 0x4D, 0x34, 0x5E, 0x9F, 0x9D, 0x9E, 0xFA, 0xE9, 0x28}

#define Curve_G_32 { \
    {0xC7, 0x74, 0x4C, 0x33, 0x89, 0x45, 0x5A, 0x71, 0xE1, 0x0B, 0x66, 0xF2, 0xBF, 0x0B, 0xE3, 0x8F, 0x94, 0xC9, 0x39, 0x6A, 0x46, 0x04, 0x99, 0x5F, 0x19, 0x81, 0x19, 0x1F, 0x2C, 0xAE, 0xC4, 0x32}, \
    {0xA0, 0xF0, 0x39, 0x21, 0xE5, 0x32, 0xDF, 0x02, 0x40, 0x47, 0x2A, 0xC6, 0x7C, 0x87, 0xA9, 0xD0, 0x53, 0x21, 0x69, 0x6B, 0xE3, 0xCE, 0xBD, 0x59, 0x9C, 0x77, 0xF6, 0xF4, 0xA2, 0x36, 0x37, 0xBC}}

#define Curve_N_32 {0x23, 0x41, 0xD5, 0x39, 0x09, 0xF4, 0xBB, 0x53, 0x2B, 0x05, 0xC6, 0x21, 0x6B, 0xDF, 0x03, 0x72, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF}

static uint8_t curve_a[NUM_ECC_DIGITS] = CONCAT(Curve_A_, NUM_ECC_DIGITS);
static uint8_t curve_p[NUM_ECC_DIGITS] = CONCAT(Curve_P_, NUM_ECC_DIGITS);
static uint8_t curve_b[NUM_ECC_DIGITS] = CONCAT(Curve_B_, NUM_ECC_DIGITS);
static EccPoint curve_G = CONCAT(Curve_G_, NUM_ECC_DIGITS);
static uint8_t curve_n[NUM_ECC_DIGITS] = CONCAT(Curve_N_, NUM_ECC_DIGITS);

static void vli_modMult(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right, uint8_t *p_mod);

static void vli_clear(uint8_t *p_vli)
{
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        p_vli[i] = 0;
    }
}

/* Returns 1 if p_vli == 0, 0 otherwise. */
static int vli_isZero(uint8_t *p_vli)
{
    uint i;
    for(i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        if(p_vli[i])
        {
            return 0;
        }
    }
    return 1;
}

/* Returns nonzero if bit p_bit of p_vli is set. */
static uint8_t vli_testBit(uint8_t *p_vli, uint p_bit)
{
    return (p_vli[p_bit/8] & (1 << (p_bit % 8)));
}

/* Counts the number of 8-bit "digits" in p_vli. */
static uint vli_numDigits(uint8_t *p_vli)
{
    int i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for(i = NUM_ECC_DIGITS - 1; i >= 0 && p_vli[i] == 0; --i)
    {
    }

    return (i + 1);
}

/* Counts the number of bits required for p_vli. */
static uint vli_numBits(uint8_t *p_vli)
{
    uint i;
    uint8_t l_digit;

    uint l_numDigits = vli_numDigits(p_vli);
    if(l_numDigits == 0)
    {
        return 0;
    }

    l_digit = p_vli[l_numDigits - 1];
    for(i=0; l_digit; ++i)
    {
        l_digit >>= 1;
    }

    return ((l_numDigits - 1) * 8 + i);
}

/* Sets p_dest = p_src. */
static void vli_set(uint8_t *p_dest, uint8_t *p_src)
{
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        p_dest[i] = p_src[i];
    }
}

/* Returns sign of p_left - p_right. */
static int vli_cmp(uint8_t *p_left, uint8_t *p_right)
{
    int i;
    for(i = NUM_ECC_DIGITS-1; i >= 0; --i)
    {
        if(p_left[i] > p_right[i])
        {
            return 1;
        }
        else if(p_left[i] < p_right[i])
        {
            return -1;
        }
    }
    return 0;
}

/* Computes p_result = p_in << c, returning carry. Can modify in place (if p_result == p_in). 0 < p_shift < 8. */
static uint8_t vli_lshift(uint8_t *p_result, uint8_t *p_in, uint p_shift)
{
    uint8_t l_carry = 0;
    uint i;
    for(i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        uint8_t l_temp = p_in[i];
        p_result[i] = (l_temp << p_shift) | l_carry;
        l_carry = l_temp >> (8 - p_shift);
    }

    return l_carry;
}

/* Computes p_vli = p_vli >> 1. */
static void vli_rshift1(uint8_t *p_vli)
{
    uint8_t *l_end = p_vli;
    uint8_t l_carry = 0;

    p_vli += NUM_ECC_DIGITS;
    while(p_vli-- > l_end)
    {
        uint8_t l_temp = *p_vli;
        *p_vli = (l_temp >> 1) | l_carry;
        l_carry = l_temp << 7;
    }
}

/* Computes p_result = p_left + p_right, returning carry. Can modify in place. */
static uint8_t vli_add(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right)
{
    uint8_t l_carry = 0;
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        uint8_t l_sum = p_left[i] + p_right[i] + l_carry;
        if(l_sum != p_left[i])
        {
            l_carry = (l_sum < p_left[i]);
            //l_carry = (l_sum < p_left[i]) | ((l_sum == p_left[i]) && (l_carry));
        }
        p_result[i] = l_sum;
    }
    return l_carry;
}

/* Computes p_result = p_left - p_right, returning borrow. Can modify in place. */
static uint8_t vli_sub(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right)
{
    uint8_t l_borrow = 0;
    uint i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        uint8_t l_diff = p_left[i] - p_right[i] - l_borrow;
        if(l_diff != p_left[i])
        {
            l_borrow = (l_diff > p_left[i]);
        }
        p_result[i] = l_diff;
    }
    return l_borrow;
}

/* Computes p_result = p_left * p_right. */
static void vli_mult(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right)
{
    uint16_t r01 = 0;
    uint8_t r2 = 0;

    uint i, k;

    /* Compute each digit of p_result in sequence, maintaining the carries. */
    for(k=0; k < NUM_ECC_DIGITS*2 - 1; ++k)
    {
        uint l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
        for(i=l_min; i<=k && i<NUM_ECC_DIGITS; ++i)
        {
            uint16_t l_product = (uint16_t)p_left[i] * p_right[k-i];
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint8_t)r01;
        r01 = (r01 >> 8) | (((uint16_t)r2) << 8);
        r2 = 0;
    }

    p_result[NUM_ECC_DIGITS*2 - 1] = (uint8_t)r01;
}

/* Computes p_result = (p_left + p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modAdd(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right, uint8_t *p_mod)
{
    uint8_t l_carry = vli_add(p_result, p_left, p_right);
    if(l_carry || vli_cmp(p_result, p_mod) >= 0)
    { /* p_result > p_mod (p_result = p_mod + remainder), so subtract p_mod to get remainder. */
        vli_sub(p_result, p_result, p_mod);
    }
}

/* Computes p_result = (p_left - p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modSub(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right, uint8_t *p_mod)
{
    uint8_t l_borrow = vli_sub(p_result, p_left, p_right);
    if(l_borrow)
    { /* In this case, p_result == -diff == (max int) - diff.
         Since -x % d == d - x, we can get the correct result from p_result + p_mod (with overflow). */
        vli_add(p_result, p_result, p_mod);
    }
}

static void vli_mmod_fast(uint8_t *p_result, uint8_t *p_product) {
    uint8_t l_tmp1[NUM_ECC_DIGITS];
    uint8_t l_tmp2[NUM_ECC_DIGITS];
    uint8_t l_tmp3[NUM_ECC_DIGITS];
    int l_carry = 0;

    vli_set(p_result, p_product);
    vli_clear(l_tmp1);
    vli_clear(l_tmp2);
    vli_clear(l_tmp3);

    /* Y0 */
    l_tmp1[0] = l_tmp1[12] = l_tmp1[28] = p_product[32];
    l_tmp1[1] = l_tmp1[13] = l_tmp1[29] = p_product[33];
    l_tmp1[2] = l_tmp1[14] = l_tmp1[30] = p_product[34];
    l_tmp1[3] = l_tmp1[15] = l_tmp1[31] = p_product[35];
    l_tmp2[8] = p_product[32];
    l_tmp2[9] = p_product[33];
    l_tmp2[10] = p_product[34];
    l_tmp2[11] = p_product[35];
    l_carry += vli_add(p_result, p_result, l_tmp1);
    l_carry -= vli_sub(p_result, p_result, l_tmp2);

    /* Y1 */
    l_tmp1[0] = l_tmp1[4] = l_tmp1[16] = l_tmp1[28] = p_product[36];
    l_tmp1[1] = l_tmp1[5] = l_tmp1[17] = l_tmp1[29] = p_product[37];
    l_tmp1[2] = l_tmp1[6] = l_tmp1[18] = l_tmp1[30] = p_product[38];
    l_tmp1[3] = l_tmp1[7] = l_tmp1[19] = l_tmp1[31] = p_product[39];
    l_tmp1[12] = l_tmp1[13] = l_tmp1[14] = l_tmp1[15] = 0;
    l_tmp2[8] = p_product[36];
    l_tmp2[9] = p_product[37];
    l_tmp2[10] = p_product[38];
    l_tmp2[11] = p_product[39];
    l_carry += vli_add(p_result, p_result, l_tmp1);
    l_carry -= vli_sub(p_result, p_result, l_tmp2);

    /* Y2 */
    l_tmp1[0] = l_tmp1[4] = l_tmp1[20] = l_tmp1[28] = p_product[40];
    l_tmp1[1] = l_tmp1[5] = l_tmp1[21] = l_tmp1[29] = p_product[41];
    l_tmp1[2] = l_tmp1[6] = l_tmp1[22] = l_tmp1[30] = p_product[42];
    l_tmp1[3] = l_tmp1[7] = l_tmp1[23] = l_tmp1[31] = p_product[43];
    l_tmp1[16] = l_tmp1[17] = l_tmp1[18] = l_tmp1[19] = 0;
    l_carry += vli_add(p_result, p_result, l_tmp1);

    /* Y3 */
    l_tmp1[0] = l_tmp1[4] = l_tmp1[12] = l_tmp1[24] = l_tmp1[28] = p_product[44];
    l_tmp1[1] = l_tmp1[5] = l_tmp1[13] = l_tmp1[25] = l_tmp1[29] = p_product[45];
    l_tmp1[2] = l_tmp1[6] = l_tmp1[14] = l_tmp1[26] = l_tmp1[30] = p_product[46];
    l_tmp1[3] = l_tmp1[7] = l_tmp1[15] = l_tmp1[27] = l_tmp1[31] = p_product[47];
    l_tmp1[20] = l_tmp1[21] = l_tmp1[22] = l_tmp1[23] = 0;
    l_carry += vli_add(p_result, p_result, l_tmp1);

    /* Y4 */
    l_tmp1[0] = l_tmp1[4] = l_tmp1[12] = l_tmp1[16] = l_tmp1[28] = l_tmp3[28] = p_product[48];
    l_tmp1[1] = l_tmp1[5] = l_tmp1[13] = l_tmp1[17] = l_tmp1[29] = l_tmp3[29] = p_product[49];
    l_tmp1[2] = l_tmp1[6] = l_tmp1[14] = l_tmp1[18] = l_tmp1[30] = l_tmp3[30] = p_product[50];
    l_tmp1[3] = l_tmp1[7] = l_tmp1[15] = l_tmp1[19] = l_tmp1[31] = l_tmp3[31] = p_product[51];
    l_tmp1[24] = l_tmp1[25] = l_tmp1[26] = l_tmp1[27] = 0;
    l_carry += vli_add(p_result, p_result, l_tmp1);
    l_carry += vli_add(p_result, p_result, l_tmp3);

    /* Y5 */
    l_tmp1[0] = l_tmp1[4] = l_tmp1[12] = l_tmp1[16] = l_tmp1[20] = l_tmp1[28] = p_product[52];
    l_tmp1[1] = l_tmp1[5] = l_tmp1[13] = l_tmp1[17] = l_tmp1[21] = l_tmp1[29] = p_product[53];
    l_tmp1[2] = l_tmp1[6] = l_tmp1[14] = l_tmp1[18] = l_tmp1[22] = l_tmp1[30] = p_product[54];
    l_tmp1[3] = l_tmp1[7] = l_tmp1[15] = l_tmp1[19] = l_tmp1[23] = l_tmp1[31] = p_product[55];
    l_tmp2[8] = p_product[52];
    l_tmp2[9] = p_product[53];
    l_tmp2[10] = p_product[54];
    l_tmp2[11] = p_product[55];
    l_tmp3[0] = l_tmp3[12] = l_tmp3[28] = p_product[52];
    l_tmp3[1] = l_tmp3[13] = l_tmp3[29] = p_product[53];
    l_tmp3[2] = l_tmp3[14] = l_tmp3[30] = p_product[54];
    l_tmp3[3] = l_tmp3[15] = l_tmp3[31] = p_product[55];
    l_carry += vli_add(p_result, p_result, l_tmp1);
    l_carry += vli_add(p_result, p_result, l_tmp3);
    l_carry -= vli_sub(p_result, p_result, l_tmp2);

    /* Y6 */
    l_tmp1[0] = l_tmp1[4] = l_tmp1[12] = l_tmp1[16] = l_tmp1[20] = l_tmp1[24] = l_tmp1[28] = p_product[56]; 
    l_tmp1[1] = l_tmp1[5] = l_tmp1[13] = l_tmp1[17] = l_tmp1[21] = l_tmp1[25] = l_tmp1[29] = p_product[57];
    l_tmp1[2] = l_tmp1[6] = l_tmp1[14] = l_tmp1[18] = l_tmp1[22] = l_tmp1[26] = l_tmp1[30] = p_product[58];
    l_tmp1[3] = l_tmp1[7] = l_tmp1[15] = l_tmp1[19] = l_tmp1[23] = l_tmp1[27] = l_tmp1[31] = p_product[59];
    l_tmp2[8] = p_product[56];
    l_tmp2[9] = p_product[57];
    l_tmp2[10] = p_product[58];
    l_tmp2[11] = p_product[59];
    l_tmp3[0] = l_tmp3[4] = l_tmp3[16] = l_tmp3[28] = p_product[56];
    l_tmp3[1] = l_tmp3[5] = l_tmp3[17] = l_tmp3[29] = p_product[57];
    l_tmp3[2] = l_tmp3[6] = l_tmp3[18] = l_tmp3[30] = p_product[58];
    l_tmp3[3] = l_tmp3[7] = l_tmp3[19] = l_tmp3[31] = p_product[59];
    l_tmp3[12] = l_tmp3[13] = l_tmp3[14] = l_tmp3[15] = 0;
    l_carry += vli_add(p_result, p_result, l_tmp1);
    l_carry += vli_add(p_result, p_result, l_tmp3);
    l_carry -= vli_sub(p_result, p_result, l_tmp2);

    /* Y7 */
    l_tmp1[0] = l_tmp1[4] = l_tmp1[12] = l_tmp1[16] = l_tmp1[20] = l_tmp1[24] = l_tmp1[28] = p_product[60];
    l_tmp1[1] = l_tmp1[5] = l_tmp1[13] = l_tmp1[17] = l_tmp1[21] = l_tmp1[25] = l_tmp1[29] = p_product[61];
    l_tmp1[2] = l_tmp1[6] = l_tmp1[14] = l_tmp1[18] = l_tmp1[22] = l_tmp1[26] = l_tmp1[30] = p_product[62];
    l_tmp1[3] = l_tmp1[7] = l_tmp1[15] = l_tmp1[19] = l_tmp1[23] = l_tmp1[27] = l_tmp1[31] = p_product[63];
    l_tmp3[0] = l_tmp3[4] = l_tmp3[20]  = p_product[60];
    l_tmp3[1] = l_tmp3[5] = l_tmp3[21]  = p_product[61];
    l_tmp3[2] = l_tmp3[6] = l_tmp3[22]  = p_product[62];
    l_tmp3[3] = l_tmp3[7] = l_tmp3[23]  = p_product[63];
    l_tmp3[16] = l_tmp3[17] = l_tmp3[18] = l_tmp3[19] = l_tmp3[28] = l_tmp3[29] = l_tmp3[30] = l_tmp3[31] = 0;
    l_tmp2[28] = p_product[60];
    l_tmp2[29] = p_product[61];
    l_tmp2[30] = p_product[62];
    l_tmp2[31] = p_product[63];
    l_tmp2[8] = l_tmp2[9] = l_tmp2[10] = l_tmp2[11] = 0;
    l_carry += vli_lshift(l_tmp2, l_tmp2, 1);
    l_carry += vli_add(p_result, p_result, l_tmp1);
    l_carry += vli_add(p_result, p_result, l_tmp3);
    l_carry += vli_add(p_result, p_result, l_tmp2);

    if(l_carry < 0)
    {
        do
        {
            l_carry += vli_add(p_result, p_result, curve_p);
        } while(l_carry < 0);
    }
    else
    {
        while(l_carry || vli_cmp(curve_p, p_result) != 1)
        {
            l_carry -= vli_sub(p_result, p_result, curve_p);
        }
    }
}

/* Computes p_result = (p_left * p_right) % curve_p. */
static void vli_modMult_fast(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right)
{
   uint8_t l_product[2 * NUM_ECC_DIGITS];
   vli_mult(l_product, p_left, p_right);
   vli_mmod_fast(p_result, l_product);
}

#if ECC_SQUARE_FUNC

/* Computes p_result = p_left^2. */
static void vli_square(uint8_t *p_result, uint8_t *p_left)
{
    uint16_t r01 = 0;
    uint8_t r2 = 0;

    uint i, k;
    for(k=0; k < NUM_ECC_DIGITS*2 - 1; ++k)
    {
        uint l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
        for(i=l_min; i<=k && i<=k-i; ++i)
        {
            uint16_t l_product = (uint16_t)p_left[i] * p_left[k-i];
            if(i < k-i)
            {
                r2 += l_product >> 15;
                l_product *= 2;
            }
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint8_t)r01;
        r01 = (r01 >> 8) | (((uint16_t)r2) << 8);
        r2 = 0;
    }

    p_result[NUM_ECC_DIGITS*2 - 1] = (uint8_t)r01;
}

/* Computes p_result = p_left^2 % curve_p. */
static void vli_modSquare_fast(uint8_t *p_result, uint8_t *p_left)
{
    uint8_t l_product[2 * NUM_ECC_DIGITS];
    vli_square(l_product, p_left);
    vli_mmod_fast(p_result, l_product);
}

#else /* ECC_SQUARE_FUNC */

#define vli_square(result, left, size) vli_mult((result), (left), (left), (size))
#define vli_modSquare_fast(result, left) vli_modMult_fast((result), (left), (left))

#endif /* ECC_SQUARE_FUNC */

#define EVEN(vli) (!(vli[0] & 1))
/* Computes p_result = (1 / p_input) % p_mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
   https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf */
static void vli_modInv(uint8_t *p_result, uint8_t *p_input, uint8_t *p_mod)
{
    uint8_t a[NUM_ECC_DIGITS], b[NUM_ECC_DIGITS], u[NUM_ECC_DIGITS], v[NUM_ECC_DIGITS];
    uint8_t l_carry;

    vli_set(a, p_input);
    vli_set(b, p_mod);
    vli_clear(u);
    u[0] = 1;
    vli_clear(v);

    int l_cmpResult;
    while((l_cmpResult = vli_cmp(a, b)) != 0)
    {
        l_carry = 0;
        if(EVEN(a))
        {
            vli_rshift1(a);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if(l_carry)
            {
                u[NUM_ECC_DIGITS-1] |= 0x80;
            }
        }
        else if(EVEN(b))
        {
            vli_rshift1(b);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if(l_carry)
            {
                v[NUM_ECC_DIGITS-1] |= 0x80;
            }
        }
        else if(l_cmpResult > 0)
        {
            vli_sub(a, a, b);
            vli_rshift1(a);
            if(vli_cmp(u, v) < 0)
            {
                vli_add(u, u, p_mod);
            }
            vli_sub(u, u, v);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if(l_carry)
            {
                u[NUM_ECC_DIGITS-1] |= 0x80;
            }
        }
        else
        {
            vli_sub(b, b, a);
            vli_rshift1(b);
            if(vli_cmp(v, u) < 0)
            {
                vli_add(v, v, p_mod);
            }
            vli_sub(v, v, u);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if(l_carry)
            {
                v[NUM_ECC_DIGITS-1] |= 0x80;
            }
        }
    }

    vli_set(p_result, u);
}

/* ------ Point operations ------ */

/* Returns 1 if p_point is the point at infinity, 0 otherwise. */
static int EccPoint_isZero(EccPoint *p_point)
{
    return (vli_isZero(p_point->x) && vli_isZero(p_point->y));
}

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
From http://eprint.iacr.org/2011/338.pdf
*/

/* Double in place */
static void EccPoint_double_jacobian(uint8_t *X1, uint8_t *Y1, uint8_t *Z1)
{
    /* t1 = X, t2 = Y, t3 = Z */
    uint8_t t4[NUM_ECC_DIGITS];
    uint8_t t5[NUM_ECC_DIGITS];

    if(vli_isZero(Z1))
    {
        return;
    }

    vli_modSquare_fast(t4, Y1);   /* t4 = y1^2 */
    vli_modMult_fast(t5, X1, t4); /* t5 = x1*y1^2 = A */
    vli_modSquare_fast(t4, t4);   /* t4 = y1^4 */
    vli_modMult_fast(Y1, Y1, Z1); /* t2 = y1*z1 = z3 */
    vli_modSquare_fast(Z1, Z1);   /* t3 = z1^2 */

    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = x1 + z1^2 */
    vli_modAdd(Z1, Z1, Z1, curve_p); /* t3 = 2*z1^2 */
    vli_modSub(Z1, X1, Z1, curve_p); /* t3 = x1 - z1^2 */
    vli_modMult_fast(X1, X1, Z1);    /* t1 = x1^2 - z1^4 */

    vli_modAdd(Z1, X1, X1, curve_p); /* t3 = 2*(x1^2 - z1^4) */
    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = 3*(x1^2 - z1^4) */
    if(vli_testBit(X1, 0))
    {
        uint8_t l_carry = vli_add(X1, X1, curve_p);
        vli_rshift1(X1);
        X1[NUM_ECC_DIGITS-1] |= l_carry << 7;
    }
    else
    {
        vli_rshift1(X1);
    }
                     /* t1 = 3/2*(x1^2 - z1^4) = B */

    vli_modSquare_fast(Z1, X1);      /* t3 = B^2 */
    vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - A */
    vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - 2A = x3 */
    vli_modSub(t5, t5, Z1, curve_p); /* t5 = A - x3 */
    vli_modMult_fast(X1, X1, t5);    /* t1 = B * (A - x3) */
    vli_modSub(t4, X1, t4, curve_p); /* t4 = B * (A - x3) - y1^4 = y3 */

    vli_set(X1, Z1);
    vli_set(Z1, Y1);
    vli_set(Y1, t4);
}

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(uint8_t *X1, uint8_t *Y1, uint8_t *Z)
{
    uint8_t t1[NUM_ECC_DIGITS];

    vli_modSquare_fast(t1, Z);    /* z^2 */
    vli_modMult_fast(X1, X1, t1); /* x1 * z^2 */
    vli_modMult_fast(t1, t1, Z);  /* z^3 */
    vli_modMult_fast(Y1, Y1, t1); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void XYcZ_initial_double(uint8_t *X1, uint8_t *Y1, uint8_t *X2, uint8_t *Y2, uint8_t *p_initialZ)
{
    uint8_t z[NUM_ECC_DIGITS];

    vli_set(X2, X1);
    vli_set(Y2, Y1);

    vli_clear(z);
    z[0] = 1;
    if(p_initialZ)
    {
        vli_set(z, p_initialZ);
    }
    apply_z(X1, Y1, z);

    EccPoint_double_jacobian(X1, Y1, z);

    apply_z(X2, Y2, z);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   Output:x2=x3,y2=y3
   or P => P', Q => P + Q
*/
static void XYcZ_add(uint8_t *X1, uint8_t *Y1, uint8_t *X2, uint8_t *Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uint8_t t5[NUM_ECC_DIGITS];

//X3 = D ? (B + C) ; Y3 = (Y2 ? Y1)(B ? X3) ? E and Z3 = Z(X2 ? X1) 
//A = (X2 ? X1)2, B = X1A, C = X2A, D = (Y2 ? Y1)2 and E = Y1(C ? B)

    vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5);    /* X1 = t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5);    /* X2 = t3 = x2*A = C */
    vli_modSub(Y2, Y2, Y1, curve_p); /* Y2 = t4 = y2 - y1 */
    vli_modSquare_fast(t5, Y2);      /* t5 = (y2 - y1)^2 = D */

//X3 = D ? (B + C)
    vli_modSub(t5, t5, X1, curve_p); /* t5 = D - B */
    vli_modSub(t5, t5, X2, curve_p); /* t5 = D - B - C = x3 */

    vli_modSub(X2, X2, X1, curve_p); /* X2 = t3 = C - B */
    vli_modMult_fast(Y1, Y1, X2);    /* Y1 = t2 = y1*(C - B) = E*/
    vli_modSub(X2, X1, t5, curve_p); /* X2 = t3 = B - x3 */
    vli_modMult_fast(Y2, Y2, X2);    /* Y2 = t4 = (y2 - y1)*(B - x3) */
//y2=y3
    vli_modSub(Y2, Y2, Y1, curve_p); /* Y2 = t4 = y3 */

//x2=t5=x3
    vli_set(X2, t5);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   Output:x1=x3',y1=y3';x2=x3,y2=y3
   or P => P - Q, Q => P + Q
*/
static void XYcZ_addC(uint8_t *X1, uint8_t *Y1, uint8_t *X2, uint8_t *Y2)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uint8_t t5[NUM_ECC_DIGITS];
    uint8_t t6[NUM_ECC_DIGITS];
    uint8_t t7[NUM_ECC_DIGITS];

//s1
    vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
//s2
    vli_modMult_fast(X1, X1, t5);    /* X1 = t1 = x1*A = B */
//s3
    vli_modMult_fast(X2, X2, t5);    /* X2 = t3 = x2*A = C */

//s4
    vli_modAdd(t5, Y2, Y1, curve_p); /* t5 = t4 = y2 + y1 */
    vli_modSub(Y2, Y2, Y1, curve_p); /* Y2 = t4 = y2 - y1 */

//s5 :E = Y1(C ? B)
    vli_modSub(t6, X2, X1, curve_p); /* t6 = C - B */
    vli_modMult_fast(Y1, Y1, t6);    /* t2 = y1 * (C - B) */
//s6 :B + C
    vli_modAdd(t6, X1, X2, curve_p); /* t6 = B + C */
//s4:D=(Y2 ? Y1)^2
    vli_modSquare_fast(X2, Y2);      /* X2 = t3 = (y2 - y1)^2 */
//s6:X3=D ? (B + C)
    vli_modSub(X2, X2, t6, curve_p); /* X2 = t3 = x3 */

//s7:Y3 = (Y2 ? Y1)(B ? X3) ? E
    vli_modSub(t7, X1, X2, curve_p); /* t7 = B - x3 */
    vli_modMult_fast(Y2, Y2, t7);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */

//s4
    vli_modSquare_fast(t7, t5);      /* t7 = (y2 + y1)^2 = F */

//s8:F-(B+C)
    vli_modSub(t7, t7, t6, curve_p); /* t7 = x3' */

//s9
    vli_modSub(t6, t7, X1, curve_p); /* t6 = x3' - B */
    vli_modMult_fast(t6, t6, t5);    /* t6 = (y2 + y1)*(x3' - B) */
    vli_modSub(Y1, t6, Y1, curve_p); /* t2 = y3' */

    vli_set(X1, t7);
}

static void EccPoint_mult(EccPoint *p_result, EccPoint *p_point, uint8_t *p_scalar, uint8_t *p_initialZ)
{
    /* R0 and R1 */
    uint8_t Rx[2][NUM_ECC_DIGITS];
    uint8_t Ry[2][NUM_ECC_DIGITS];
    uint8_t z[NUM_ECC_DIGITS];

    uint i, nb;

    vli_set(Rx[1], p_point->x);
    vli_set(Ry[1], p_point->y);

    XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], p_initialZ);

    for(i = vli_numBits(p_scalar) - 2; i > 0; --i)
    {
        nb = !vli_testBit(p_scalar, i);
        XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
        XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
    }

    nb = !vli_testBit(p_scalar, 0);
    XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);

    /* Find final 1/Z value. */
    vli_modSub(z, Rx[1], Rx[0], curve_p); /* X1 - X0 */
    vli_modMult_fast(z, z, Ry[1-nb]);     /* Yb * (X1 - X0) */
    vli_modMult_fast(z, z, p_point->x);   /* xP * Yb * (X1 - X0) */
    vli_modInv(z, z, curve_p);            /* 1 / (xP * Yb * (X1 - X0)) */
    vli_modMult_fast(z, z, p_point->y);   /* yP / (xP * Yb * (X1 - X0)) */
    vli_modMult_fast(z, z, Rx[1-nb]);     /* Xb * yP / (xP * Yb * (X1 - X0)) */
    /* End 1/Z calculation */

    XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);

    apply_z(Rx[0], Ry[0], z);

    vli_set(p_result->x, Rx[0]);
    vli_set(p_result->y, Ry[0]);
}

int ecc_make_key(EccPoint *p_publicKey, uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS])
{
    /* Make sure the private key is in the range [1, n-1].
       For the supported curves, n is always large enough that we only need to subtract once at most. */
    vli_set(p_privateKey, p_random);
    if(vli_cmp(curve_n, p_privateKey) != 1)
    {
        vli_sub(p_privateKey, p_privateKey, curve_n);
    }

    if(vli_isZero(p_privateKey))
    {
        return 0; /* The private key cannot be 0 (mod p). */
    }

    EccPoint_mult(p_publicKey, &curve_G, p_privateKey, NULL);
    return 1;
}

int ecc_valid_public_key(EccPoint *p_publicKey)
{
    uint8_t na[NUM_ECC_DIGITS] = {3}; /* a mod p = (-3) mod p */

    uint8_t l_tmp1[NUM_ECC_DIGITS];
    uint8_t l_tmp2[NUM_ECC_DIGITS];

    if(EccPoint_isZero(p_publicKey))
    {
        return 0;
    }

    if(vli_cmp(curve_p, p_publicKey->x) != 1 || vli_cmp(curve_p, p_publicKey->y) != 1)
    {
        return 0;
    }

    vli_modSquare_fast(l_tmp1, p_publicKey->y); /* tmp1 = y^2 */
    vli_modSquare_fast(l_tmp2, p_publicKey->x); /* tmp2 = x^2 */
    vli_modSub(l_tmp2, l_tmp2, na, curve_p);  /* tmp2 = x^2 + a = x^2 - 3 */
    vli_modMult_fast(l_tmp2, l_tmp2, p_publicKey->x); /* tmp2 = x^3 + ax */
    vli_modAdd(l_tmp2, l_tmp2, curve_b, curve_p); /* tmp2 = x^3 + ax + b */

    /* Make sure that y^2 == x^3 + ax + b */
    if(vli_cmp(l_tmp1, l_tmp2) != 0)
    {
        return 0;
    }

    return 1;
}

int ecdh_shared_secret(uint8_t p_secret[NUM_ECC_DIGITS], EccPoint *p_publicKey, uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS])
{
    EccPoint l_product;

    EccPoint_mult(&l_product, p_publicKey, p_privateKey, p_random);
    if(EccPoint_isZero(&l_product))
    {
        return 0;
    }

    vli_set(p_secret, l_product.x);

    return 1;
}

#if SM2_ECDSA

extern int sm2_get_z(unsigned char *IDa, int IDLen, unsigned char *xa, unsigned char *ya, unsigned char *Za);
extern void sm3(unsigned char *input, int ilen, unsigned char output[32]);

int sm2_get_e(char *IDa, int IDLen, unsigned char *xa, unsigned char *ya, unsigned char *plaintext, unsigned int plainLen, unsigned char *e)
{
#define SM3_OUTSIZE     32

    unsigned char Za[64];
    unsigned char *M;

    sm2_get_z((unsigned char *)IDa, strlen(IDa), xa, ya, Za);
    M = (unsigned char *)malloc(plainLen + SM3_OUTSIZE);
    memset(M, 0, plainLen + SM3_OUTSIZE);
    memcpy(M, Za, SM3_OUTSIZE);
    memcpy(M + SM3_OUTSIZE, plaintext, plainLen);
    sm3(M, SM3_OUTSIZE + plainLen, e);

#if 0
    int i = 0;
    printf("HASH:");
    for (i = 0; i < 32; i++){
        printf("%02X ",e[i]);
    }
    printf("\n");
#endif

    free(M);
    return 1;
}

/* ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)ã?*/
int sm2_get_z(unsigned char *IDa, int IDLen, unsigned char *xa, unsigned char *ya, unsigned char *Za)
{

    unsigned char Z[256];
    unsigned char *p = Z;
    unsigned int len = 0;
    
    unsigned char a[] = { 
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC 
    };

    unsigned char b[] = { 
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
    0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
    0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93 
    };

    unsigned char xG[] = { 
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
    0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
    0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7 
    };

    unsigned char yG[] = { 
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
    0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
    0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0 
    };

    unsigned short idBitLen = IDLen * 8;

    if (IDLen > 32)
        return -1;

    *p = (idBitLen >> 8) & 0xff;
    *(p + 1) = idBitLen & 0xff;
    p += sizeof(idBitLen);
    len += sizeof(idBitLen);

    memcpy(p, IDa, IDLen);
    p += IDLen;
    len += IDLen;

    memcpy(p, a, sizeof(a));
    p += sizeof(a);    
    len += sizeof(a);

    memcpy(p, b, sizeof(b));
    p += sizeof(b);    
    len += sizeof(b);

    memcpy(p, xG, sizeof(xG));
    p += sizeof(xG);
    len += sizeof(xG);

    memcpy(p, yG, sizeof(yG));
    p += sizeof(yG);
    len += sizeof(yG);

    memcpy(p, xa, 32);
    p += 32;
    len += 32;

    memcpy(p, ya, 32);
    //p += 32;
    len += 32;

    //len = (unsigned int)p - (unsigned int)Z;
    sm3(Z, len, Za);

    return 0;
}

/* -------- ECDSA code -------- */

/* Computes p_result = (p_left * p_right) % p_mod. */
static void vli_modMult(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right, uint8_t *p_mod)
{
    uint8_t l_product[2 * NUM_ECC_DIGITS];
    uint8_t l_modMultiple[2 * NUM_ECC_DIGITS];
    uint l_digitShift, l_bitShift;
    uint l_productBits;
    uint l_modBits = vli_numBits(p_mod);
    
    vli_mult(l_product, p_left, p_right);
    l_productBits = vli_numBits(l_product + NUM_ECC_DIGITS);
    if(l_productBits)
    {
        l_productBits += NUM_ECC_DIGITS * 8;
    }
    else
    {
        l_productBits = vli_numBits(l_product);
    }
    
    if(l_productBits < l_modBits)
    { /* l_product < p_mod. */
        vli_set(p_result, l_product);
        return;
    }
    
    /* Shift p_mod by (l_leftBits - l_modBits). This multiplies p_mod by the largest
       power of two possible while still resulting in a number less than p_left. */
    vli_clear(l_modMultiple);
    vli_clear(l_modMultiple + NUM_ECC_DIGITS);
    l_digitShift = (l_productBits - l_modBits) / 8;
    l_bitShift = (l_productBits - l_modBits) % 8;
    if(l_bitShift)
    {
        l_modMultiple[l_digitShift + NUM_ECC_DIGITS] = vli_lshift(l_modMultiple + l_digitShift, p_mod, l_bitShift);
    }
    else
    {
        vli_set(l_modMultiple + l_digitShift, p_mod);
    }

    /* Subtract all multiples of p_mod to get the remainder. */
    vli_clear(p_result);
    p_result[0] = 1; /* Use p_result as a temp var to store 1 (for subtraction) */
    while(l_productBits > NUM_ECC_DIGITS * 8 || vli_cmp(l_modMultiple, p_mod) >= 0)
    {
        int l_cmp = vli_cmp(l_modMultiple + NUM_ECC_DIGITS, l_product + NUM_ECC_DIGITS);
        if(l_cmp < 0 || (l_cmp == 0 && vli_cmp(l_modMultiple, l_product) <= 0))
        {
            if(vli_sub(l_product, l_product, l_modMultiple))
            { /* borrow */
                vli_sub(l_product + NUM_ECC_DIGITS, l_product + NUM_ECC_DIGITS, p_result);
            }
            vli_sub(l_product + NUM_ECC_DIGITS, l_product + NUM_ECC_DIGITS, l_modMultiple + NUM_ECC_DIGITS);
        }
        uint8_t l_carry = (l_modMultiple[NUM_ECC_DIGITS] & 0x01) << 7;
        vli_rshift1(l_modMultiple + NUM_ECC_DIGITS);
        vli_rshift1(l_modMultiple);
        l_modMultiple[NUM_ECC_DIGITS-1] |= l_carry;
        
        --l_productBits;
    }
    vli_set(p_result, l_product);
}

static uint max(uint a, uint b)
{
    return (a > b ? a : b);
}

//************ DSA Sign with SM2 ************//
int ecdsa_sign(uint8_t r[NUM_ECC_DIGITS], uint8_t s[NUM_ECC_DIGITS], uint8_t p_privateKey[NUM_ECC_DIGITS],
    uint8_t p_random[NUM_ECC_DIGITS], uint8_t p_hash[NUM_ECC_DIGITS])
{
    uint8_t k[NUM_ECC_DIGITS];
    EccPoint p;
    
    if(vli_isZero(p_random))
    { /* The random number must not be 0. */
        return 0;
    }
    
    vli_set(k, p_random);
    if(vli_cmp(curve_n, k) != 1)
    {
        vli_sub(k, k, curve_n);
    }
    
    /* tmp = k * G */
    EccPoint_mult(&p, &curve_G, k, NULL);
    
    /* r = x1 + e (mod n) */
    vli_set(r, p.x);
    vli_modAdd(r, r, p_hash, curve_n);
    if(vli_cmp(curve_n, r) != 1)
    {
        vli_sub(r, r, curve_n);
    }
    if(vli_isZero(r))
    { /* If r == 0, fail (need a different random number). */
        return 0;
    }
    
    vli_modMult(s, r, p_privateKey, curve_n); /* s = r*d */
    vli_modSub(s, k, s, curve_n); /* k-r*d */
    uint8_t one[NUM_ECC_DIGITS] = {1};
    vli_modAdd(p_privateKey, p_privateKey, one, curve_n); /* 1+d */
    vli_modInv(p_privateKey, p_privateKey, curve_n); /* (1+d)' */
    vli_modMult(s, p_privateKey, s, curve_n); /* (1+d)'*(k-r*d) */
    
    return 1;
}

/************ DSA Verify with SM2 ************/
int ecdsa_verify(EccPoint *p_publicKey, uint8_t p_hash[NUM_ECC_DIGITS], uint8_t r[NUM_ECC_DIGITS], uint8_t s[NUM_ECC_DIGITS])
{
    uint8_t z[NUM_ECC_DIGITS];
    EccPoint l_sum;
    uint8_t rx[NUM_ECC_DIGITS];
    uint8_t ry[NUM_ECC_DIGITS];
    uint8_t tx[NUM_ECC_DIGITS];
    uint8_t ty[NUM_ECC_DIGITS];
    uint8_t tz[NUM_ECC_DIGITS];
    
    if(vli_isZero(r) || vli_isZero(s))
    { /* r, s must not be 0. */
        return 0;
    }

    if(vli_cmp(curve_n, r) != 1 || vli_cmp(curve_n, s) != 1)
    { /* r, s must be < n. */
        return 0;
    }

    uint8_t t[NUM_ECC_DIGITS];
    vli_modAdd(t, r, s, curve_n); // r + s
    if (t == 0) return 0;

    //sG + tPa
    /* Calculate l_sum = G + Q. */
    vli_set(l_sum.x, p_publicKey->x);
    vli_set(l_sum.y, p_publicKey->y);
    vli_set(tx, curve_G.x);
    vli_set(ty, curve_G.y);
    vli_modSub(z, l_sum.x, tx, curve_p); /* Z = x2 - x1 */
    XYcZ_add(tx, ty, l_sum.x, l_sum.y);
    vli_modInv(z, z, curve_p); /* Z = 1/Z */
    apply_z(l_sum.x, l_sum.y, z);//l_sum.x/Z^2, l_sum.y/Z^3
    
    /* Use Shamir's trick to calculate u1*G + u2*Q */
    EccPoint *l_points[4] = {NULL, &curve_G, p_publicKey, &l_sum};
    uint l_numBits = max(vli_numBits(s), vli_numBits(t));
    
    EccPoint *l_point = l_points[(!!vli_testBit(s, l_numBits-1)) | ((!!vli_testBit(t, l_numBits-1)) << 1)];
    vli_set(rx, l_point->x);
    vli_set(ry, l_point->y);
    vli_clear(z);
    z[0] = 1;

    int i;
    for(i = l_numBits - 2; i >= 0; --i)
    {
        EccPoint_double_jacobian(rx, ry, z);
        
        int l_index = (!!vli_testBit(s, i)) | ((!!vli_testBit(t, i)) << 1);
        EccPoint *l_point = l_points[l_index];
        if(l_point)
        {
            vli_set(tx, l_point->x);
            vli_set(ty, l_point->y);
            apply_z(tx, ty, z);
            vli_modSub(tz, rx, tx, curve_p); /* Z = x2 - x1 */
            XYcZ_add(tx, ty, rx, ry);
            vli_modMult_fast(z, z, tz);
        }
    }

    vli_modInv(z, z, curve_p); /* Z = 1/Z */
    apply_z(rx, ry, z);
    
    /* v = x1 + e (mod n) */
    vli_modAdd(rx, rx, p_hash, curve_n);

    if(vli_cmp(curve_n, rx) != 1)
    {
        vli_sub(rx, rx, curve_n);
    }

    /* Accept only if v == r. */
    return (vli_cmp(rx, r) == 0);
}

int sm2_sign(EccSig *sig, uint8_t *msg, unsigned int msg_len, uint8_t *IDa, uint8_t IDa_len, uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS])
{
    int i = 0;
    int ret = 0;
    uint8_t tmp = 0;
    uint8_t br[NUM_ECC_DIGITS];//r
    uint8_t bs[NUM_ECC_DIGITS];//s
    uint8_t p_pvk[NUM_ECC_DIGITS];//p_pvk
    uint8_t p_rnd[NUM_ECC_DIGITS];//p_rand
    uint8_t e_hash[NUM_ECC_DIGITS];
    EccPoint p_publicKey, p_pubk;

    for (i=0; i<NUM_ECC_DIGITS; i++)
    {
        p_pvk[i] = p_privateKey[NUM_ECC_DIGITS - 1 -i];
        p_rnd[i] = p_random[NUM_ECC_DIGITS - 1 -i];
    }

    EccPoint_mult(&p_publicKey, &curve_G, p_pvk, NULL);

    for (i=0; i<NUM_ECC_DIGITS; i++)
    {
        p_pubk.x[i] = p_publicKey.x[NUM_ECC_DIGITS - 1 -i];
        p_pubk.y[i] = p_publicKey.y[NUM_ECC_DIGITS - 1 -i];
    }

#ifdef __SM2_DEBUG__
    printf("\n-revert-p_rnd:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", p_rnd[i]);
    }
    printf("\n");

    printf("\n-normal-p_pubkx:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", p_pubk.x[i]);
    }
    printf("\n");

    printf("\n-normal-p_pubky:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", p_pubk.y[i]);
    }
    printf("\n");

    printf("\n-msg:");
    for (i = 0; i<msg_len; i++)
    {
        printf("%02X", msg[i]);
    }
    printf("\n");

    printf("\nIDa:");
    for (i = 0; i<IDa_len; i++)
    {
        printf("%02X", IDa[i]);
    }
    printf("\n");
#endif

    //Õý³£¼ÆËãeÖµ
    sm2_get_e(IDa, IDa_len, p_pubk.x, p_pubk.y, msg, msg_len, e_hash);

    for (i=0; i<NUM_ECC_DIGITS/2; i++)
    {
        tmp = e_hash[i];
        e_hash[i] = e_hash[NUM_ECC_DIGITS - 1 -i];
        e_hash[NUM_ECC_DIGITS - 1 -i] = tmp;
    }
#ifdef __SM2_DEBUG__
    printf("\nrevert p_hash:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", e_hash[i]);
    }
    printf("\n");
#endif

    if (1 != ecdsa_sign(br, bs, p_pvk, p_rnd, e_hash))
    {
        printf("ecdsa_sign error\n");
        return 0;
    }

    for (i=0; i<NUM_ECC_DIGITS; i++)
    {
        sig->r[i] = br[NUM_ECC_DIGITS - 1 -i];
        sig->s[i] = bs[NUM_ECC_DIGITS - 1 -i];
    }

    return 1;
}

int sm2_verify(EccSig *sig, uint8_t *msg, unsigned int msg_len, uint8_t *IDa, uint8_t IDa_len, EccPoint *p_pubk)
{
    int i = 0;
    uint8_t br[NUM_ECC_DIGITS];//r
    uint8_t bs[NUM_ECC_DIGITS];//s
    uint8_t p_pvk[NUM_ECC_DIGITS];//p_pvk
    uint8_t p_rnd[NUM_ECC_DIGITS];//p_rand
    uint8_t e_hash[NUM_ECC_DIGITS];
    uint8_t p_hash[NUM_ECC_DIGITS];

    EccPoint p_publicKey;

    //Õý³£¼ÆËãeÖµ
    sm2_get_e(IDa, IDa_len, p_pubk->x, p_pubk->y, msg, msg_len, e_hash);

    for (i=0; i<NUM_ECC_DIGITS; i++)
    {
        br[i] = sig->r[NUM_ECC_DIGITS - 1 - i];
        bs[i] = sig->s[NUM_ECC_DIGITS - 1 - i];
        p_publicKey.x[i] = p_pubk->x[NUM_ECC_DIGITS - 1 - i];
        p_publicKey.y[i] = p_pubk->y[NUM_ECC_DIGITS - 1 - i];
        p_hash[i] = e_hash[NUM_ECC_DIGITS - 1 - i];
    }
#ifdef __SM2_DEBUG__
    printf("\nbr:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", br[i]);
    }
    printf("\n");

    printf("\nbs:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", bs[i]);
    }
    printf("\n");

    
    printf("\n-revert-p_pubkx:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", p_publicKey.x[i]);
    }
    printf("\n");

    
    printf("\n-revert-p_pubky:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", p_publicKey.y[i]);
    }
    printf("\n");

    printf("\nsm2_verify revert p_hash:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", p_hash[i]);
    }
    printf("\n");
#endif

    return ecdsa_verify(&p_publicKey, p_hash, br, bs);
}

int EccPoint_is_on_curve(EccPoint C1)
{
    uint8_t x[NUM_ECC_DIGITS];
    uint8_t y[NUM_ECC_DIGITS];

    vli_modSquare_fast(y, C1.y); /* tmp1 = y^2 */
    vli_modSquare_fast(x, C1.x); /* tmp2 = x^2 */
    vli_modAdd(x, x, curve_a, curve_p);  /* tmp2 = x^2 + a */
    vli_modMult_fast(x, x, C1.x); /* tmp2 = x^3 + ax */
    vli_modAdd(x, x, curve_b, curve_p); /* tmp2 = x^3 + ax + b */

    /* Make sure that y^2 == x^3 + ax + b */
    if(vli_cmp(y, x) != 0)
    {
        printf("not on curve: y^2 == x^3 + ax + b\n");
        return 0;
    }

    return 1;
}

int sm2_encrypt(uint8_t *cipher_text, unsigned int *cipher_len, EccPoint *p_publicKey, uint8_t p_random[NUM_ECC_DIGITS], uint8_t *plain_text, unsigned int plain_len)
{
    int i = 0;
    uint8_t PC = 0X04;
    uint8_t tmp = 0x00;
    uint8_t k[NUM_ECC_DIGITS];
    EccPoint C1;
    EccPoint Pb;
    EccPoint point2;
    EccPoint point2_revert;

    uint8_t x2y2[NUM_ECC_DIGITS * 2];
    uint8_t C2[plain_len];
    uint8_t C3[NUM_ECC_DIGITS];
    sm3_context sm3_ctx;

    if (*cipher_len < NUM_ECC_DIGITS * 3 + 1 + plain_len)
    {
        printf("ciphertext buffer len error\n");
        return 0;
    }
    
//A1:generate random number k;
    for (i=0; i < NUM_ECC_DIGITS; i++)
    {
        k[i] = p_random[NUM_ECC_DIGITS - i - 1];
    }

//A2:C1=[k]G;
    EccPoint_mult(&C1, &curve_G, k, NULL);
    for (i=0; i < NUM_ECC_DIGITS/2; i++)
    {
        tmp = C1.x[i];
        C1.x[i] = C1.x[NUM_ECC_DIGITS - i - 1];
        C1.x[NUM_ECC_DIGITS - i - 1] = tmp;

        tmp = C1.y[i];
        C1.y[i] = C1.y[NUM_ECC_DIGITS - i - 1];
        C1.y[NUM_ECC_DIGITS - i - 1] = tmp;
    }

//A3:h=1;S=[h]Pb;
    for (i=0; i < NUM_ECC_DIGITS; i++)
    {
        Pb.x[i] = p_publicKey->x[NUM_ECC_DIGITS - i - 1];
        Pb.y[i] = p_publicKey->y[NUM_ECC_DIGITS - i - 1];
    }
    if(EccPoint_isZero(&Pb))
    {
        printf("S at infinity...\n");
        return 0;
    }

//A4:[k]Pb = (x2, y2);
    EccPoint_mult(&point2, &Pb, k, NULL);
    for (i=0; i < NUM_ECC_DIGITS; i++)
    {
        point2_revert.x[i] = point2.x[NUM_ECC_DIGITS - i - 1];
        point2_revert.y[i] = point2.y[NUM_ECC_DIGITS - i - 1];
    }

//A5: t =KDF(x2||y2, klen)
    memcpy(x2y2, point2_revert.x, NUM_ECC_DIGITS);
    memcpy(x2y2 + NUM_ECC_DIGITS, point2_revert.y, NUM_ECC_DIGITS);

    x9_63_kdf_sm3(x2y2, NUM_ECC_DIGITS * 2, C2, plain_len);
    if(vli_isZero(C2))
    { /* If r == 0, fail (need a different random number). */
        return 0;
    }

//A6: C2 = M^t;
    for (i = 0; i < plain_len; i++) 
    {
        C2[i] ^= plain_text[i];
    }

//A7:C3 = Hash(x2, M, y2);
    sm3_starts(&sm3_ctx);
    sm3_update(&sm3_ctx, point2_revert.x, NUM_ECC_DIGITS);
    sm3_update(&sm3_ctx, plain_text, plain_len);
    sm3_update(&sm3_ctx, point2_revert.y, NUM_ECC_DIGITS);
    sm3_finish(&sm3_ctx, C3);

//A8:C=C1||C3||C2
    cipher_text[0] = PC;
    *cipher_len = 1;
    memcpy(cipher_text + *cipher_len, C1.x, NUM_ECC_DIGITS * 2);
    *cipher_len += NUM_ECC_DIGITS * 2;
    memcpy(cipher_text + *cipher_len, C3, NUM_ECC_DIGITS);
    *cipher_len += NUM_ECC_DIGITS;
    memcpy(cipher_text + *cipher_len, C2, plain_len);
    *cipher_len += plain_len;

    return 1;
}

int sm2_decrypt(uint8_t *plain_text, uint8_t *plain_len, uint8_t *cipher_text, uint8_t cipher_len, uint8_t p_privateKey[NUM_ECC_DIGITS])
{
    int i = 0;
    int ret = 0;
    sm3_context sm3_ctx;
    EccPoint point2;
    EccPoint point2_revrt;
    uint8_t mac[NUM_ECC_DIGITS];
    uint8_t x2y2[NUM_ECC_DIGITS * 2];
    EccPoint C1;
    EccPoint S;
    uint8_t p_pvk[NUM_ECC_DIGITS];

    EccPoint *p_C1;
    uint8_t *p_C3;
    uint8_t *p_C2;
    int C2_len = 0;

    p_C1 = (EccPoint *)(cipher_text + 1);
    p_C3 = cipher_text + NUM_ECC_DIGITS*2 + 1;
    p_C2 = cipher_text + NUM_ECC_DIGITS*3 + 1;
    C2_len = cipher_len - NUM_ECC_DIGITS*3 - 1;
    
    if (*plain_len < C2_len)
    {
        printf("plaintext buffer len error\n");
        return 0;
    }

    for (i = 0; i < NUM_ECC_DIGITS; i++)
    {
        C1.x[i] = p_C1->x[NUM_ECC_DIGITS - i - 1];
        C1.y[i] = p_C1->y[NUM_ECC_DIGITS - i - 1];
        p_pvk[i] = p_privateKey[NUM_ECC_DIGITS - i - 1];
    }

    ret = EccPoint_is_on_curve(C1);
    if (1 != ret)
    {
        printf("C1 error\n");
        return 0;
    }

//B2:h=1;S=[h]C1;
    if(EccPoint_isZero(&C1))
    {
        printf("S at infinity...\n");
        return 0;
    }

#ifdef __SM2_DEBUG__
    printf("p_privateKey:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", p_pvk[i]);
    }

    printf("\ncipher->C1.x:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", C1.x[i]);
    }

    printf("\ncipher->C1.y:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", C1.y[i]);
    }
    printf("\n");
#endif

//B3:[dB]C1 = (x2, y2);
    EccPoint_mult(&point2, &C1, p_pvk, NULL);
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        point2_revrt.x[i] = point2.x[NUM_ECC_DIGITS - i - 1];
        point2_revrt.y[i] = point2.y[NUM_ECC_DIGITS - i - 1];
    }

#ifdef __SM2_DEBUG__
    printf("point2.x:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", point2.x[i]);
    }

    printf("\npoint2.y:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", point2.y[i]);
    }
#endif

//B4: t =KDF(x2||y2, klen)
    memcpy(x2y2, point2_revrt.x, NUM_ECC_DIGITS);
    memcpy(x2y2 + NUM_ECC_DIGITS, point2_revrt.y, NUM_ECC_DIGITS);

    *plain_len = C2_len;
    x9_63_kdf_sm3(x2y2, NUM_ECC_DIGITS * 2, plain_text, *plain_len);
    if(vli_isZero(plain_text))
    { /* If r == 0, fail (need a different random number). */
        return 0;
    }

#ifdef __SM2_DEBUG__
    printf("\nkdf out:");
    for (i = 0; i<*plain_len; i++)
    {
        printf("%02X", plain_text[i]);
    }

    printf("\nC2:");
    for (i = 0; i < C2_len; i++) 
    {
        printf("%02X", p_C2[i]);
    }
#endif

//B5:M' = C2 ^ t;
    for (i = 0; i < C2_len; i++) 
    {
        plain_text[i] ^= p_C2[i];
    }

// B6: check Hash(x2 || M || y2) == C3
    sm3_starts(&sm3_ctx);
    sm3_update(&sm3_ctx, point2_revrt.x, NUM_ECC_DIGITS);
    sm3_update(&sm3_ctx, plain_text, *plain_len);
    sm3_update(&sm3_ctx, point2_revrt.y, NUM_ECC_DIGITS);
    sm3_finish(&sm3_ctx, mac);

#ifdef __SM2_DEBUG__
    printf("\nmac:");
    for (i = 0; i < NUM_ECC_DIGITS; i++) 
    {
        printf("%02X", mac[i]);
    }

    printf("\ncipher->M:");
    for (i = 0; i < NUM_ECC_DIGITS; i++) 
    {
        printf("%02X", p_C3[i]);
    }
    printf("\n");
#endif

    if (0 != memcmp(p_C3, mac, NUM_ECC_DIGITS)) 
    {
        printf("hash error\n");
        return 0;
    }

    return 1;
}




#endif /* SM2_ECDSA */

void ecc_bytes2native(uint8_t p_native[NUM_ECC_DIGITS], uint8_t p_bytes[NUM_ECC_DIGITS*4])
{
    unsigned i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        p_native[i] = p_bytes[NUM_ECC_DIGITS-i-1];
    }
}

void ecc_native2bytes(uint8_t p_bytes[NUM_ECC_DIGITS*4], uint8_t p_native[NUM_ECC_DIGITS])
{
    unsigned i;
    for(i=0; i<NUM_ECC_DIGITS; ++i)
    {
        p_bytes[NUM_ECC_DIGITS-i-1] = p_native[i];
    }
}
