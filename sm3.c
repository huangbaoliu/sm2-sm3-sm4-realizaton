/*
 * SM3 Hash alogrith 
 * thanks to Xyssl
 * author:goldboar
 * email:goldboar@163.com
 * 2011-10-26
 */

//Testing data from SM3 Standards
//http://www.oscca.gov.cn/News/201012/News_1199.htm 

// Sample 1
// Input:"abc"  
// Output:66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

// Sample 2 
// Input:"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
// Outpuf:debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732

#include "sm3.h"
#include <string.h>
#include <stdio.h>

//#define  SM3_DEBUG 1
/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned int) (b)[(i)    ] << 24 )        \
        | ( (unsigned int) (b)[(i) + 1] << 16 )        \
        | ( (unsigned int) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned int) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif


/*
 * SM3 compression function for single message block of 512-bit
 */
static void sm3_process( sm3_context *ctx, unsigned char data[64] )
{
    unsigned int SS1, SS2, TT1, TT2, W[68],W1[64];
    unsigned int A, B, C, D, E, F, G, H;
    unsigned int T[64];
    unsigned int Temp1,Temp2,Temp3,Temp4,Temp5;
    int j;
#ifdef SM3_DEBUG
    int i;
#endif

//  for(j=0; j < 68; j++)
//      W[j] = 0;
//  for(j=0; j < 64; j++)
//      W1[j] = 0;
    
    for(j = 0; j < 16; j++)
        T[j] = 0x79CC4519;
    for(j =16; j < 64; j++)
        T[j] = 0x7A879D8A;

    GET_ULONG_BE( W[ 0], data,  0 );
    GET_ULONG_BE( W[ 1], data,  4 );
    GET_ULONG_BE( W[ 2], data,  8 );
    GET_ULONG_BE( W[ 3], data, 12 );
    GET_ULONG_BE( W[ 4], data, 16 );
    GET_ULONG_BE( W[ 5], data, 20 );
    GET_ULONG_BE( W[ 6], data, 24 );
    GET_ULONG_BE( W[ 7], data, 28 );
    GET_ULONG_BE( W[ 8], data, 32 );
    GET_ULONG_BE( W[ 9], data, 36 );
    GET_ULONG_BE( W[10], data, 40 );
    GET_ULONG_BE( W[11], data, 44 );
    GET_ULONG_BE( W[12], data, 48 );
    GET_ULONG_BE( W[13], data, 52 );
    GET_ULONG_BE( W[14], data, 56 );
    GET_ULONG_BE( W[15], data, 60 );

#ifdef SM3_DEBUG 
    printf("Message with padding:\n");
    for(i=0; i< 8; i++)
        printf("%08x ",W[i]);
    printf("\n");
    for(i=8; i< 16; i++)
        printf("%08x ",W[i]);
    printf("\n");
#endif

#define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


#define SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17)) 
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23)) 

    for(j = 16; j < 68; j++ )
    {
        //W[j] = P1( W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j - 13],7 ) ^ W[j-6];
        //Why thd release's result is different with the debug's ?
        //Below is okay. Interesting, Perhaps VC6 has a bug of Optimizaiton.
        
        Temp1 = W[j-16] ^ W[j-9];
        Temp2 = ROTL(W[j-3],15);
        Temp3 = Temp1 ^ Temp2;
        Temp4 = P1(Temp3);
        Temp5 =  ROTL(W[j - 13],7 ) ^ W[j-6];
        W[j] = Temp4 ^ Temp5;
    }

#ifdef SM3_DEBUG 
    printf("Expanding message W0-67:\n");
    for(i=0; i<68; i++)
    {
        printf("%08x ",W[i]);
        if(((i+1) % 8) == 0) printf("\n");
    }
    printf("\n");
#endif

    for(j =  0; j < 64; j++)
    {
        W1[j] = W[j] ^ W[j+4];
    }

#ifdef SM3_DEBUG 
    printf("Expanding message W'0-63:\n");
    for(i=0; i<64; i++)
    {
        printf("%08x ",W1[i]);
        if(((i+1) % 8) == 0) printf("\n");
    }
    printf("\n");
#endif

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];
#ifdef SM3_DEBUG       
    printf("j     A       B        C         D         E        F        G       H\n");
    printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",A,B,C,D,E,F,G,H);
#endif

    for(j =0; j < 16; j++)
    {
        SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7); 
        SS2 = SS1 ^ ROTL(A,12);
        TT1 = FF0(A,B,C) + D + SS2 + W1[j];
        TT2 = GG0(E,F,G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F,19);
        F = E;
        E = P0(TT2);
#ifdef SM3_DEBUG 
        printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif
    }
    
    for(j =16; j < 64; j++)
    {
        SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7); 
        SS2 = SS1 ^ ROTL(A,12);
        TT1 = FF1(A,B,C) + D + SS2 + W1[j];
        TT2 = GG1(E,F,G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F,19);
        F = E;
        E = P0(TT2);
#ifdef SM3_DEBUG 
        printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif  
    }

    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
#ifdef SM3_DEBUG 
       printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",ctx->state[0],ctx->state[1],ctx->state[2],
                                  ctx->state[3],ctx->state[4],ctx->state[5],ctx->state[6],ctx->state[7]);
#endif
}


/*
 * SM3 context init setup
 */
void sm3_starts( sm3_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;
}


/*
 * SM3 process buffer
 */
void sm3_update( sm3_context *ctx, unsigned char *input, int ilen )
{
    int fill;
    unsigned int left;

    if( ilen <= 0 )
        return;

    left = ctx->total[0] & 0x3F;   //先判断当前ctx中已处理完的消息块字节长度模64后剩余的字节数，这是上一个SM3_update函数处理字节数模64后的残留字节数
    fill = 64 - left;              //fill为填满64字节需要在残留字节基础上再补充的字节数
    ctx->total[0] += ilen;         //更新当前SM3_update函数处理完的字节数
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (unsigned int) ilen ) //满足该条件时要进位
        ctx->total[1]++;
/*byte completement to 64 bytes*/
    if( left && ilen >= fill ) //首先，根据需要先配合上次SM3_update处理完后的buffer残留进行第一步的处理
    {
        memcpy( (void *) (ctx->buffer + left), (void *) input, fill );
        sm3_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

/*process 64 bytes as a group*/
    while( ilen >= 64 )  //其次，处理input缓存中正好是64字节（512-bit）整数倍对应的数据流
    {
        sm3_process( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )   //最后，将 input缓存区中的剩余数据拷贝到 buffer中供下一次调用SM3_update时使用或供 SM3_finish进行最后的处理
    {
        memcpy( (void *) (ctx->buffer + left), (void *) input, ilen );
    }
}

static const unsigned char sm3_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SM3 final digest
 */
void sm3_finish( sm3_context *ctx, unsigned char output[32] )
{
    unsigned int last, padn;
    unsigned int high, low;
    unsigned char msglen[8];  //该8个字节用于填充最后一块中的64比特长度信息

    /*use << 3 because of using binary expression*/
    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 ); //将total的字节长度信息转换为bit长度信息，注意到total[1]是高位，而total[0]是低位

    PUT_ULONG_BE( high, msglen, 0 );
    PUT_ULONG_BE( low,  msglen, 4 );


    //最后一块的填充逻辑， 包括  “10..0 + 64-bit的长度填充”对应的总字节数,padn表示"10..0"部分对应的字节数

    last = ctx->total[0] & 0x3F; //last注意这里total[1]是高位，total[0]%64 表示低位表示最后一个分块内的已有消息长度字节长度
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sm3_update( ctx, (unsigned char *) sm3_padding, padn );
    sm3_update( ctx, msglen, 8);

    PUT_ULONG_BE( ctx->state[0], output,  0 );
    PUT_ULONG_BE( ctx->state[1], output,  4 );
    PUT_ULONG_BE( ctx->state[2], output,  8 );
    PUT_ULONG_BE( ctx->state[3], output, 12 );
    PUT_ULONG_BE( ctx->state[4], output, 16 );
    PUT_ULONG_BE( ctx->state[5], output, 20 );
    PUT_ULONG_BE( ctx->state[6], output, 24 );
    PUT_ULONG_BE( ctx->state[7], output, 28 );
}

/*
 * output = SM3( input buffer )
 */
void sm3(unsigned char *input, int ilen,
           unsigned char output[32] )
{
    sm3_context ctx;

    sm3_starts( &ctx );
    sm3_update( &ctx, input, ilen );
    sm3_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );
}

/*
 * output = SM3( file contents )
 */
int sm3_file( char *path, unsigned char output[32] )
{
    FILE *f;
    unsigned int n;
    sm3_context ctx;
    unsigned char buf[1024];

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( 1 );

    sm3_starts( &ctx );

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
        sm3_update( &ctx, buf, (int) n );

    sm3_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );

    if( ferror( f ) != 0 )
    {
        fclose( f );
        return( 2 );
    }

    fclose( f );
    return( 0 );
}

/*
 * SM3 HMAC context setup
 */
void sm3_hmac_starts( sm3_context *ctx, unsigned char *key, int keylen )
{
    int i;
    unsigned char sum[32];

    if( keylen > 64 )
    {
        sm3(key, keylen, sum );
        keylen = 32;
        key = sum;
    }

    memset( ctx->ipad, 0x36, 64 );
    memset( ctx->opad, 0x5C, 64 );

    for( i = 0; i < keylen; i++ )
    {
        ctx->ipad[i] = (unsigned char)( ctx->ipad[i] ^ key[i] );
        ctx->opad[i] = (unsigned char)( ctx->opad[i] ^ key[i] );
    }

    sm3_starts( ctx);
    sm3_update( ctx, ctx->ipad, 64 );

    memset( sum, 0, sizeof( sum ) );
}

/*
 * SM3 HMAC process buffer
 */
void sm3_hmac_update( sm3_context *ctx, unsigned char *input, int ilen )
{
    sm3_update( ctx, input, ilen );
}

/*
 * SM3 HMAC final digest
 */
void sm3_hmac_finish( sm3_context *ctx, unsigned char output[32] )
{
    int hlen;
    unsigned char tmpbuf[32];

    //is224 = ctx->is224;
    hlen =  32;

    sm3_finish( ctx, tmpbuf );
    sm3_starts( ctx );
    sm3_update( ctx, ctx->opad, 64 );
    sm3_update( ctx, tmpbuf, hlen );
    sm3_finish( ctx, output );

    memset( tmpbuf, 0, sizeof( tmpbuf ) );
}

/*
 * output = HMAC-SM#( hmac key, input buffer )
 */
void sm3_hmac( unsigned char *key, int keylen,
                unsigned char *input, int ilen,
                unsigned char output[32] )
{
    sm3_context ctx;

    sm3_hmac_starts( &ctx, key, keylen);
    sm3_hmac_update( &ctx, input, ilen );
    sm3_hmac_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );
}

#ifndef min
#define mk_min( a, b ) ( ((a) < (b)) ? (a) : (b) )
#endif

int x9_63_kdf_sm3(const unsigned char *share, unsigned int sharelen, unsigned char *outkey, unsigned int keylen)
{
    int ret = 0;

    sm3_context ctx;
    unsigned int new_counter = 1;
    unsigned char new_counter_be_[4] = {0, 0, 0, 1};
    unsigned char dgst[32];
    unsigned int dgstlen = 32;
    int rlen = (int)keylen;
    unsigned char *pp;

    if ((NULL == outkey) || (0 == keylen))
    {
        printf("invalid parameter, null\n");
        return ret;
    }

    pp = outkey;
    while (rlen > 0)
    {
        new_counter_be_[0] = (unsigned char)((new_counter >> 24) & 0xFF);
        new_counter_be_[1] = (unsigned char)((new_counter >> 16) & 0xFF);
        new_counter_be_[2] = (unsigned char)((new_counter >> 8) & 0xFF);
        new_counter_be_[3] = (unsigned char)(new_counter & 0xFF);

        sm3_starts(&ctx);
        sm3_update(&ctx, (unsigned char *)share, sharelen);
        sm3_update(&ctx, new_counter_be_, 4);
        sm3_finish(&ctx, dgst);

        if (keylen > dgstlen)
        {
            memcpy(pp, dgst, dgstlen);
            pp += dgstlen;
            keylen -= dgstlen;
        }
        else
        {
            memcpy(pp, dgst, keylen);
            memset(dgst, 0, dgstlen);
            break;
        }
        new_counter++;
    }

    ret = 1;

end:
    return ret;
}

