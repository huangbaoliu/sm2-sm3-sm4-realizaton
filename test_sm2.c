#include <stdio.h>
#include "sm2.h"

void tohex(const uint8_t *source, uint8_t *result, int len)
{
    uint8_t h1,h2; 
    uint8_t s1,s2;
    int i;
    for (i=0; i<len; i++)
    {
        h1 = source[2*i];
        h2 = source[2*i+1];
        s1 = toupper(h1) - '0';
        if (s1 > 9) 
            s1 = s1 - ('A' - ':');
        s2 = toupper(h2) - '0';
        if (s2 > 9) 
            s2 = s2 - ('A' - ':');
        
        result[i] = s1*16 + s2; 
    }
}

void test_sm2_verify()
{
    int i = 0;
    EccSig sig;

    EccPoint p_publicKey = {\
    {0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6, 0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20}, \
    {0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60, 0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13}};

    uint8_t id_buf[128];
    uint8_t msg_buf[NUM_ECC_DIGITS];

    uint8_t pukx_str[] = "27AE9564D854B5585BF1662225B9AF566A3877F389AB64B085D52ABE02D98859";
    uint8_t puky_str[] = "3912F8185ED47FC41574FB6BDB5EE118643CA11FCF655E3336B3E6C36A8F1645";
    uint8_t id_str[] = "C8A427891024E0F839875DC5435C4A20CA5BC75A8CE30B3B26A74D0E1EA4E4E0";
    
    uint8_t msg_str[] = "2656AD299F2BADE95D38F7F7AA2AD096";
    int msg_len = 0x10;

    uint8_t r_str[] = "D95A7B97A779DBFA5EA3426482C5DDDDD331C85122AEE8329813A3BBFE51AC93";
    uint8_t s_str[] = "25AFEE39CDF951F9CBAAB98899799375A84DB02BB0BF7C99680579EE7C8406C6";

    tohex(pukx_str, p_publicKey.x, NUM_ECC_DIGITS);
    tohex(puky_str, p_publicKey.y, NUM_ECC_DIGITS);

    tohex(id_str, id_buf, NUM_ECC_DIGITS);
    id_buf[NUM_ECC_DIGITS] = '\0';
    tohex(msg_str, msg_buf, msg_len);
    tohex(r_str, sig.r, NUM_ECC_DIGITS);
    tohex(s_str, sig.s, NUM_ECC_DIGITS);

    printf("r:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", sig.r[i]);
    }

    printf("\ns:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", sig.s[i]);
    }
    printf("\n");

    printf("result:%d\n\n", sm2_verify(&sig, msg_buf, msg_len, id_buf, NUM_ECC_DIGITS, &p_publicKey));
}


int test_sm2_sign_verify() 
{
    int i = 0;
    EccSig sig;

    uint8_t *IDa = "1234567812345678";
    uint8_t in[] = "message digest";
    uint8_t p_random[NUM_ECC_DIGITS] = {0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0, 0x2d, 0xcc, 0xef, 0x3c, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE, 0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21};
    EccPoint p_publicKey = {\
    {0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6, 0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20}, \
    {0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60, 0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13}};
    uint8_t p_privateKey[NUM_ECC_DIGITS] = {0X39, 0X45, 0X20, 0X8F, 0X7B, 0X21, 0X44, 0XB1, 0X3F, 0X36, 0XE3, 0X8A, 0XC6, 0XD3, 0X9F, 0X95, 0X88, 0X93, 0X93, 0X69, 0X28, 0X60, 0XB5, 0X1A, 0X42, 0XFB, 0X81, 0XEF, 0X4D, 0XF7, 0XC5, 0XB8};

    uint8_t id_buf[128];
    uint8_t msg_buf[NUM_ECC_DIGITS];
    int msg_len = 0x10;

    uint8_t pukx_str[] = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020";
    uint8_t puky_str[] = "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";
    uint8_t pvk_str[] = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    uint8_t rnd_str[] = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21";

    tohex(rnd_str, p_random, NUM_ECC_DIGITS);
    tohex(pvk_str, p_privateKey, NUM_ECC_DIGITS);
    tohex(pukx_str, p_publicKey.x, NUM_ECC_DIGITS);
    tohex(puky_str, p_publicKey.y, NUM_ECC_DIGITS);

    sm2_sign(&sig, in, strlen(in), IDa, strlen(IDa), p_privateKey, p_random);

    printf("\nr:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", sig.r[i]);
    }

    printf("\ns:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", sig.s[i]);
    }
    printf("\n");

    printf("result:%d\n\n", sm2_verify(&sig, in, strlen(in), IDa, strlen(IDa), &p_publicKey));
}

void test_ecdsa_sign_verify()
{
    int i = 0;
	uint8_t p_random[NUM_ECC_DIGITS] = {0x6F, 0xF9, 0xB2, 0x1F, 0xAE, 0xBA, 0x0D, 0x26, 0x27, 0xB7, 0x72, 0xDD, 0x25, 0xD9, 0x76, 0xC1, 0x3F, 0x66, 0x17, 0x48, 0x93, 0x4E, 0xF9, 0x94, 0x5C, 0x17, 0x5C, 0x38, 0x99, 0x8D, 0xB2, 0x6C};

    uint8_t p_privateKey[NUM_ECC_DIGITS] = {0xAD, 0x0E, 0x7F, 0xDF, 0x64, 0xFF, 0x25, 0xAE, 0x83, 0x6E, 0x0F, 0x79, 0xA6, 0x93, 0x21, 0xC8, 0xD0, 0x59, 0x86, 0x12, 0x28, 0xC3, 0xF7, 0x83, 0x13, 0x7A, 0x2A, 0xD7, 0xCF, 0xBA, 0x4D, 0x08};

    EccPoint p_publicKey = { \
    {0xDF, 0x09, 0x69, 0x21, 0x84, 0xE7, 0xC7, 0xEA, 0x5E, 0x91, 0x2C, 0x4C, 0xE2, 0xFF, 0x22, 0x89, 0xEC, 0x3D, 0x2F, 0xA3, 0xAB, 0xC7, 0xA8, 0x21, 0x9F, 0xE3, 0x17, 0x6F, 0xE4, 0x4F, 0xB2, 0xE3},
    {0x27, 0xA7, 0x8D, 0xC1, 0xFB, 0x3D, 0x1C, 0x0C, 0xB0, 0xAC, 0x23, 0xDE, 0x65, 0xB1, 0xDF, 0x1C, 0xF6, 0x75, 0xD2, 0x1F, 0x4C, 0x10, 0xDE, 0x21, 0x3C, 0xCB, 0x68, 0x36, 0xFE, 0x6A, 0x2D, 0xEE}};

    uint8_t r[NUM_ECC_DIGITS];
    uint8_t s[NUM_ECC_DIGITS];

    uint8_t p_hash[NUM_ECC_DIGITS] = {0x95, 0x8E, 0x72, 0xE6, 0x3C, 0x1B, 0x65, 0xD3, 0x25, 0xAC, 0xF7, 0xF6, 0x50, 0xAF, 0xBA, 0x75, 0x32, 0x5E, 0x22, 0x47, 0x58, 0xB0, 0x7C, 0x10, 0x66, 0xBB, 0xC1, 0x5A, 0xC5, 0x46, 0x89, 0xED};

    ecdsa_sign(r, s, p_privateKey, p_random, p_hash);
    printf("r:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", r[i]);
    }

    printf("\ns:");
    for (i = 0; i<NUM_ECC_DIGITS; i++)
    {
        printf("%02X", s[i]);
    }
    printf("\n");
    printf("result:%d\n\n", ecdsa_verify(&p_publicKey, p_hash, r, s));
}

void test_sm2_decrypt()
{
    int ret = 0;
    int i = 0;
    uint8_t tmp = 0;
    uint8_t plain_text[NUM_ECC_DIGITS];
    int plain_len;
    uint8_t cipher[1024];
    int cipher_len = 0;

    uint8_t p_privateKey[NUM_ECC_DIGITS] = {0X39, 0X45, 0X20, 0X8F, 0X7B, 0X21, 0X44, 0XB1, 0X3F, 0X36, 0XE3, 0X8A, 0XC6, 0XD3, 0X9F, 0X95, 0X88, 0X93, 0X93, 0X69, 0X28, 0X60, 0XB5, 0X1A, 0X42, 0XFB, 0X81, 0XEF, 0X4D, 0XF7, 0XC5, 0XB8};

    uint8_t pvk_str[] = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    uint8_t x1_str[] = "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73";
    uint8_t y1_str[] = "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0";
    uint8_t C3_str[] = "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766";
    uint8_t C2_str[] = "21886CA989CA9C7D58087307CA93092D651EFA";

    cipher[0] = 0X04;
    tohex(pvk_str, p_privateKey, NUM_ECC_DIGITS);
    tohex(x1_str, cipher + 1, NUM_ECC_DIGITS);
    tohex(y1_str, cipher + 33, NUM_ECC_DIGITS);
    tohex(C3_str, cipher + 65, NUM_ECC_DIGITS);
    cipher_len = sizeof(C2_str)/2;
    tohex(C2_str, cipher + 97, cipher_len);
    cipher_len += 97;

    //plain_text[cipher.L] = '\0';
    //memset(plain_text, '\0', sizeof(plain_text));
    ret = sm2_decrypt(plain_text, &plain_len, &cipher, cipher_len, p_privateKey);

    printf("sm2_decrypt result:%d\n", ret);
    printf("plaintext is:%s\n", plain_text);
    for (i = 0; i<plain_len; i++)
    {
        printf("%02X", plain_text[i]);
    }
    printf("\n");
}

void test_sm2_encrypt_decrypt()
{
    int i = 0;
    int ret = 0;
    uint8_t encdata[1024];
    unsigned int encdata_len = 1024;
    EccPoint p_publicKey;
    uint8_t p_privateKey[NUM_ECC_DIGITS];
    uint8_t p_random[NUM_ECC_DIGITS];
    uint8_t *plain_text = "encryption standard";
    unsigned int plain_len = strlen(plain_text);

    uint8_t p_out[NUM_ECC_DIGITS];
    int p_out_len = 0;

    uint8_t pvk_str[] = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    uint8_t pukx_str[] = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020";
    uint8_t puky_str[] = "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";
    uint8_t rnd_str[] = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21";

    tohex(pukx_str, p_publicKey.x, NUM_ECC_DIGITS);
    tohex(puky_str, p_publicKey.y, NUM_ECC_DIGITS);

    tohex(rnd_str, p_random, NUM_ECC_DIGITS);

    ret = sm2_encrypt(encdata, &encdata_len, &p_publicKey, p_random, plain_text, plain_len);
    printf("sm2_encrypt result:%d\n", ret);

    printf("enc result:");
    for (i=0; i < encdata_len; i++)
    {
        printf("%02X", encdata[i]);
        if (1 == (i + 1)%32)
            printf("\n");
    }
    printf("\n");

    tohex(pvk_str, p_privateKey, NUM_ECC_DIGITS);
    ret = sm2_decrypt(p_out, &p_out_len, &encdata, encdata_len, p_privateKey);
    printf("sm2_decrypt result:%d\n", ret);

    printf("plaintext is:%s\n", p_out);
}

int main(int argc, char *argv[])
{
    int index = 0;
    if (argc < 2)
    {
        printf("usage: %s index\n", argv[0]);
        printf("\t1:test sm2 verify\n");
        printf("\t2:sm2 sign & verify test\n");
        printf("\t3:ecdsa sign & verify test\n");
        printf("\t4:sm2 decrypt test\n");
        printf("\t5:sm2 encrypt test\n");
    }
    else
    {
        index = atoi(argv[1]);
        switch(index)
        {
            case 1:
                test_sm2_verify();
                break;
            case 2:
                test_sm2_sign_verify();
                break;
            case 3:
                test_ecdsa_sign_verify();
                break;
            case 4:
                test_sm2_decrypt();
                break;
            case 5:
                test_sm2_encrypt_decrypt();
                break;
            default:
                printf("parameter 1 value:%s error\n", argv[1]);
                break;
        }
    }
    return 0;
}

