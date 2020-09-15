sm2-sm3-sm4-realizaton
========

这是一个纯软c实现的SM2、SM3、SM4函数库，未使用openssl等第三方库，目前仅支持256位SM2。代码基于nano-sm2实现（8位处理器上的ecc实现，详情见https://github.com/Aries-orz/nano-sm2）。

Changes
--------

本代码主要在以下几方面对nano-sm2进行了改动：

 * 字节顺序按照x86 linux系统的小端模式；

 * 签名过程 - sm2_sign本代码完全按照SM2签名过程实现；

 * 验签过程 - sm2_verify本代码完全按照SM2验签过程实现；
 
 * 加密过程 - sm2_encrypt本代码完全按照SM2加密过程实现；

 * 解密过程 - sm2_decrypt本代码完全按照SM2解密过程实现；

 * 提供了sm3、sm4相关的接口函数；

Usage Notes
-----------

使用时只需将sm2.h、sm2.c、sm3.h、sm3.c加入自己的项目工程中，然后再include头文件sm2.h即可。test_sm2.c为测试算法的样例。

Parameters
-----------

另附本代码使用的SM2官方推荐参数（256位）：  
椭圆曲线方程：y^2 = x^3 + ax + b  
曲线参数：  
p=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF  
a=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC  
b=28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93  
n=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123  
Gx=32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7  
Gy=BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0  
