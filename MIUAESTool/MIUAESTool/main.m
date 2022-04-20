

#import <Foundation/Foundation.h>
#import "MIUAES.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *originalStr = @"123";
        NSString *encryptKey = @"0123456789ABCDEF";
        NSString *iv = @"0123456789ABCDEF";
        
        NSString *enStr = [MIUAES MIUAESEncrypt:originalStr mode:kCCModeCBC key:encryptKey keySize:MIUKeySizeAES128 iv:iv padding:MIUCryptorPKCS7Padding];
        NSString *deStr = [MIUAES MIUAESDecrypt:enStr mode:kCCModeCBC key:encryptKey keySize:MIUKeySizeAES128 iv:iv padding:MIUCryptorPKCS7Padding];
        
        NSLog(@"\n加密前：%@\n加密后：%@\n解密后：%@\n",originalStr,enStr,deStr);
    }
    return 0;
}
