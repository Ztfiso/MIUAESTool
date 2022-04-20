

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>

NS_ASSUME_NONNULL_BEGIN

typedef enum : NSUInteger {
    MIUCryptorNoPadding = 0,    // 无填充
    MIUCryptorPKCS7Padding = 1, // PKCS_7 | 每个字节填充字节序列的长度。 ***此填充模式使用系统方法。***
    MIUCryptorZeroPadding = 2,  // 0x00 填充 | 每个字节填充 0x00
    MIUCryptorANSIX923,         // 最后一个字节填充字节序列的长度，其余字节填充0x00。
    MIUCryptorISO10126          // 最后一个字节填充字节序列的长度，其余字节填充随机数据。
}MIUCryptorPadding;

typedef enum {
    MIUKeySizeAES128          = 16,
    MIUKeySizeAES192          = 24,
    MIUKeySizeAES256          = 32,
}MIUKeySizeAES;

typedef enum {
    MIUModeECB        = 1,
    MIUModeCBC        = 2,
    MIUModeCFB        = 3,
    MIUModeOFB        = 7,
}MIUMode;

@interface MIUAES : NSObject

+ (NSString *)MIUAESEncrypt:(NSString *)originalStr
                      mode:(MIUMode)mode
                       key:(NSString *)key
                   keySize:(MIUKeySizeAES)keySize
                        iv:(NSString * _Nullable )iv
                   padding:(MIUCryptorPadding)padding;

+ (NSString *)MIUAESDecrypt:(NSString *)originalStr
                      mode:(MIUMode)mode
                       key:(NSString *)key
                   keySize:(MIUKeySizeAES)keySize
                        iv:(NSString * _Nullable )iv
                   padding:(MIUCryptorPadding)padding;

@end

NS_ASSUME_NONNULL_END
