#import "FaceStore.h"
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>

static NSData *_aesEncrypt(NSData *data, NSData *key, NSData *iv) {
    size_t outLen = data.length + kCCBlockSizeAES128;
    void *buf = malloc(outLen);
    size_t moved = 0;
    CCCryptorStatus s = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
        key.bytes, kCCKeySizeAES256, iv.bytes,
        data.bytes, data.length, buf, outLen, &moved);
    if (s != kCCSuccess) { free(buf); return nil; }
    return [NSData dataWithBytesNoCopy:buf length:moved freeWhenDone:YES];
}

static NSData *_aesDecrypt(NSData *data, NSData *key, NSData *iv) {
    size_t outLen = data.length + kCCBlockSizeAES128;
    void *buf = malloc(outLen);
    size_t moved = 0;
    CCCryptorStatus s = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
        key.bytes, kCCKeySizeAES256, iv.bytes,
        data.bytes, data.length, buf, outLen, &moved);
    if (s != kCCSuccess) { free(buf); return nil; }
    return [NSData dataWithBytesNoCopy:buf length:moved freeWhenDone:YES];
}

@interface FaceStore ()
@property (nonatomic, strong, nullable) NSData *cachedKey;
@end

@implementation FaceStore

+ (instancetype)shared {
    static FaceStore *inst;
    static dispatch_once_t t;
    dispatch_once(&t, ^{ inst = [self new]; });
    return inst;
}

- (instancetype)init {
    if (!(self = [super init])) return nil;
    [[NSFileManager defaultManager]
        createDirectoryAtPath:FACESTORE_DIR
  withIntermediateDirectories:YES attributes:nil error:nil];
    return self;
}

- (NSData *)_key {
    if (self.cachedKey) return self.cachedKey;
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:FACESTORE_KEY]) {
        self.cachedKey = [NSData dataWithContentsOfFile:FACESTORE_KEY];
        return self.cachedKey;
    }
    uint8_t kb[kCCKeySizeAES256];
    (void)SecRandomCopyBytes(kSecRandomDefault, sizeof(kb), kb);
    NSData *key = [NSData dataWithBytes:kb length:sizeof(kb)];
    [key writeToFile:FACESTORE_KEY atomically:YES];
    [fm setAttributes:@{NSFilePosixPermissions: @(0600)} ofItemAtPath:FACESTORE_KEY error:nil];
    self.cachedKey = key;
    return key;
}

- (NSData *)_randomIV {
    uint8_t iv[kCCBlockSizeAES128];
    (void)SecRandomCopyBytes(kSecRandomDefault, sizeof(iv), iv);
    return [NSData dataWithBytes:iv length:sizeof(iv)];
}

- (BOOL)saveFaceData:(NSData *)data {
    NSData *iv  = [self _randomIV];
    NSData *enc = _aesEncrypt(data, [self _key], iv);
    if (!enc) return NO;
    NSMutableData *blob = [NSMutableData dataWithData:iv];
    [blob appendData:enc];
    BOOL ok = [blob writeToFile:FACESTORE_DATA atomically:YES];
    [[NSFileManager defaultManager]
        setAttributes:@{NSFilePosixPermissions: @(0600)}
         ofItemAtPath:FACESTORE_DATA error:nil];
    NSLog(@"[FakeFaceID] FaceStore saved %lu bytes (encrypted)", (unsigned long)data.length);
    return ok;
}

- (nullable NSData *)loadFaceData {
    NSData *blob = [NSData dataWithContentsOfFile:FACESTORE_DATA];
    if (blob.length <= kCCBlockSizeAES128) return nil;
    NSData *iv  = [blob subdataWithRange:NSMakeRange(0, kCCBlockSizeAES128)];
    NSData *ct  = [blob subdataWithRange:NSMakeRange(kCCBlockSizeAES128, blob.length - kCCBlockSizeAES128)];
    return _aesDecrypt(ct, [self _key], iv);
}

- (BOOL)hasFace {
    return [[NSFileManager defaultManager] fileExistsAtPath:FACESTORE_DATA];
}

- (void)clear {
    [[NSFileManager defaultManager] removeItemAtPath:FACESTORE_DATA error:nil];
    [[NSFileManager defaultManager] removeItemAtPath:FACESTORE_KEY error:nil];
    self.cachedKey = nil;
    NSLog(@"[FakeFaceID] FaceStore cleared");
}

@end
