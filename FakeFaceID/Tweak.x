#import <substrate.h>
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import "FaceStore.h"

// ================================================================
// FakeFaceID v2.0
//
// FACE ID:
//   Let Pearl do the real face scan UI. Hook completeWithError:
//   to save face template before SEP gets it. On match attempts,
//   fire biometric event 3 (matched) directly.
//
// PASSCODE:
//   Hook SBFMobileKeyBag + MCProfileConnection to intercept
//   passcode verification and substitute our own SHA256 hash
//   comparison. Completely bypasses SEP.
//
// SETTINGS:
//   Rename all biometric/passcode cells to show (FakeFaceID)
//   so users know SEP is not involved.
//
// Verified via Frida on iOS 16.7.10 iPhone X (A11)
// ================================================================

// ----------------------------------------------------------------
// Passcode storage helpers
// ----------------------------------------------------------------
#define FFI_PREF_PATH @"/var/jb/var/mobile/Library/FakeFaceID/passcode.plist"

static NSString *_sha256(NSString *input) {
    const char *str = [input UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(str, (CC_LONG)strlen(str), result);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hex appendFormat:@"%02x", result[i]];
    return hex;
}

static NSString *_savedHash(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:FFI_PREF_PATH];
    return d[@"passcodeHash"];
}

static void _savePasscode(NSString *passcode) {
    NSDictionary *d = @{
        @"passcodeHash": _sha256(passcode),
        @"passcodeType": @4
    };
    [d writeToFile:FFI_PREF_PATH atomically:YES];
    [[NSFileManager defaultManager]
        setAttributes:@{NSFilePosixPermissions: @(0600)}
         ofItemAtPath:FFI_PREF_PATH error:nil];
    NSLog(@"[FakeFaceID] Passcode saved");
}

static BOOL _hasPasscode(void) {
    return _savedHash() != nil;
}

static BOOL _checkPasscode(NSString *passcode) {
    NSString *saved = _savedHash();
    if (!saved || !passcode) return NO;
    return [_sha256(passcode) isEqualToString:saved];
}

// ----------------------------------------------------------------
// Forward declarations (verified via Frida)
// ----------------------------------------------------------------

@interface BKEnrollPearlProgressInfo : NSObject
- (float)percentageCompleted;
@end

@interface BKEnrollPearlOperation : NSObject
- (BOOL)completeWithError:(NSError **)error;
- (id)enrollResultInfoWithServerIdentity:(id)identity details:(id)details;
- (void)enrollUpdate:(BKEnrollPearlProgressInfo *)progress client:(id)client;
@end

@interface BKMatchPearlOperation : NSObject
- (BOOL)startNewMatchAttemptWithError:(NSError **)error;
- (id)matchResultInfoWithServerIdentity:(id)identity details:(id)details;
@end

@interface BKDevicePearl : NSObject
+ (instancetype)deviceAvailableWithFailure:(NSError **)error;
- (NSInteger)pearlState;
@end

@interface LAContext : NSObject
- (BOOL)canEvaluatePolicy:(NSInteger)policy error:(NSError **)error;
- (void)evaluatePolicy:(NSInteger)policy
       localizedReason:(NSString *)localizedReason
                 reply:(void (^)(BOOL success, NSError *error))reply;
- (NSInteger)biometryType;
@end

@interface SBFMobileKeyBag : NSObject
- (BOOL)unlockWithPasscode:(NSString *)passcode error:(NSError **)error;
- (BOOL)unlockWithOptions:(NSDictionary *)options error:(NSError **)error;
@end

@interface MCPasscodeManager : NSObject
+ (instancetype)sharedManager;
- (BOOL)isPasscodeSet;
- (NSInteger)passcodeType;
@end

@interface MCProfileConnection : NSObject
+ (instancetype)sharedConnection;
- (BOOL)unlockDeviceWithPasscode:(NSString *)passcode outError:(NSError **)error;
- (BOOL)changePasscodeFrom:(NSString *)old to:(NSString *)newPass outError:(NSError **)error;
- (id)effectiveValueForSetting:(NSString *)setting;
@end

@interface PSSpecifier : NSObject
- (void)setProperty:(id)property forKey:(NSString *)key;
- (id)propertyForKey:(NSString *)key;
@end

@interface PSListController : UIViewController
- (NSArray *)specifiers;
@end

@interface PSUIBiometricController : PSListController
@end

// ================================================================
// SECTION 1: BKEnrollPearlOperation — Face ID enrollment
// ================================================================

%hook BKEnrollPearlOperation

- (BOOL)completeWithError:(NSError **)error {
    NSLog(@"[FakeFaceID] completeWithError: fired — saving face data");

    id resultInfo = [self enrollResultInfoWithServerIdentity:nil details:nil];
    NSData *faceData = nil;

    if (resultInfo) {
        @try {
            faceData = [NSKeyedArchiver archivedDataWithRootObject:resultInfo
                                             requiringSecureCoding:NO
                                                             error:nil];
        } @catch (NSException *e) {
            NSLog(@"[FakeFaceID] Serialization failed: %@", e);
        }
    }

    if (!faceData) {
        faceData = [@"ENROLLED" dataUsingEncoding:NSUTF8StringEncoding];
    }

    BOOL saved = [[FaceStore shared] saveFaceData:faceData];
    NSLog(@"[FakeFaceID] Face saved: %@", saved ? @"✓" : @"✗");

    return %orig;
}

- (void)enrollUpdate:(BKEnrollPearlProgressInfo *)progress client:(id)client {
    NSLog(@"[FakeFaceID] Enrollment: %.1f%%", progress.percentageCompleted * 100);
    %orig;
}

%end

// ================================================================
// SECTION 2: BKMatchPearlOperation — Face ID authentication
// ================================================================

%hook BKMatchPearlOperation

- (BOOL)startNewMatchAttemptWithError:(NSError **)error {
    if (![[FaceStore shared] hasFace]) return %orig;

    NSLog(@"[FakeFaceID] Match attempt — firing matched event");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        id monitor = [NSClassFromString(@"SBUIBiometricEventMonitor")
                        performSelector:@selector(sharedInstance)];
        if (monitor)
            [monitor performSelector:@selector(_handleBiometricEvent:) withObject:@(3)];
    });

    if (error) *error = nil;
    return YES;
}

- (id)matchResultInfoWithServerIdentity:(id)identity details:(id)details {
    if (![[FaceStore shared] hasFace]) return %orig;
    return %orig(nil, details);
}

%end

// ================================================================
// SECTION 3: BKDevicePearl — fake hardware availability
// ================================================================

%hook BKDevicePearl

+ (instancetype)deviceAvailableWithFailure:(NSError **)failure {
    if (failure) *failure = nil;
    id result = %orig;
    return result ?: [self new];
}

- (NSInteger)pearlState {
    return [[FaceStore shared] hasFace] ? 3 : 1;
}

%end

// ================================================================
// SECTION 4: LAContext — in-app Face ID prompts
// ================================================================

%hook LAContext

- (NSInteger)biometryType {
    return 2; // LABiometryTypeFaceID
}

- (BOOL)canEvaluatePolicy:(NSInteger)policy error:(NSError **)error {
    if (error) *error = nil;
    return [[FaceStore shared] hasFace];
}

- (void)evaluatePolicy:(NSInteger)policy
       localizedReason:(NSString *)localizedReason
                 reply:(void (^)(BOOL success, NSError *error))reply {
    if (![[FaceStore shared] hasFace]) {
        NSError *e = [NSError errorWithDomain:@"com.apple.LocalAuthentication"
                                         code:-6
                                     userInfo:@{NSLocalizedDescriptionKey: @"Face ID not set up"}];
        dispatch_async(dispatch_get_main_queue(), ^{ reply(NO, e); });
        return;
    }
    dispatch_async(dispatch_get_main_queue(), ^{ reply(YES, nil); });
}

%end

// ================================================================
// SECTION 5: SBFMobileKeyBag — biometric + passcode unlock gate
// ================================================================

%hook SBFMobileKeyBag

- (BOOL)unlockWithOptions:(NSDictionary *)options error:(NSError **)error {
    if ((options[@"biometric"] || options[@"biometryType"]) &&
        [[FaceStore shared] hasFace]) {
        if (error) *error = nil;
        return YES;
    }
    return %orig;
}

- (BOOL)unlockWithPasscode:(NSString *)passcode error:(NSError **)error {
    if (!_hasPasscode()) return %orig;
    BOOL ok = _checkPasscode(passcode);
    NSLog(@"[FakeFaceID] Passcode: %@", ok ? @"✓" : @"✗");
    if (ok && error) *error = nil;
    return ok ?: %orig;
}

%end

// ================================================================
// SECTION 6: MCProfileConnection — passcode management
// Hooks verified from FakePass strings analysis
// ================================================================

%hook MCProfileConnection

- (BOOL)unlockDeviceWithPasscode:(NSString *)passcode outError:(NSError **)error {
    if (!_hasPasscode()) return %orig;
    BOOL ok = _checkPasscode(passcode);
    if (ok && error) *error = nil;
    return ok ?: %orig;
}

- (BOOL)changePasscodeFrom:(NSString *)old to:(NSString *)newPass outError:(NSError **)error {
    if (!_hasPasscode() || _checkPasscode(old)) {
        _savePasscode(newPass);
        if (error) *error = nil;
        return YES;
    }
    return %orig;
}

- (id)effectiveValueForSetting:(NSString *)setting {
    if ([setting isEqualToString:@"PasscodeIsSet"] && _hasPasscode())
        return @YES;
    return %orig;
}

%end

// ================================================================
// SECTION 7: MCPasscodeManager
// ================================================================

%hook MCPasscodeManager

- (BOOL)isPasscodeSet {
    return _hasPasscode() || [[FaceStore shared] hasFace];
}

- (NSInteger)passcodeType {
    return _hasPasscode() ? 4 : %orig;
}

%end

// ================================================================
// SECTION 8: Settings UI — rename cells
// IDs verified via Frida on iOS 16.7.10
// ================================================================

%hook PSUIBiometricController

- (NSArray *)specifiers {
    NSArray *orig = %orig;
    for (PSSpecifier *spec in orig) {
        NSString *sid = [spec propertyForKey:@"id"];
        if ([sid isEqualToString:@"PEARL_ENROLL"])
            [spec setProperty:@"Set up Face ID (FakeFaceID)" forKey:@"label"];
        else if ([sid isEqualToString:@"PASSCODE_OFF"])
            [spec setProperty:@"Turn Passcode On (FakeFaceID)" forKey:@"label"];
        else if ([sid isEqualToString:@"PASSCODE_ON"])
            [spec setProperty:@"Turn Passcode Off (FakeFaceID)" forKey:@"label"];
        else if ([sid isEqualToString:@"CHANGE_PASSCODE"])
            [spec setProperty:@"Change Passcode (FakeFaceID)" forKey:@"label"];
    }
    return orig;
}

%end

// ================================================================
// SECTION 9: Darwin notification listeners
// notifyutil -p com.mineturtlee.fakefaceid.clear     — wipe everything
// notifyutil -p com.mineturtlee.fakefaceid.status    — log state
// notifyutil -p com.mineturtlee.fakefaceid.testauth  — test unlock
// ================================================================

static void _ffi_onClear(CFNotificationCenterRef c, void *o, CFStringRef n, const void *obj, CFDictionaryRef u) {
    [[FaceStore shared] clear];
    [[NSFileManager defaultManager] removeItemAtPath:FFI_PREF_PATH error:nil];
    NSLog(@"[FakeFaceID] All data cleared");
}

static void _ffi_onStatus(CFNotificationCenterRef c, void *o, CFStringRef n, const void *obj, CFDictionaryRef u) {
    NSLog(@"[FakeFaceID] Face: %@ | Passcode: %@",
          [[FaceStore shared] hasFace] ? @"enrolled" : @"not enrolled",
          _hasPasscode() ? @"set" : @"not set");
}

static void _ffi_onTestAuth(CFNotificationCenterRef c, void *o, CFStringRef n, const void *obj, CFDictionaryRef u) {
    NSLog(@"[FakeFaceID] Test auth — firing matched event");
    id monitor = [NSClassFromString(@"SBUIBiometricEventMonitor")
                    performSelector:@selector(sharedInstance)];
    if (monitor)
        [monitor performSelector:@selector(_handleBiometricEvent:) withObject:@(3)];
}

%ctor {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    NSLog(@"[FakeFaceID] v2.0 injected into %@", bid);

    if (![bid isEqualToString:@"com.apple.springboard"]) return;

    CFNotificationCenterRef darwin = CFNotificationCenterGetDarwinNotifyCenter();
    CFNotificationCenterAddObserver(darwin, NULL, _ffi_onClear,
        CFSTR("com.mineturtlee.fakefaceid.clear"), NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(darwin, NULL, _ffi_onStatus,
        CFSTR("com.mineturtlee.fakefaceid.status"), NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(darwin, NULL, _ffi_onTestAuth,
        CFSTR("com.mineturtlee.fakefaceid.testauth"), NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately);
}

%hook NSBundle
- (NSString *)localizedStringForKey:(NSString *)key value:(NSString *)value table:(NSString *)tableName {
    NSString *ret = %orig;

    if ([self.bundleIdentifier isEqualToString:@"com.apple.preferences-ui-framework"]
            && [tableName isEqualToString:@"Passcode Lock"]
            && [key isEqualToString:@"PASSCODE_ON"]) {
        return [NSString stringWithFormat:@"%@ (FakePass)", ret];
    }

    return ret;
}
%end