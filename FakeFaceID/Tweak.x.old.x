#import <substrate.h>
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import "FaceStore.h"
#import <CommonCrypto/CommonDigest.h>

// ================================================================
// FakeFaceID v1.0 — Pearl-based approach
//
// Strategy:
//   ENROLLMENT: Let Pearl do the real face scan UI. Hook
//   completeWithError: to grab the face template data before
//   it reaches SEP. Save it ourselves via FaceStore (AES-256).
//
//   AUTHENTICATION: Hook matchResultInfoWithServerIdentity:details:
//   Intercept the match result and substitute our own verdict
//   based on whether a face was enrolled via FakeStore.
//
// Class names verified live via Frida on iOS 16.7.10 iPhone X:
//   BKEnrollPearlOperation  — drives enrollment
//   BKMatchPearlOperation   — drives matching
//   BKEnrollPearlResultInfo — enrollment result (would go to SEP)
//   BKMatchPearlResultInfo  — match result (would go to SEP)
//   BKDevicePearl           — hardware availability gate
// ================================================================

// ----------------------------------------------------------------
// Forward declarations (verified via Frida)
// ----------------------------------------------------------------

@interface BKEnrollPearlResultInfo : NSObject
- (instancetype)initWithServerIdentity:(id)identity details:(id)details device:(id)device;
- (BOOL)glassesDetected;
@end

@interface BKMatchPearlResultInfo : NSObject
- (instancetype)initWithServerIdentity:(id)identity details:(id)details device:(id)device;
- (NSInteger)feedback;
- (NSInteger)periocularMatchState;
@end

@interface BKEnrollPearlProgressInfo : NSObject
- (float)percentageCompleted;
- (NSArray *)enrolledPoses;
@end

@interface BKEnrollPearlOperation : NSObject
- (instancetype)initWithDevice:(id)device;
- (BOOL)startWithError:(NSError **)error;
- (BOOL)completeWithError:(NSError **)error;
- (BOOL)suspendWithError:(NSError **)error;
- (BOOL)resumeWithError:(NSError **)error;
- (id)enrollResultInfoWithServerIdentity:(id)identity details:(id)details;
- (id)clientToComplete;
- (NSInteger)enrollmentType;
- (void)enrollFeedback:(id)feedback client:(id)client;
- (void)enrollUpdate:(BKEnrollPearlProgressInfo *)progress client:(id)client;
@end

@interface BKMatchPearlOperation : NSObject
- (BOOL)startNewMatchAttemptWithError:(NSError **)error;
- (id)matchResultInfoWithServerIdentity:(id)identity details:(id)details;
- (BOOL)shouldAutoRetry;
- (void)setShouldAutoRetry:(BOOL)retry;
@end

@interface BKDevicePearl : NSObject
+ (instancetype)deviceAvailableWithFailure:(NSError **)error;
- (id)createEnrollOperationWithError:(NSError **)error;
- (id)createMatchOperationWithError:(NSError **)error;
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
- (BOOL)unlockWithOptions:(NSDictionary *)options error:(NSError **)error;
@end

@interface SBFUserAuthenticationController : NSObject
- (void)tryUserAuthenticationWithCompletion:(void (^)(BOOL success))completion;
@end

@interface SBUIBiometricEventMonitor : NSObject
+ (instancetype)sharedInstance;
- (void)_handleBiometricEvent:(unsigned int)event;
- (BOOL)isMatchingFaceID;
@end

@interface MCPasscodeManager : NSObject
+ (instancetype)sharedManager;
- (BOOL)isPasscodeSet;
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
// SECTION 1: BKEnrollPearlOperation
// Hook completeWithError: — called when user finishes face scan
// Grab the template data and save it ourselves before SEP gets it
// ================================================================

// Flag to track if we're in a FakeFaceID enrollment
static BOOL _enrolling = NO;

%hook BKEnrollPearlOperation

- (BOOL)completeWithError:(NSError **)error {
    NSLog(@"[FakeFaceID] BKEnrollPearlOperation completeWithError: called");

    // Get the result info which contains the face template
    // We pass nil for serverIdentity to get just the local template data
    id resultInfo = [self enrollResultInfoWithServerIdentity:nil details:nil];
    NSLog(@"[FakeFaceID] enrollResultInfo: %@", resultInfo);

    if (resultInfo) {
        // Serialize the result info to save it
        NSData *faceData = nil;
        @try {
            faceData = [NSKeyedArchiver archivedDataWithRootObject:resultInfo
                                             requiringSecureCoding:NO
                                                             error:nil];
        } @catch (NSException *e) {
            // Fallback: try NSCoding
            NSLog(@"[FakeFaceID] NSKeyedArchiver failed: %@", e);
        }

        if (faceData) {
            BOOL saved = [[FaceStore shared] saveFaceData:faceData];
            NSLog(@"[FakeFaceID] Face template saved: %@", saved ? @"✓" : @"✗");
        } else {
            // Last resort: save the description as a marker so we know enrollment happened
            NSData *marker = [@"ENROLLED" dataUsingEncoding:NSUTF8StringEncoding];
            [[FaceStore shared] saveFaceData:marker];
            NSLog(@"[FakeFaceID] Saved enrollment marker (couldn't serialize resultInfo)");
        }
    } else {
        // Even without result data, mark as enrolled
        NSData *marker = [@"ENROLLED" dataUsingEncoding:NSUTF8StringEncoding];
        [[FaceStore shared] saveFaceData:marker];
        NSLog(@"[FakeFaceID] No resultInfo, saved enrollment marker");
    }

    _enrolling = NO;

    // Call orig to let Pearl think enrollment completed normally
    return %orig;
}

- (void)enrollUpdate:(BKEnrollPearlProgressInfo *)progress client:(id)client {
    NSLog(@"[FakeFaceID] Enrollment progress: %.1f%%", progress.percentageCompleted * 100);
    %orig;
}

%end

// ================================================================
// SECTION 2: BKMatchPearlOperation
// Hook matchResultInfoWithServerIdentity:details:
// If we have a saved face → return a successful match result
// If not enrolled → let it fail normally
// ================================================================

%hook BKMatchPearlOperation

- (id)matchResultInfoWithServerIdentity:(id)identity details:(id)details {
    NSLog(@"[FakeFaceID] matchResultInfoWithServerIdentity called");

    if (![[FaceStore shared] hasFace]) {
        NSLog(@"[FakeFaceID] No face enrolled, passing through");
        return %orig;
    }

    // We have a saved face — return a successful match result
    // feedback = 0 means success in Pearl's result codes
    NSLog(@"[FakeFaceID] Face enrolled — spoofing successful match result");

    // Create result with nil identity (bypasses SEP verification)
    id result = %orig(nil, details);
    return result;
}

- (BOOL)startNewMatchAttemptWithError:(NSError **)error {
    NSLog(@"[FakeFaceID] startNewMatchAttemptWithError called");
    if (![[FaceStore shared] hasFace]) return %orig;

    // We have a face enrolled — fire the biometric matched event
    // directly into SpringBoard's event pipeline
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        NSLog(@"[FakeFaceID] Firing biometric matched event");
        id monitor = [NSClassFromString(@"SBUIBiometricEventMonitor")
                        performSelector:@selector(sharedInstance)];
        if (monitor) {
            [monitor performSelector:@selector(_handleBiometricEvent:)
                         withObject:@(3)]; // 3 = matched
        }
    });

    if (error) *error = nil;
    return YES;
}

%end

// ================================================================
// SECTION 3: BKDevicePearl — fake hardware availability
// ================================================================

%hook BKDevicePearl

+ (instancetype)deviceAvailableWithFailure:(NSError **)failure {
    if (failure) *failure = nil;
    // Call orig but ignore the failure — always return a device
    id result = %orig;
    return result ?: [self new];
}

- (NSInteger)pearlState {
    // 3 = enrolled and ready (based on Pearl state machine)
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
    // Face is enrolled — approve the auth
    NSLog(@"[FakeFaceID] LAContext evaluatePolicy — approving");
    dispatch_async(dispatch_get_main_queue(), ^{ reply(YES, nil); });
}

%end

// ================================================================
// SECTION 5: SBFMobileKeyBag — cryptographic unlock gate
// ================================================================

%hook SBFMobileKeyBag

- (BOOL)unlockWithOptions:(NSDictionary *)options error:(NSError **)error {
    if ((options[@"biometric"] || options[@"biometryType"]) &&
        [[FaceStore shared] hasFace]) {
        NSLog(@"[FakeFaceID] SBFMobileKeyBag biometric unlock — passing through");
        if (error) *error = nil;
        return YES;
    }
    return %orig;
}

%end

// ================================================================
// SECTION 6: MCPasscodeManager
// ================================================================

%hook MCPasscodeManager

- (BOOL)isPasscodeSet {
    return YES;
}

%end

// ================================================================
// SECTION 7: Settings UI — rename "Set up Face ID" cell
// ================================================================

%hook PSUIBiometricController

- (NSArray *)specifiers {
    NSArray *orig = %orig;
    for (PSSpecifier *spec in orig) {
        // Verified via Frida: "Set up Face ID" cell has id=PEARL_ENROLL
        NSString *specID = [spec propertyForKey:@"id"];
        if ([specID isEqualToString:@"PEARL_ENROLL"]) {
            [spec setProperty:@"Set up Face ID (FakeFaceID)" forKey:@"label"];
            [spec setProperty:@"Set up Face ID (FakeFaceID)" forKey:@"staticTextMessage"];
            NSLog(@"[FakeFaceID] Renamed PEARL_ENROLL cell → Set up Face ID (FakeFaceID)");
        }
    }
    return orig;
}

%end

// ================================================================
// SECTION 8: Darwin notification listeners
// notifyutil -p com.mineturtlee.fakefaceid.clear
// notifyutil -p com.mineturtlee.fakefaceid.status
// ================================================================

static void _ffi_onClear(CFNotificationCenterRef c, void *o, CFStringRef n, const void *obj, CFDictionaryRef u) {
    [[FaceStore shared] clear];
    NSLog(@"[FakeFaceID] Face data cleared via notification");
}

static void _ffi_onStatus(CFNotificationCenterRef c, void *o, CFStringRef n, const void *obj, CFDictionaryRef u) {
    NSLog(@"[FakeFaceID] Status: %@", [[FaceStore shared] hasFace] ? @"enrolled" : @"not enrolled");
}

%ctor {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    NSLog(@"[FakeFaceID] v1.0 injected into %@", bid);

    if (![bid isEqualToString:@"com.apple.springboard"]) return;

    CFNotificationCenterRef darwin = CFNotificationCenterGetDarwinNotifyCenter();
    CFNotificationCenterAddObserver(darwin, NULL, _ffi_onClear,
        CFSTR("com.mineturtlee.fakefaceid.clear"), NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(darwin, NULL, _ffi_onStatus,
        CFSTR("com.mineturtlee.fakefaceid.status"), NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately);
}

// ================================================================
// SECTION 9: Passcode support (replaces FakePass)
// Hooks verified from FakePass strings analysis
// ================================================================

// Store passcode hash in same dir as face data
#define FAKEPASS_PREF_PATH @"/var/jb/var/mobile/Library/Preferences/com.mineturtlee.fakefaceid.plist"

static NSString *_hashPasscode(NSString *passcode) {
    // Simple SHA256 hash of passcode
    const char *str = [passcode UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(str, (CC_LONG)strlen(str), result);
    NSMutableString *hash = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hash appendFormat:@"%02x", result[i]];
    return hash;
}

static NSString *_savedPasscodeHash(void) {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:FAKEPASS_PREF_PATH];
    return prefs[@"passcodeHash"];
}

static void _savePasscode(NSString *passcode) {
    NSString *hash = _hashPasscode(passcode);
    NSDictionary *prefs = @{@"passcodeHash": hash, @"passcodeType": @4};
    [prefs writeToFile:FAKEPASS_PREF_PATH atomically:YES];
    NSLog(@"[FakeFaceID] Passcode saved");
}

// Hook SBFMobileKeyBag unlockWithPasscode — the real gate
%hook SBFMobileKeyBag

- (BOOL)unlockWithPasscode:(NSString *)passcode error:(NSError **)error {
    NSString *saved = _savedPasscodeHash();
    if (!saved) return %orig;
    BOOL match = [_hashPasscode(passcode) isEqualToString:saved];
    NSLog(@"[FakeFaceID] Passcode attempt: %@", match ? @"✓" : @"✗");
    if (match && error) *error = nil;
    return match ?: %orig;
}

%end

// Hook MCProfileConnection unlockDeviceWithPasscode — Settings auth chain
%hook MCProfileConnection

- (BOOL)unlockDeviceWithPasscode:(NSString *)passcode outError:(NSError **)error {
    NSString *saved = _savedPasscodeHash();
    if (!saved) return %orig;
    BOOL match = [_hashPasscode(passcode) isEqualToString:saved];
    if (match && error) *error = nil;
    return match ?: %orig;
}

// Hook changePasscodeFrom:to: — intercept when user sets a new passcode
- (BOOL)changePasscodeFrom:(NSString *)old to:(NSString *)new outError:(NSError **)error {
    NSString *saved = _savedPasscodeHash();
    // Allow if no passcode set yet, or if old passcode matches
    if (!saved || [_hashPasscode(old) isEqualToString:saved]) {
        _savePasscode(new);
        if (error) *error = nil;
        return YES;
    }
    return %orig;
}

%end

// MCPasscodeManager — report passcode as set if we have one saved
// (overrides the existing hook above)