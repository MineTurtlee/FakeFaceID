#pragma once
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#define FACESTORE_DIR   @"/var/jb/var/mobile/Library/FakeFaceID"
#define FACESTORE_DATA  @"/var/jb/var/mobile/Library/FakeFaceID/face.bin"
#define FACESTORE_KEY   @"/var/jb/var/mobile/Library/FakeFaceID/key.bin"

/// Handles AES-256-CBC encrypted storage of raw face template data
@interface FaceStore : NSObject

+ (instancetype)shared;

/// Save raw face template data (from Pearl) encrypted to disk
- (BOOL)saveFaceData:(NSData *)data;

/// Load and decrypt saved face template data
- (nullable NSData *)loadFaceData;

/// Whether a face template is saved
- (BOOL)hasFace;

/// Wipe all stored data
- (void)clear;

@end

NS_ASSUME_NONNULL_END
