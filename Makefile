THEOS_DEVICE_IP = localhost
THEOS_DEVICE_PORT = 2222

TARGET := iphone:clang:16.5:15.0
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FakeFaceID
FakeFaceID_FILES = FakeFaceID/Tweak.x FakeFaceID/FaceStore.m
FakeFaceID_CFLAGS = -fobjc-arc -IFakeFaceID
FakeFaceID_FRAMEWORKS = UIKit Foundation Security
FakeFaceID_PRIVATE_FRAMEWORKS = LocalAuthentication
FakeFaceID_LIBRARIES = system

include $(THEOS)/makefiles/tweak.mk
