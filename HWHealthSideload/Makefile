TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = HuaweiWear
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HWHealthSideload

HWHealthSideload_FILES = Tweak.xm fishhook.c
HWHealthSideload_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
HWHealthSideload_FRAMEWORKS = UIKit Foundation Security

include $(THEOS_MAKE_PATH)/tweak.mk
