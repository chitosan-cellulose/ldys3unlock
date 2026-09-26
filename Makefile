ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:14.0
THEOS_PACKAGE_SCHEME = roothide
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ldys3unlock

ldys3unlock_FILES = Tweak.xm
ldys3unlock_CFLAGS = -fobjc-arc
ldys3unlock_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tweak.mk

# 附带两份注入过滤：SpringBoard 端 + ldysdaemon 端
after-install::
	install.exec "killall -9 SpringBoard; killall -9 ldysdaemon || true"
