TARGET := iphone:clang:latest:7.0
INSTALL_TARGET_PROCESSES = Podcasts


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = PodcastsX

MBEDTLS_DIR = $(PWD)/../vendor/mbedtls-armv7

PodcastsX_FILES = Tweak/Tweak.x Relay/TLSRelay.m
PodcastsX_CFLAGS = -fobjc-arc -I$(MBEDTLS_DIR)/include
PodcastsX_LDFLAGS = -framework Security -framework CFNetwork \
                   -L$(MBEDTLS_DIR)/lib -lmbedtls -lmbedx509 -lmbedcrypto

include $(THEOS_MAKE_PATH)/tweak.mk
