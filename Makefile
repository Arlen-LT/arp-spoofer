#
# Copyright (C) 2024 Arlen LT
#
# Licensed under the GPL-2.0
#

include $(TOPDIR)/rules.mk

PKG_NAME:=arp-spoofer
PKG_RELEASE:=1

PKG_BUILD_DEPENDS:=libpcap
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

PKG_LICENSE:=GPL-2.0
PKG_MAINTAINER:=Arlen <arlen-lt@protonmail.com>

include $(INCLUDE_DIR)/package.mk

define Package/arp-spoofer
  SECTION:=net
  CATEGORY:=Utilities
  TITLE:=Simple ARP Spoofer
  DEPENDS:=+libpcap
endef

define Package/arp-spoofer/description
  A minimal ARP spoofing utility based on libpcap
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) \
		-o $(PKG_BUILD_DIR)/arp-spoofer \
		$(PKG_BUILD_DIR)/arp_spoofer.c \
		-lpcap
endef

define Package/arp-spoofer/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/arp-spoofer $(1)/usr/bin/
endef

$(eval $(call BuildPackage,arp-spoofer))
