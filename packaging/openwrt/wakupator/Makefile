include $(TOPDIR)/rules.mk

PKG_NAME:=wakupator
PKG_VERSION:=$(if $(WAKUPATOR_VERSION),$(WAKUPATOR_VERSION),0.0.0)
PKG_RELEASE:=1
PKG_BUILD_PARALLEL:=1

WAKUPATOR_SRC ?= $(CURDIR)/../../..

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_OPTIONS += -DWAKUPATOR_BUILD_TESTS=OFF -DWAKUPATOR_VERSION=$(PKG_VERSION)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(WAKUPATOR_SRC)/. $(PKG_BUILD_DIR)/
	rm -rf $(PKG_BUILD_DIR)/.git $(PKG_BUILD_DIR)/build*
endef

define Package/wakupator
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Wakupator
  DEPENDS:=+libpthread
endef

define Package/wakupator/description
  Automatically starts machines based on incoming traffic, using smart local IP spoofing and Wake-on-LAN.
endef

define Package/wakupator/conffiles
/etc/config/wakupator
endef

define Package/wakupator/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/wakupator $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/packaging/openwrt/files/etc/config/wakupator $(1)/etc/config/wakupator

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packaging/openwrt/files/etc/init.d/wakupator $(1)/etc/init.d/wakupator
endef

$(eval $(call BuildPackage,wakupator))