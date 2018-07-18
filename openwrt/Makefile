include $(TOPDIR)/rules.mk

PKG_NAME:=crappydns
PKG_VERSION:=0.1
PKG_RELEASE=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-v$(PKG_VERSION)

PKG_INSTALL:=1
PKG_FIXUP:=autoreconf
PKG_USE_MIPS16:=0
PKG_BUILD_PARALLEL:=1
PKG_BUILD_DEPENDS:=libuv libstdcpp

include $(INCLUDE_DIR)/package.mk

define Package/crappydns
  SECTION:=net
  CATEGORY:=Network
  TITLE:=A crappy DNS repeater
  DEPENDS:=+libuv +libstdcpp
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ../* $(PKG_BUILD_DIR)/
endef

define Build/Configure
	( cd $(PKG_BUILD_DIR); ./autogen.sh )
	$(call Build/Configure/Default)
endef

define Package/crappydns/description
A crappy DNS repeater.
endef

define Package/crappydns/conffiles
/etc/crappyhosts
/etc/chnroute.txt
endef

define Package/crappydns/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/init.sh $(1)/etc/init.d/crappydns
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/hosts $(1)/etc/crappyhosts
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/chnroute.txt $(1)/etc/chnroute.txt
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/crappydns $(1)/usr/bin
endef

$(eval $(call BuildPackage,crappydns))