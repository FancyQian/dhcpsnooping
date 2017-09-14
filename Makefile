include $(TOPDIR)/rules.mk

PKG_NAME:=dhcpsnoopd
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/dhcpsnoopd
  SECTION:=Hitron Properties
  CATEGORY:=Hitron Properties
  TITLE:=DHCP snooping
  SUBMENU:=Applications
  DEPENDS:=+libpcap
endef

define Package/dhcpsnoopd/description
  DHCP snooping
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS += \
				-I$(LINUX_DIR)/drivers/char/ \
				-I$(LINUX_DIR)/drivers/net/raeth \
				-lpcap

EXTRA_CFLAGS += -DCONFIG_RALINK_MT7621

define Package/dhcpsnoopd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dhcpsnoopd $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/dhcpsnooping.init $(1)/etc/init.d/dhcpsnooping
endef

$(eval $(call BuildPackage,dhcpsnoopd))

