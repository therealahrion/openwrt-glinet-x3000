#
# GL-X3000 lean XDP/tc-bpf suite — compiled in-tree, baked into the
# image. All-inclusive: no host build, no scp. Nothing auto-attaches
# (lever-off); use the x3000-xdp / x3000-tc-cake CLIs on the router.
#
# Mirrors the in-tree BPF build path used by qosify (include/bpf.mk +
# CompileBPF + bpf-headers). Selecting this package pulls the BPF
# toolchain (prebuilt LLVM where the build host offers one, else built
# from source) — the same cost qosify carried.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=x3000-ebpf
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0
PKG_MAINTAINER:=therealahrion

PKG_BUILD_DEPENDS:=bpf-headers
PKG_FLAGS:=nonshared

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

define Package/x3000-ebpf
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=GL-X3000 lean XDP + tc-bpf suite (lever-off)
  DEPENDS:=+kmod-sched-bpf +kmod-sched-cake +kmod-ifb +tc-bpf +libbpf $(BPF_DEPENDS)
endef

define Package/x3000-ebpf/description
  In-tree eBPF for the GL-X3000 lean build, compiled to arch-independent
  BPF objects and installed to /lib/bpf:
    xdp_filter.o    L2/L3/L4 XDP ingress filter (stats, src + dport block)
    tc_cake_mark.o  clsact egress DSCP classifier feeding cake tins
  Loaders installed to /usr/sbin as x3000-xdp and x3000-tc-cake.
  Nothing is attached at boot; both are drivers you invoke.
endef

# CompileBPF (include/bpf.mk) emits <name>.o next to the source.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/*.c $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(call CompileBPF,$(PKG_BUILD_DIR)/xdp_filter.c)
	$(call CompileBPF,$(PKG_BUILD_DIR)/tc_cake_mark.c)
endef

define Package/x3000-ebpf/install
	$(INSTALL_DIR) $(1)/lib/bpf $(1)/usr/sbin
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/xdp_filter.o   $(1)/lib/bpf/xdp_filter.o
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/tc_cake_mark.o $(1)/lib/bpf/tc_cake_mark.o
	$(INSTALL_BIN) ./files/load-xdp.sh $(1)/usr/sbin/x3000-xdp
	$(INSTALL_BIN) ./files/tc-cake.sh  $(1)/usr/sbin/x3000-tc-cake
endef

$(eval $(call BuildPackage,x3000-ebpf))
