# Shared guard for this image's first-boot defaults. Sourced, not executed.
#
# uci-defaults scripts are deleted by /etc/init.d/boot once they run
# (`rm -f $applied` at the end of uci_apply_defaults), so a normal reboot does
# not run them again. A sysupgrade does: SAVE_OVERLAY defaults to 0 in
# /sbin/sysupgrade (-c and -o are opt-in), so the rootfs is replaced and these
# scripts come back from the new squashfs and run a second time against a
# restored /etc/config. Every script here is therefore written so that running
# twice is harmless and never overwrites a choice made in LuCI.
#
# For a setting whose packaged state is "absent", `uci -q get` coming back
# empty is guard enough - that is how 90, 91, 94 and 96-flow-offload work. For
# a setting whose packaged state is a real value there is no way to tell
# "package default" from "user picked this", so those record a flag here and
# apply exactly once per factory state. Two cases need it: irqbalance ships
# enabled='0', and the wireless sections ship with a real SSID, channel and
# htmode already filled in.
#
# On /etc/config/x3000 surviving a sysupgrade: base-files declares /etc/config/
# as a conffile, and include/package-pack.mk writes any declared conffile that
# is not shipped as a real file into /lib/upgrade/keep.d/<pkg>. sysupgrade's
# list_static_conffiles() then finds every file under it, so the whole of
# /etc/config is preserved and this file rides along with it. Nothing extra is
# needed in /etc/sysupgrade.conf. Confirm on the box with:
#     cat /lib/upgrade/keep.d/base-files

x3000_defaults_init() {
	[ -f /etc/config/x3000 ] || : > /etc/config/x3000
	uci -q get x3000.defaults >/dev/null 2>&1 || {
		uci set x3000.defaults=defaults
		uci commit x3000
	}
}

# True when this default has already been applied once on this install.
x3000_applied() {
	x3000_defaults_init
	[ "$(uci -q get "x3000.defaults.$1")" = "1" ]
}

x3000_mark() {
	x3000_defaults_init
	uci set "x3000.defaults.$1=1"
	uci commit x3000
}
