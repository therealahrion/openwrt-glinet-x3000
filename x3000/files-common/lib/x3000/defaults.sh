# Shared guard for this image's first-boot defaults. Sourced, not executed.
#
# uci-defaults scripts are deleted by /etc/init.d/boot once they run
# (`rm -f $applied` at the end of uci_apply_defaults), so a normal reboot does
# not run them again. Whether they run again after a sysupgrade depends on how
# much of the overlay that particular upgrade carried across, which is not
# worth relying on either way. Every script here is therefore written so that
# running twice is harmless and never overwrites a choice made in LuCI.
#
# For a setting whose packaged state is "absent", `uci -q get` coming back
# empty is guard enough - that is how 94-packet-steering and 96-flow-offload
# work. For a setting whose packaged state is a real value there is no way to
# tell "package default" from "user picked this", so those record a flag here
# instead and apply exactly once per factory state. Two cases need it:
# irqbalance ships enabled='0', and the wireless sections ship with a real
# SSID and channel already filled in.
#
# /etc/config/x3000 belongs to no package, so it is not a conffile and would
# not be backed up on its own; x3000/files-common/etc/sysupgrade.conf lists it
# for that reason.

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
