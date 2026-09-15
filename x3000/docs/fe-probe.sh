#!/bin/sh
# Read-only probe of the MT7981 frame-engine register window.
#
# Question it answers: does this SoC implement the register region MediaTek's
# PCE driver uses on MT7988? That driver takes no reg of its own -- its DT node
# is pce@15100000 with fe_mem = <&eth> -- so it pokes offsets inside the frame
# engine's own window, which MT7981 has at the same base and the same size.
#
# NEEDS THE REBUILT IMAGE. OpenWrt's shared config carries
# "# CONFIG_DEVMEM is not set" (target/linux/generic/config-6.12:1405), so on
# a stock build /dev/mem does not exist and no userspace tool can reach a
# physical address at all. This tree overrides that with three symbols split
# across two files:
#
#   x3000/config.common
#     CONFIG_KERNEL_DEVMEM=y              the device node exists
#   target/linux/mediatek/filogic/config-6.12
#     CONFIG_STRICT_DEVMEM=y                system RAM stays unreachable
#     # CONFIG_IO_STRICT_DEVMEM is not set  driver-claimed MMIO stays readable
#
# The split is forced. OpenWrt declares KERNEL_DEVMEM and appends it to the
# merged kernel config after the fragments, so a CONFIG_DEVMEM=y written in the
# fragment is silently overridden and the image ships with no /dev/mem. The
# other two have no KERNEL_ equivalent, so the fragment is their only home.
#
# All three lines are load-bearing. Without the third, the kernel refuses
# reads of any region a driver has claimed, and mtk_eth_soc claims this whole
# window, so every row below would fail. The second is what keeps the price of
# having /dev/mem at all down to MMIO instead of all of physical memory:
# devmem_is_allowed() returns 1 for a page that is not RAM and 0 for one that
# is (lib/devmem_is_allowed.c).
#
# Until an image carrying that config is flashed, this exits at the /dev/mem
# check below.
#
# READS ONLY. Never add a write to this script. Writing an undocumented frame
# engine register on a live router is how the WAN goes away.
#
# Reading is not guaranteed free either: on some designs a read of an
# unimplemented address inside a peripheral window raises an imprecise abort
# rather than returning zero. It is usually benign within a mapped window, and
# I cannot promise it here. Run it when a reboot is cheap.
#
# Indented with SPACES on purpose. A leading tab pasted into an interactive
# shell triggers readline completion and dumps the whole command list into the
# middle of the heredoc, which silently corrupts the script being written.

FE=0x15100000    # eth: ethernet@15100000, length 0x80000 on mt7981 and mt7988

say() { printf '%s\n' "$*"; }
hr()  { say "------------------------------------------------------------"; }

# Pick a 32-bit physical read backend.
#
# devmem is a BUSYBOX applet, not a coreutils one, so installing coreutils does
# not provide it. busybox may also carry the applet without a /usr/bin symlink
# for it, which is why the second probe calls it through busybox by name. The
# third backend needs only dd plus one of od or hexdump, and coreutils and
# busybox both supply those.
BACKEND=
DUMP=
if command -v devmem >/dev/null 2>&1; then
  BACKEND=devmem
elif command -v busybox >/dev/null 2>&1 && busybox devmem 2>&1 | grep -qi usage; then
  BACKEND=busybox
elif command -v dd >/dev/null 2>&1; then
  if command -v od >/dev/null 2>&1; then
    BACKEND=dd
    DUMP=od
  elif command -v hexdump >/dev/null 2>&1; then
    BACKEND=dd
    DUMP=hexdump
  fi
fi

if [ -z "$BACKEND" ]; then
  say "no usable backend. Need one of:"
  say "  devmem, a busybox applet enabled with CONFIG_BUSYBOX_CONFIG_DEVMEM"
  say "  busybox carrying that applet"
  say "  dd plus od or hexdump"
  exit 1
fi

if [ ! -r /dev/mem ]; then
  say "/dev/mem is not readable, so nothing below can run."
  say ""
  say "On an OpenWrt build this is almost always CONFIG_DEVMEM=n rather than a"
  say "permissions problem: the char major is still registered but the minor"
  say "is skipped, so the node is never created. Confirm with"
  say "'zcat /proc/config.gz | grep CONFIG_DEVMEM'."
  say ""
  say "If that says it is not set, this image predates the config change in"
  say "target/linux/mediatek/filogic/config-6.12 and needs a rebuild."
  exit 1
fi

# One little-endian 32-bit word on stdout, no address column, from either tool.
dump_word() {
  if [ "$DUMP" = od ]; then
    od -An -tx4 -N4
  else
    hexdump -n 4 -e '1/4 "%08x"'
  fi
}

rd() {  # rd <offset> <label>
  _off=$1
  _lab=$2
  _addr=$(printf '0x%08x' $(( FE + _off )))
  case "$BACKEND" in
    devmem)
      _v=$(devmem "$_addr" 32 2>/dev/null)
      ;;
    busybox)
      _v=$(busybox devmem "$_addr" 32 2>/dev/null)
      ;;
    dd)
      _skip=$(( (FE + _off) / 4 ))
      _raw=$(dd if=/dev/mem bs=4 count=1 skip=$_skip 2>/dev/null | dump_word)
      _v=$(printf '%s' "$_raw" | tr -d ' \n')
      [ -n "$_v" ] && _v=0x$_v
      ;;
  esac
  if [ -z "$_v" ]; then
    printf '  %-26s %s  READ FAILED\n' "$_lab" "$_addr"
  else
    printf '  %-26s %s  %s\n' "$_lab" "$_addr" "$_v"
  fi
}

hr
say "frame engine window probe -- READ ONLY"
say "base $FE, length 0x80000"
if [ -n "$DUMP" ]; then
  say "backend $BACKEND via $DUMP"
  say "  Access width: the read lands in copy_from_kernel_nofault(), which"
  say "  picks its width from the alignment of the source and destination"
  say "  pointers alone. At bs=4 count=1 on a 4-aligned address the u64 loop"
  say "  cannot run and the u32 loop does exactly one 32-bit load, which is"
  say "  the right width for these registers. Do not change the block size."
else
  say "backend $BACKEND"
fi
hr

say "environment"
if [ -r /proc/iomem ]; then
  _io=$(grep -i '15100000' /proc/iomem 2>/dev/null)
  if [ -n "$_io" ]; then
    printf '%s\n' "$_io" | sed 's/^/  /'
  else
    say "  no /proc/iomem line covers the base"
  fi
else
  say "  /proc/iomem not readable"
fi
if [ -r /proc/config.gz ] && command -v zcat >/dev/null 2>&1; then
  zcat /proc/config.gz 2>/dev/null \
    | grep -E '^(# )?CONFIG_(DEVMEM|STRICT_DEVMEM|IO_STRICT_DEVMEM)[ =]' \
    | sed 's/^/  /'
else
  say "  /proc/config.gz absent, cannot report the DEVMEM config symbols"
fi
say ""

say "positive controls -- upstream drives these, so they must read sanely"
rd 0x2000 "PPE0 base (ppe_base)"
rd 0x2004 "PPE0 +0x04"
rd 0x2400 "PPE1 base"
say ""
say "the registers the PCE driver uses on MT7988"
rd 0x0258 "PPE_TPORT_TBL_0"
rd 0x025c "PPE_TPORT_TBL_1"
rd 0x0600 "GLO_MEM_CFG"
rd 0x0604 "GLO_MEM_CTRL"
rd 0x0608 "GLO_MEM_DATA_IDX(0)"
rd 0x060c "GLO_MEM_DATA_IDX(1)"
rd 0x0610 "GLO_MEM_DATA_IDX(2)"
rd 0x0614 "GLO_MEM_DATA_IDX(3)"
say ""
say "negative controls -- offsets nothing is known to implement."
say "whatever pattern these show is what 'not implemented' looks like here."
rd 0x7f000 "high unused"
rd 0x7f004 "high unused +4"
rd 0x0700 "0x700 unused"
hr
say "How to read this:"
say "  If GLO_MEM_* matches the negative controls exactly (all 0, or all"
say "  0xffffffff), that is consistent with the region not being implemented."
say "  If GLO_MEM_* differs from the negative controls and looks structured,"
say "  the region responds and the PCE tables may well be present but unwired."
say ""
say "  If the positive controls also read 0 or FAILED, the backend is the"
say "  problem and no row here means anything."
say ""
say "  If every row fails with a permission error rather than reading zero,"
say "  suspect CONFIG_IO_STRICT_DEVMEM. OpenWrt's shared config sets it, and"
say "  with it live the kernel refuses reads of any driver-claimed range --"
say "  which this whole window is. The subtarget config turns it back off"
say "  for exactly that reason; confirm with"
say "  'zcat /proc/config.gz | grep IO_STRICT_DEVMEM'."
hr
