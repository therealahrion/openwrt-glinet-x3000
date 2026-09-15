#!/bin/sh
# Read-only probe of the MT7981 frame-engine register window.
#
# Question it answers: does this SoC implement the register region MediaTek's
# PCE driver uses on MT7988? That driver takes no reg of its own -- its DT node
# is pce@15100000 with fe_mem = <&eth> -- so it reaches offsets inside the
# frame engine's own window, which MT7981 has at the same base and size.
#
# Result as of 2026-09-15: all eight PCE offsets read zero, inside a 748-byte
# contiguous zero run, in a window that returns structured values for dozens of
# registers upstream never names. See xdp-methods-tested.md section 24.14 for
# what that does and does not license.
#
# REQUIREMENTS
#   CONFIG_KERNEL_DEVMEM=y in x3000/config.common, plus CONFIG_STRICT_DEVMEM=y
#   and IO_STRICT_DEVMEM off in the subtarget fragment. See the Enhancements
#   entry in the repo-root README.
#   The "io" package (CONFIG_PACKAGE_io=y, or apk add io).
#
# WHY io AND NOT dd
#   read() cannot reach MMIO on arm64. valid_phys_addr_range()
#   (arch/arm64/mm/mmap.c:41) returns memblock_is_region_memory() &&
#   memblock_is_map_memory(), true for RAM only, so read_mem() gives up with
#   -EFAULT at drivers/char/mem.c:112. mmap_mem() is gated by
#   valid_mmap_phys_addr_range() (mmap.c:60) instead, which permits any address
#   in the physical mask. io mmaps at io.c:354; dd, od, hexdump and xxd do not.
#
# WINDOW LAYOUT
#   Registers below FE+0x40000; on-chip SRAM from FE+0x40000 up, because
#   MT7981_CAPS carries MTK_SRAM and MTK_ETH_SRAM_OFFSET is 0x40000
#   (mtk_eth_soc.h:145, mtk_eth_soc.c:4907). Do not use the top half as a
#   negative control -- it holds live buffer contents.
#
# READ ONLY, and io does not make that easy: at io.c:236 a second positional
# argument turns a read into a WRITE, and -r does not override it. Every call
# below passes exactly two arguments. Never add a third. Writing an
# undocumented frame engine register on a live router is how the WAN goes away.
#
# Indented with SPACES on purpose: a leading tab pasted into an interactive
# shell triggers readline completion and corrupts the heredoc being written.

FE=0x15100000

say() { printf '%s\n' "$*"; }
hr()  { say "------------------------------------------------------------"; }

command -v io >/dev/null 2>&1 || {
  say "io not installed:  apk add io   (or opkg install io)"
  exit 1
}
[ -r /dev/mem ] || {
  say "/dev/mem not readable. This image predates the config change; see the"
  say "Enhancements entry in the repo-root README."
  exit 1
}

rd() {  # rd <hex offset without 0x> <label>
  _a=$(printf '0x%08x' $(( FE + 0x$1 )))
  # stderr to /dev/null on purpose: an error message has fields too, and
  # letting awk take $2 from one would print it as if it were a register value.
  _v=$(io -4 "$_a" 2>/dev/null | awk 'NR==1 && NF>=2 {print $2}')
  [ -n "$_v" ] && _v=0x$_v || _v="READ FAILED"
  printf '  %-22s %s  %s\n' "$2" "$_a" "$_v"
}

hr
say "frame engine window probe -- READ ONLY, io/mmap backend"
say "base $FE; registers below +0x40000, SRAM above"
hr
grep -i '15100000' /proc/iomem 2>/dev/null | sed 's/^/  /'
say ""
say "CONTROLS -- the driver programs these, so they must be non-zero."
say "If they are not, nothing below means anything."
rd 2200 "PPE0 GLO_CFG"
rd 221c "PPE0 TB_CFG"
rd 2220 "PPE0 TB_BASE"
rd 2620 "PPE1 TB_BASE"
rd 4604 "QDMA GLO_CFG"
say ""
say "SUBJECT -- the registers MediaTek's PCE driver uses on MT7988"
rd 0258 "PPE_TPORT_TBL_0"
rd 025c "PPE_TPORT_TBL_1"
rd 0600 "GLO_MEM_CFG"
rd 0604 "GLO_MEM_CTRL"
rd 0608 "GLO_MEM_DATA_IDX0"
rd 060c "GLO_MEM_DATA_IDX1"
rd 0610 "GLO_MEM_DATA_IDX2"
rd 0614 "GLO_MEM_DATA_IDX3"
say ""
say "FLOOR -- register half, clear of every block in mt7986_reg_map"
rd 0700 "0x0700"
rd 0f00 "0x0f00"
rd 1800 "0x1800"
rd 3f00 "0x3f00"
rd 5000 "0x5000"
hr
say "For the full picture rather than these rows, dump the region in one call:"
say "  io -4 -l 0x800 $FE > /tmp/fe.dump"
say "  grep -v ':  00000000 00000000 00000000 00000000\$' /tmp/fe.dump"
say ""
say "How to read it: a subject register reading zero is only meaningful"
say "against the floor AND against how much of the region is alive. Both"
say "naive inferences are false here -- 46 live offsets are unnamed by"
say "upstream, and 10 offsets upstream does name read zero."
hr
