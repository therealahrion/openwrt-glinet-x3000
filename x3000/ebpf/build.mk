# Build with: make -f build.mk
# (named build.mk rather than Makefile only because the file-transfer bridge
#  refuses to write a file called Makefile; rename it if you prefer.)
# Build the wwan0 flowtable XDP objects.
#
# Cross-compiling BPF needs no cross toolchain: BPF bytecode is
# architecture-neutral. -D__TARGET_ARCH_arm64 only selects the register
# names used by BPF_CORE_READ's tracing macros, which this program does
# not use, but it is set so the object is honest about its target.
CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
ARCH     ?= arm64
INCLUDES ?= -idirafter /usr/include/$(shell uname -m)-linux-gnu
CFLAGS   := -O2 -g -Wall -Wextra -Wno-unused-parameter \
            -target bpf -mcpu=v3 -D__TARGET_ARCH_$(ARCH)

# The committed .o is stripped of DWARF but keeps .BTF, which CO-RE needs to
# relocate struct offsets against the router's own kernel at load time. Strip
# with llvm-strip -g, never plain strip, which would take BTF with it.
all: xdp_ft_wwan.bpf.o

xdp_ft_wwan.bpf.o: xdp_ft_wwan.bpf.c
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f xdp_ft_wwan.bpf.o

.PHONY: all clean
