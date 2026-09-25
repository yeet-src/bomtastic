# BPF objects for this project.
#
#   make bpf     compile bpf/*.bpf.c into bin/app.bpf.o
#   make clean-bpf
#   make veristat  load the object and let this kernel's verifier judge it
#
# yeetkit runs `make bpf` for you whenever bpf/ has sources in it, so
# this is here to be edited (CFLAGS, extra objects) and to be run on its
# own when you want the compiler's output without the dev loop around
# it.
#
# clang and bpftool come from the pinned static toolchain resolved by
# build/toolchain.mk — fetched once into a shared per-machine cache, so
# the build needs no system C or BPF toolchain.

.DEFAULT_GOAL := bpf

include build/toolchain.mk
include build/bpf.mk
