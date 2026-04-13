# KDIR points to your previously configured and compiled kernel source tree
KDIR ?= /home/alkpone/driver/linux-rust

# Module object file name
obj-m := rtl8192su.o
rtl8192su-y := rtl8192su_main.o rust_helpers.o

# Use LLVM toolchain for compilation
ccflags-y := -D__KERNEL__ -DDEBUG -I$(KDIR)/rust -I$(KDIR)/include -include $(KDIR)/include/linux/kconfig.h
HOSTCFLAGS_MODULE   =
CLANG_FLAGS_MODULE  =

all:
	make LLVM=1 -C $(KDIR) M=$(CURDIR) modules

clean:
	make LLVM=1 -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean