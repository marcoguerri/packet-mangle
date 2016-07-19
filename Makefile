obj-m += packet_mangle.o
packet_mangle-objs := packet.o libcrc/libcrc.a

LIBCRC_DIR = $(PWD)/libcrc
KERNEL_BUILD = /lib/modules/$(shell uname -r)/build
KERNEL_SRC= /usr/src/kernels/$(shell uname -r)
LDFLAGS_packet_mangle.o += -L$(LIBCRC_DIR)/libcrc

all:
	make -C $(KERNEL_BUILD) M=$(PWD) modules

$(LIBCRC_DIR)/libcrc.a:
	# Not relying on Kbuild, need to define include paths manually.
	# isystem is evaluated after -I and before default system include paths
	make -C $(LIBCRC_DIR) libcrc.a \
	EXTRA_CFLAGS+="-D__KERNEL__ -isystem $(KERNEL_SRC)/include -isystem $(KERNEL_SRC)/arch/x86/include -mcmodel=kernel"

clean:
	make -C libcrc $@
	make -C $(KERNEL_BUILD) M=$(PWD) clean

