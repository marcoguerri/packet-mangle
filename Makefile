obj-m += packet_mangle.o
packet_mangle-objs := packet.o libcrc/libcrc.a

LIBCRC_DIR = $(PWD)/libcrc
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
LDFLAGS_packet_mangle.o += -L$(LIBCRC_DIR)/libcrc

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

$(LIBCRC_DIR)/libcrc.a:
	make -C $(LIBCRC_DIR) libcrc.a EXTRA_CFLAGS+="-D__KERNEL__"

clean:
	make -C libcrc $@
	make -C $(KERNEL_DIR) M=$(PWD) clean

