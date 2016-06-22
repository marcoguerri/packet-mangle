obj-m += packet_mangle.o

LIB_DIR=/lib/modules/$(shell uname -r)/build

all:
	make -C $(LIB_DIR) M=$(PWD) modules

clean:
	make -C $(LIB_DIR) M=$(PWD) clean

