obj-m 		   += mypblk.o
mypblk-objs := pblk-l2p.o pblk-test.o

KDIR	:=	/lib/modules/$(shell uname -r)/build
PWD		:=	$(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
