NELDIR=	/lib/modules/$(shell uname -r)/build

obj-m	:= pblk.o
pblk-objs += pblk-l2p.o
pblk-objs += pblk-test.o

KDIR	:=	/lib/modules/$(shell uname -r)/build
PWD	:=	$(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.ko
	rm -rf *.mod.*
	rm -rf *.cmd
	rm -rf *.o
	rm -rf .tmp_versions
