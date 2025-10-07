MODULE_NAME = hook
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs += main.o

all:
	
	make -C ~/kernel/ares/out ARCH=arm64 SUBARCH=arm64 CROSS_COMPILE=clang CC=clang CLANG_TRIPLE=aarch64-linux-gnu- HOSTCC=gcc HOSTCXX=g++ HOSTLD=ld STRIP=llvm-strip DEPMOD=depmod LD=ld.lld AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump READELF=llvm-readelf OBJSIZE=llvm-size $(KDIR) M=$(PWD) modules
	
	find . -type f -name '*.o' -not -name '*.ko' -delete
	find . -type f -name '*.mod.c' -delete
	find . -type f -name '*.mod.o' -delete
	find . -type f -name '*.o.d' -delete
	find . -type f -name '*.cmd' -delete
	rm -rf .tmp_versions
	rm -f Module.symvers
	rm -f modules.order
	rm -f Module.markers

clean:
	find . -type f -name '*.o' -not -name '*.ko' -delete
	find . -type f -name '*.mod.c' -delete
	find . -type f -name '*.mod.o' -delete
	find . -type f -name '*.o.d' -delete
	find . -type f -name '*.cmd' -delete
	rm -rf .tmp_versions
	rm -f Module.symvers
	rm -f modules.order
	rm -f Module.markers
