TARGET := ethblk
KERNEL := /lib/modules/$(shell uname -r)/build

ccflags-y += -g3 -O3

obj-m += $(TARGET).o
$(TARGET)-y := main.o target.o initiator.o network.o worker.o

all:
	make -C $(KERNEL) M=$(PWD) modules

clean:
	make -C $(KERNEL) M=$(PWD) clean
