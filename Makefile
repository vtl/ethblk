KVER := `uname -r`

ccflags-y += -g3 -O3
obj-m += ethblk.o
ethblk-y := main.o target.o initiator.o network.o worker.o

all:
	make -C /lib/modules/${KVER}/build M=`pwd` modules

clean:
	make -C /lib/modules/${KVER}/build M=`pwd` clean
