obj-m += async_sys.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc jobmanager.c -o jobmanager  -lpthread  -lssl -lcrypto
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm jobmanager
