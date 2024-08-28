kernel-version=5.19.0
arch=x86_64

build:
	git clone --depth 1 https://github.com/libbpf/libbpf
	cd $(abspath ./libbpf/src) && make install

btf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/kern/vmlinux.h

kern:
	clang -O2 -Wall \
	-Iinclude \
	-target bpf -D__TARGET_ARCH_x86 -g -c kern.c -o conprov.o

skel:
	bpftool gen skeleton conprov.o > include/usr/conprov.skel.h

cjson:
	git clone https://github.com/DaveGamble/cJSON
	cd $(abspath ./cJSON) && make
	cd $(abspath ./cJSON) && cp libcjson.so /usr/lib && cp libcjson.so.1 /usr/lib

usr:
	clang -Wall usr.c -o usr.o -Iinclude -c
	clang -Wall types.c -o types.o -Iinclude -c
	clang -Wall configuration.c -o configuration.o -Iinclude -c
	clang -Wall record.c -o record.o -Iinclude -c
	clang -Wall docker.c -o docker.o -Iinclude -c
	clang -Wall utils.c -o utils.o -Iinclude -c
	clang -Wall spade.c -o spade.o -Iinclude -c
	clang -o conprovd \
	configuration.o \
	usr.o \
	record.o \
	docker.o \
	spade.o \
	utils.o \
	types.o \
	-lbpf -lpthread -linih -lelf -lcurl -lcjson


usr_dbg:
	clang -g usr.c -o usr.o -Iinclude -c
	clang -g configuration.c -o configuration.o -Iinclude -c
	clang -g record.c -o record.o -Iinclude -c
	clang -g docker.c -o docker.o -Iinclude -c
	clang -g utils.c -o utils.o -Iinclude -c
	clang -g types.c -o types.o -Iinclude -c
	clang -g spade.c -o spade.o -Iinclude -c
	clang -g -o conprovd \
	configuration.o \
	usr.o \
	record.o \
	docker.o \
	spade.o \
	utils.o \
	types.o \
	-lbpf -lpthread -linih -lelf -lcurl -lcjson

all: clean btf kern skel usr_dbg

clean:
	rm -f *.o
	rm -f include/usr/conprov.skel.h
	rm -f include/kern/vmlinux.h
	rm -rf output

install:
	sudo cp --force ./conprovd /usr/bin/conprovd
	sudo cp --force ./conprovd.service /etc/systemd/system/conprovd.service
	sudo systemctl enable conprovd.service

start:
	sudo systemctl start conprovd.service

stop:
	sudo systemctl stop conprovd.service

status:
	sudo systemctl status conprovd.service

uninstall:
	sudo systemctl stop conprovd.service
	sudo systemctl disable conprovd.service
	sudo rm -f /usr/bin/conprovd
	sudo rm -f /etc/systemd/system/conprovd.service

run:
	rm -rf audit.log
	sudo conprovd