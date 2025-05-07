#
#
# Makefile IOT-AFL
# -----------------------------

all: 
	$(MAKE) -C aflnet
	$(MAKE) -C AFL
	./build_qemu_support.sh all
	@echo "\033[32m[+]\033[0m Compilation Completed"

test_x86: 
	$(MAKE) -C aflnet test_x86

afl-gcc: 
	$(MAKE) -C aflnet afl-gcc
	@echo "\033[32m[+]\033[0m Compilation afl-gcc Completed"

afl-as: $(MAKE) -C aflnet afl-as
	@echo "\033[32m[+]\033[0m Compilation afl-as Completed"

afl-fuzz: 
	$(MAKE) -C AFL afl-fuzz
	@echo "\033[32m[+]\033[0m Compilation afl-fuzz Completed"

afl-fuzz-net: 
	$(MAKE) -C aflnet afl-fuzz
	@echo "\033[32m[+]\033[0m Compilation afl-fuzz Completed"

afl-showmap: 
	$(MAKE) -C aflnet afl-showmap
	@echo "\033[32m[+]\033[0m Compilation afl-showmap Completed"

afl-tmin: 
	$(MAKE) -C aflnet afl-tmin
	@echo "\033[32m[+]\033[0m Compilation afl-tmin Completed"

afl-analyze: 
	$(MAKE) -C aflnet afl-analyze
	@echo "\033[32m[+]\033[0m Compilation afl-analyze Completed"

afl-gotcpu: 
	$(MAKE) -C aflnet afl-gotcpu
	@echo "\033[32m[+]\033[0m Compilation afl-gotcpu Completed"

test_build: 
	$(MAKE) -C aflnet test_build
	@echo "\033[32m[+]\033[0m Compilation test_build Completed"

all_done: 
	$(MAKE) -C aflnet all_done

qemu_all:
	./build_qemu_support.sh all

afl-qemu-system-trace-full:
	./build_qemu_support.sh qemu_full

afl-qemu-system-trace-full-2020:
	./build_qemu_support.sh qemu_full_2020

afl-qemu-system-trace-full-10:
	./build_qemu_support.sh qemu_full_10

afl-qemu-system-trace-full-2:
	./build_qemu_support.sh qemu_full_10

afl-qemu-system-trace:
	./build_qemu_support.sh qemu

afl-qemu-trace :
	./build_qemu_support.sh user

.NOTPARALLEL: 
	$(MAKE) -C aflnet publish

clean:
	$(MAKE) -C aflnet clean

install: 
	$(MAKE) -C aflnet install

publish:
	$(MAKE) -C aflnet publish
	
