#
#
# Makefile IOT-AFL
# -----------------------------

all: 
	$(MAKE) -C aflnet afl-fuzz
	$(MAKE) -C AFL afl-fuzz
	./build_qemu_support.sh all
	@echo "\033[32m[+]\033[0m Compilation Completed"

afl-fuzz: 
	$(MAKE) -C AFL afl-fuzz
	@echo "\033[32m[+]\033[0m Compilation afl-fuzz Completed"

afl-fuzz-net: 
	$(MAKE) -C aflnet afl-fuzz
	@echo "\033[32m[+]\033[0m Compilation afl-fuzz Completed"

afl-qemu-system-trace-full:
	./build_qemu_support.sh qemu_full

.NOTPARALLEL: 
	$(MAKE) -C aflnet publish

clean:
	$(MAKE) -C aflnet clean

install: 
	$(MAKE) -C aflnet install

publish:
	$(MAKE) -C aflnet publish
	
