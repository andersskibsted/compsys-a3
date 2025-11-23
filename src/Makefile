#GCC=gcc -g -Wall -Wextra -pedantic -std=gnu11
GCC=gcc -g -Wall -Wextra -pedantic -std=gnu11
LD_FLAGS= -lpthread -lm

all: peer

rebuild: clean all

compsys_helpers.o: compsys_helpers.c compsys_helpers.h
	$(GCC) -c $< -o $@

common.o: common.c common.h
	$(GCC) -c $< -o $@

network.o: network.c network.h
	$(GCC) -c $< -o $@

security.o: security.c security.h
	$(GCC) -c $< -o $@

utils.o: utils.c utils.h
	$(GCC) -c $< -o $@

messages.o: messages.c messages.h utils.h network.h
	$(GCC) -c $< -o $@

request_handlers.o: request_handlers.c request_handlers.h messages.h network.h security.h peer.h
	$(GCC) -c $< -o $@

peer: peer.c peer.h common.o compsys_helpers.o sha256.o network.o security.o utils.o request_handlers.o messages.o
	$(GCC) $< *.o -o $@ $(LD_FLAGS)

hasher: hasher.c peer.h common.o compsys_helpers.o sha256.o
	$(GCC) $< *.o -o $@ $(LD_FLAGS)

sha256.o : sha256.c sha256.h
	$(CC) $(CFLAGS) -c $< -o $@

zip: ../../src.zip

../../src.zip:
	make clean
	cd ../.. && zip -r handout/src.zip handout/src/Makefile handout/src/*.c handout/src/*.h handout/python/*.py handout/python/*/*.py

clean:
	rm -rf *.o peer sha256 vgcore*
