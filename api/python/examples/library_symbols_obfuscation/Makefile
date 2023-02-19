CC=gcc
CXX=g++

all: binadd.bin obfu

libadd.so: libadd.c
	$(CC) -Wl,--hash-style=gnu -fPIC -shared -o $@ $^

binadd.bin: binadd.c libadd.so
	$(CC) $^ -Wl,--hash-style=gnu -L. -ladd -o $@
	chmod a+rx $@

run: libadd.so binadd.bin obfu
	LD_LIBRARY_PATH=. ./binadd.bin 1 2
	LD_LIBRARY_PATH=. ./binadd_obf.bin 1 2


obfu: binadd.bin libadd.so
	python ./obfu.py
	chmod a+x *.bin
	chmod a+x *.so

.PHONY: clean

clean:
	rm -rf *.o *~ *.so *.bin
