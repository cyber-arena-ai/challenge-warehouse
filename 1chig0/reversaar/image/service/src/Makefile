all: reversaar.cgi .tmp.bin

reversaar.cgi: main.c crypto/sha256.c crypto/base64.c crypto/arcfour.c
	gcc -Wall -Wextra -O2 -o $@ $^ -lfcgi -ljson-c -lz -luuid -ldl
	strip -s $@

array.so: array.c crypto/sha256.c crypto/base64.c
	gcc -fvisibility=hidden -shared -fPIC -Wall -Wextra -O2 -o $@ $^ -lfcgi -ljson-c -lz -luuid
	strip -s $@

array.forged.so: array.so
	cp $< $@
	python3 forge_crc32.py $@

array.encrypted.so: array.forged.so
	cp $< $@
	python3 rc4wrap.py $@
	
.tmp.bin: array.encrypted.so
	mv $< $@
	
.PHONY: clean
clean:
	rm -f reversaar.cgi .tmp.bin
