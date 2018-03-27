all: smlib dsm client clean

smlib: sm.c commonlib.c
	gcc -c sm.c commonlib.c
	ar -crv libsm.a sm.o commonlib.o
	@echo "'libsm.a' has been made."

dsm: dsm.c param.c commonlib.c
	gcc -o dsm dsm.c param.c commonlib.c
	@echo "'dsm' has been made."

client: client.c libsm.a
	gcc -o client client.c libsm.a
	@echo "'client' has been made."

clean:
	rm *.o
	@echo "make done."