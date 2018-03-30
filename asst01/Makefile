all: smlib dsm client clean

smlib: sm.c commonlib.c vec.c
	gcc -c sm.c commonlib.c vec.c
	ar -crv libsm.a sm.o commonlib.o vec.o
	@echo "'libsm.a' has been made."

dsm: dsm.c param.c commonlib.c vec.c
	gcc -o dsm dsm.c param.c commonlib.c vec.o
	@echo "'dsm' has been made."

client: client.c libsm.a
	gcc -o client client.c libsm.a
	@echo "'client' has been made."

clean:
	rm *.o
	@echo "make done."