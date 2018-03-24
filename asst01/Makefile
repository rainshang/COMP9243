all: smlib dsm client clean

smlib: sm.c commonlib.h
	gcc -c sm.c commonlib.h
	ar -crv libsm.a sm.o
	@echo "'libsm.a' has been made."

dsm: dsm.c param.c commonlib.h
	gcc -o dsm dsm.c param.c commonlib.h
	@echo "'dsm' has been made."

client: client.c libsm.a
	gcc -o client client.c libsm.a
	@echo "'client' has been made."

clean:
	rm *.o
	@echo "make done."