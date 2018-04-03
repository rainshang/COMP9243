all: smlib dsm share matmul clean

smlib: sm.c commonlib.* vec.c
	gcc -c sm.c commonlib.c vec.c
	ar -crv libsm.a sm.o commonlib.o vec.o
	@echo "'libsm.a' has been made."

dsm: dsm.c param.c commonlib.* vec.c
	gcc -o dsm dsm.c param.c commonlib.c vec.c
	@echo "'dsm' has been made."

share: share.c libsm.a
	gcc -o share share.c libsm.a
	@echo "'share' has been made."

matmul: matmul.c libsm.a
	gcc -o matmul matmul.c libsm.a
	@echo "'matmul' has been made."

clean:
	rm *.o
	@echo "make done."
