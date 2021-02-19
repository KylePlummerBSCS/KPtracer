CC = gcc  

all:	ptracer.c pidlist.c
	gcc -D_POSIX_C_SOURCE=199309L -o ptracer ptracer.c pidlist.c -lm

clean:	
