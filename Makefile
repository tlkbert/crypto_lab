aes: aes_enc.o aes_key_recov.o main.o
	gcc -o aes aes_enc.o aes_key_recov.o main.o
aes_enc.o: aes-128_enc.c aes-128_enc.h
	gcc -o aes_enc.o -c aes-128_enc.c
aes_key_recov.o: aes-128_key_recov.c aes-128_enc.h
	gcc -o aes_key_recov.o -c aes-128_key_recov.c
main.o: main.c aes-128_enc.h
	gcc -o main.o -c main.c
clean:
	rm *.o
