all: test_sm2

sm3.o: sm3.c sm3.h
	$(CC) -c -o sm3.o sm3.c

sm2.o: sm2.c sm2.h sm3.c sm3.h
	$(CC) -c -o sm2.o sm2.c

%.o: %.c sm2.h sm3.h
	$(CC) -c $< -o $@

test_sm2: test_sm2.o sm2.o sm3.o
	$(CC) -o test_sm2 test_sm2.o sm2.o sm3.o

clean:
	rm -f *.o test_sm2
