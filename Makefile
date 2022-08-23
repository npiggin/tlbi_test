CFLAGS=-O2
LDFLAGS=-pthread

tlbi_test: tlbi_test.o

clean:
	rm -f tlbi_test tlbi_test.o
