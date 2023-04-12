CC := gcc

all: stream

stream: test_stream.c ../pinMarker.h
	$(CC) -O3 -o stream test_stream.c
	$(CC) -O3 -o bsort bsort.c
	$(CC) -O3 -o insertsort insertsort.c
	$(CC) -O3 -o qsort qsort.c
	$(CC) -O3 -o bs bs.c

clean:
	rm -rf stream
	rm -rf bsort
	rm -rf insertsort
	rm -rf qsort
	rm -rf bs
