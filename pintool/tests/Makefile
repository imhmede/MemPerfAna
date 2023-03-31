CC := gcc

all: stream

stream: test_stream.c ../pinMarker.h
	$(CC) -O3 -o stream test_stream.c
	$(CC) -O3 -o bs bs.c

clean:
	rm -rf stream
	rm -rf bs
