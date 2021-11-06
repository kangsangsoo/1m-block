LDLIBS = -lnetfilter_queue -lnet

all: 1m-block

1m-block: 1m-block.cpp

clean:
	rm -f 1m-block *.o

remake: clean all
