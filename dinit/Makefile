INCS = -I/usr/include/blkid

CC       ?= cc
CPPFLAGS +=
CFLAGS   += -std=c99 -Wall -pedantic -Wextra ${CPPFLAGS} ${INCS}
LDFLAGS  := -lblkid ${LDFLAGS}

all: init

.c.o: init.c
	${CC} $< -c ${CFLAGS} ${CPPFLAGS}

init: init.o
	${CC} -o $@ ${LDFLAGS} $<

strip: init
	strip --strip-all init

clean:
	${RM} init init.o

