VERSION = 0.1

all: init doc

CC       ?= cc
CPPFLAGS +=
INCS      = -I/usr/include/blkid
CFLAGS   += -std=c99 -Wall -pedantic -Wextra ${CPPFLAGS} ${INCS}
LDFLAGS  := -lblkid ${LDFLAGS}

init: init.c
	${CC} -c ${CFLAGS} ${CPPFLAGS} init.c
	${CC} -o $@ ${LDFLAGS} init.o

install: init strip
	install -dm755 $(DESTDIR)$(PREFIX)/share/geninit/builders
	install -dm755 $(DESTDIR)$(PREFIX)/share/geninit/hooks
	install -dm755 $(DESTDIR)$(PREFIX)/sbin
	install -Dm644 geninit.conf $(DESTDIR)/etc/geninit.conf
	install -m755 -t $(DESTDIR)$(PREFIX)/share/geninit/hooks hooks/*
	install -m644 -t $(DESTDIR)$(PREFIX)/share/geninit/builders builders/*
	install -m644 -t $(DESTDIR)$(PREFIX)/share/geninit geninit.api
	install -m755 -t $(DESTDIR)$(PREFIX)/share/geninit dinit/init
	sed "s#^_sharedir=.*#_sharedir=$(PREFIX)/share/geninit#" < geninit > $(DESTDIR)$(PREFIX)/sbin/geninit
	chmod +x $(DESTDIR)$(PREFIX)/sbin/geninit
.PHONY: install

strip: init
	strip --strip-all init

doc:
	@echo "maybe i'll have some doc one day"
.PHONY: doc

clean:
	$(RM) init.o init

