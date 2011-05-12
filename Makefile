#
# Makefile
#
# This file is part of geninit.
#

VERSION = 0.1

all: init doc

CC       ?= cc
CPPFLAGS +=
CFLAGS   += -std=c99 -Wall -pedantic -Wextra ${CPPFLAGS}
LDFLAGS  := -lblkid ${LDFLAGS}

DIRS := \
	${PREFIX}/share/geninit/builders \
	${PREFIX}/share/geninit/hooks \
	${PREFIX}/sbin \
	${PREFIX}/bin \
	/etc/geninit.d

DISTFILES := \
	builders/ \
	hooks/ \
	geninit.conf \
	geninit.api \
	geninit.quirks \
	geninit \
	lsinitramfs \
	libinit \
	init.c \
	example.preset \
	Makefile

init: init.c
	${CC} -c ${CFLAGS} ${CPPFLAGS} init.c
	${CC} -o $@ ${LDFLAGS} init.o

install-doc: doc
	install -Dm644 geninit.8 ${DESTDIR}/share/man/man8/geninit.8
.PHONY: install-doc

install-dirs:
	$(foreach dir,${DIRS},install -dm755 ${DESTDIR}${dir};)
.PHONY: install-dirs

install: init install-dirs install-doc
	install -m644 -t ${DESTDIR}/etc geninit.conf
	install -m644 -t ${DESTDIR}/etc/geninit.d example.preset
	install -m755 -t ${DESTDIR}${PREFIX}/share/geninit/hooks hooks/*
	install -m644 -t ${DESTDIR}${PREFIX}/share/geninit/builders builders/*
	install -m644 -t ${DESTDIR}${PREFIX}/share/geninit libinit geninit.api geninit.quirks
	install -m755 -t ${DESTDIR}${PREFIX}/share/geninit init
	install -m755 -t ${DESTDIR}${PREFIX}/bin lsinitramfs
	sed "s#^\(declare.\+_sharedir\)=.*#\1=${PREFIX}/share/geninit#" < \
		geninit > ${DESTDIR}${PREFIX}/sbin/geninit
	chmod 755 ${DESTDIR}${PREFIX}/sbin/geninit
.PHONY: install

strip: init
	strip --strip-all init
.PHONY: strip

doc: geninit.8
geninit.8: README.pod
	pod2man --section=8 --center="geninit manual" --name="GENINIT" --release="geninit ${VERSION}" $< > $@
.PHONY: doc

dist:
	mkdir geninit-${VERSION}
	cp -r ${DISTFILES} geninit-${VERSION}
	tar czf geninit-${VERSION}.tar.gz ${DISTFILES}
	${RM} -r geninit-${VERSION}
.PHONY:

clean:
	${RM} init.o init geninit.8
.PHONY: clean

