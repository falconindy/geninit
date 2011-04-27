VERSION = 0.1

all: dinit doc

install: dinit
	install -dm755 $(DESTDIR)$(PREFIX)/share/geninit/builders
	install -dm755 $(DESTDIR)$(PREFIX)/share/geninit/hooks
	install -dm755 $(DESTDIR)$(PREFIX)/sbin
	install -Dm644 geninit.conf $(DESTDIR)/etc/geninit.conf
	install -m755 -t $(DESTDIR)$(PREFIX)/share/geninit/hooks hooks/*
	install -m644 -t $(DESTDIR)$(PREFIX)/share/geninit/builders builders/*
	install -m644 -t $(DESTDIR)$(PREFIX)/share/geninit geninit.api
	install -m755 -t $(DESTDIR)$(PREFIX)/share/geninit dinit/init
	sed "s#^_sharedir=.*#_sharedir=$(PREFIX)/share/geninit#" < geninit > $(DESTDIR)$(PREFIX)/sbin/geninit
.PHONY: install

doc:
	@echo "maybe i'll have some doc one day"
.PHONY: doc

dinit:
	$(MAKE) -C dinit
.PHONY: dinit

clean:
	$(MAKE) -C dinit clean

