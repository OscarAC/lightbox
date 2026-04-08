# lightbox — container runtime built on lightc
#
# lightc is resolved in order:
#   1. lightc/     (git submodule — preferred)
#   2. ../lightc/  (sibling directory)
#   3. LIGHTC=...  (override on command line)

ifeq ($(wildcard lightc/include/lightc/syscall.h),lightc/include/lightc/syscall.h)
  LIGHTC ?= lightc
else ifeq ($(wildcard ../lightc/include/lightc/syscall.h),../lightc/include/lightc/syscall.h)
  LIGHTC ?= ../lightc
else ifdef LIGHTC
  # user-provided path
else
  $(error lightc not found. Either: \
    1) git submodule update --init, \
    2) place lightc alongside this directory, or \
    3) pass LIGHTC=/path/to/lightc)
endif

PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
CONFDIR    ?= /etc/lightbox
DATADIR    ?= /var/lib/lightbox
RUNDIR     ?= /run/lightbox
HOME_CONF  ?= $(HOME)/.config/lightbox

CC = gcc
CFLAGS = -std=c23 -O2 -DNDEBUG -Wall -Wextra -Wpedantic \
         -ffreestanding -nostdlib -nostartfiles -nodefaultlibs \
         -fno-stack-protector -I$(LIGHTC)/include
LDFLAGS = -static -no-pie -nostdlib -nostartfiles -nodefaultlibs \
          -T $(LIGHTC)/lightc.ld

OBJS = lightbox.o lightbox_meta.o lightbox_state.o lightbox_net.o lightbox_config.o lightbox_util.o

lightbox: $(OBJS) $(LIGHTC)/build/liblightc.a
	$(CC) $(LDFLAGS) $^ -o $@ && strip $@

lightbox.o: lightbox.c
	$(CC) $(CFLAGS) -c $< -o $@

lightbox_meta.o: lightbox_meta.c lightbox.h
	$(CC) $(CFLAGS) -c $< -o $@

lightbox_state.o: lightbox_state.c lightbox.h
	$(CC) $(CFLAGS) -c $< -o $@

lightbox_net.o: lightbox_net.c lightbox.h
	$(CC) $(CFLAGS) -c $< -o $@

lightbox_config.o: lightbox_config.c lightbox.h
	$(CC) $(CFLAGS) -c $< -o $@

lightbox_util.o: lightbox_util.c lightbox.h
	$(CC) $(CFLAGS) -c $< -o $@

$(LIGHTC)/build/liblightc.a:
	cd $(LIGHTC) && ./configure release && ninja

install: lightbox
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 lightbox $(DESTDIR)$(BINDIR)/lightbox
	install -d -m 755 $(DESTDIR)$(CONFDIR)
	install -d -m 755 $(DESTDIR)$(DATADIR)
	install -d -m 755 $(DESTDIR)$(DATADIR)/rootfs
	install -d -m 755 $(DESTDIR)$(DATADIR)/containers
	install -d -m 755 $(DESTDIR)$(RUNDIR)
	install -d -m 755 $(HOME_CONF)
	@if [ ! -f $(HOME_CONF)/lightbox.conf ]; then \
		install -m 644 lightbox.conf.example $(HOME_CONF)/lightbox.conf; \
		echo "Installed config: $(HOME_CONF)/lightbox.conf"; \
	else \
		echo "Config already exists: $(HOME_CONF)/lightbox.conf (skipped)"; \
	fi
	@echo ""
	@echo "lightbox installed to $(DESTDIR)$(BINDIR)/lightbox"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Place a rootfs in $(DATADIR)/rootfs/"
	@echo "     e.g.: wget -qO- https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz | tar -xz -C $(DATADIR)/rootfs/"
	@echo "  2. Edit $(HOME_CONF)/lightbox.conf if needed"
	@echo "  3. Run: lightbox setup"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/lightbox

clean:
	rm -f lightbox $(OBJS)

test-validation: lightbox
	chmod +x test_validation.sh
	./test_validation.sh

test-lifecycle: lightbox
	chmod +x test_lifecycle.sh
	./test_lifecycle.sh

.PHONY: clean install uninstall test-validation test-lifecycle
