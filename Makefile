#
# Copyright (C) 2002 Phil Dibowitz.
#
# See iptstate.cc for copyright info
#
# Makefile for IPTState verion 1.2.1
#

### USERS CAN CHANGE STUFF HERE

PREFIX=/usr
SBIN=$(PREFIX)/sbin
INSTALL=/usr/bin/install
MAN=$(PREFIX)/share/man

### YOU SHOULD NOT NEED TO CHANGE ANYTHING BELOW HERE

CXX = g++
CXXFLAGS = -g -Wall -Wno-deprecated
OBJS = iptstate.cc
LIBS= -lncurses


all:
	@echo "+------------------------------------------------------------+"
	@echo "| Welcome to IP Tables State by Phil Dibowitz                |"
	@echo "|                                                            |"
	@echo "| PLEASE read the LICENSE and the README for important info. |"
	@echo "|                                                            |"
	@echo "| You may also wish to read the README for install info,     |"
	@echo "| the WISHLIST for upcoming features, BUGS for known bugs    |"
	@echo "| and info on bug reports, and the Changelog to find out     |"
	@echo "| what's new.                                                |"
	@echo "|                                                            |"
	@echo "| Let's compile...                                           |"
	@echo "+------------------------------------------------------------+"
	@echo ""

	$(CXX) $(CXXFLAGS) $(OBJS) -o iptstate $(LIBS)

	@echo ""
	@echo "All done. Do 'make install' as root and you should be set to go!"
	@echo ""


install:
	$(INSTALL) -D --mode=755 iptstate $(SBIN)/iptstate
	$(INSTALL) -D --mode=444 man/man1/iptstate.1 $(MAN)/man1/iptstate.1

clean:
	/bin/rm -rf iptstate


uninstall:
	/bin/rm -rf $(SBIN)/iptstate
	/bin/rm -rf $(MAN)/man1/iptstate.1
