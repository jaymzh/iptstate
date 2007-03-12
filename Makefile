#
# Copyright (C) 2002 Phil Dibowitz.
#
# See iptstate.cc for copyright info
#
# Makefile for IPTState verion 1.1.0
#

### USERS CAN CHANGE STUFF HERE

PREFIX=/usr
SBIN=$(PREFIX)/sbin
INSTALL=/usr/bin/install
MAN=$(PREFIX)/share/man

### YOU SHOULD NOT NEED TO CHANGE ANYTHING BELOW HERE

CXXFLAGS = -g -Wall
OBJS = iptstate.cc
LIBS= -lncurses


all:
	@echo "+-----------------------------------------------------------+"
	@echo "| Welcome to IP Tables State by Phil Dibowitz               |"
	@echo "|                                                           |"
	@echo "| PLEASE read the LICENSE and the README                    |"
	@echo "| Consult the README for installation and usage information |"
	@echo "|                                                           |"
	@echo "| Let's compile...                                          |"
	@echo "+-----------------------------------------------------------+"
	@echo ""

	$(CXX) $(CXXFLAGS) $(OBJS) -o iptstate $(LIBS)

	@echo ""
	@echo "All done. Install and you should be set to go!"
	@echo ""


install:
	$(INSTALL) -d $(SBIN)
	$(INSTALL) -D --mode=755 iptstate $(SBIN)/iptstate
	$(INSTALL) -D --mode=444 man/man1/iptstate.1 $(MAN)/man1/iptstate.1

clean:
	/bin/rm -rf iptstate


uninstall:
	/bin/rm -rf $(SBIN)/iptstate

