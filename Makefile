#
# Copyright (C) 2002 - 2007 Phil Dibowitz.
#
# See iptstate.cc for copyright info
#
# Makefile for IPTState
#

### USERS CAN CHANGE STUFF HERE

PREFIX?=/usr
SBIN?=$(PREFIX)/sbin
INSTALL?=/usr/bin/install
STRIP?=/usr/bin/strip
MAN?=$(PREFIX)/share/man

### ADVANCED USERS AND PACKAGERS MIGHT WANT TO CHANGE THIS

CXX?= g++
CXXFLAGS?= -g -Wall -O2
CXXFILES?= iptstate.cc

# THIS IS FOR NORMAL COMPILATION
LIBS?= -lncurses -lnetfilter_conntrack
CPPFLAGS=

### YOU SHOULDN'T NEED TO CHANGE ANYTHING BELOW THIS

all:	iptstate


iptstate: iptstate.cc Makefile
	@\
	echo "+------------------------------------------------------------+" ;\
	echo "| Welcome to IP Tables State by Phil Dibowitz                |" ;\
	echo "|                                                            |" ;\
	echo "| PLEASE read the LICENSE and the README for important info. |" ;\
	echo "|                                                            |" ;\
	echo "| You may also wish to read the README for install info,     |" ;\
	echo "| the WISHLIST for upcoming features, BUGS for known bugs    |" ;\
	echo "| and info on bug reports, and the Changelog to find out     |" ;\
	echo "| what's new.                                                |" ;\
	echo "|                                                            |" ;\
	echo "| Let's compile...                                           |" ;\
	echo "+------------------------------------------------------------+" ;\
	echo "";

	$(CXX) $(CXXFLAGS) $(CXXFILES) -o iptstate $(LIBS) $(CPPFLAGS)
	@touch iptstate

	@\
	echo "" ;\
	echo "All done. Do 'make install' as root and you should be set to go!" ;\
	echo ""

strip:	iptstate
	$(STRIP) iptstate
	@touch strip


install:
	$(INSTALL) -D --mode=755 iptstate $(SBIN)/iptstate
	$(INSTALL) -D --mode=444 iptstate.8 $(MAN)/man8/iptstate.8


clean:
	/bin/rm -rf iptstate
	/bin/rm -rf strip


uninstall:
	/bin/rm -rf $(SBIN)/iptstate
	/bin/rm -rf $(MAN)/man1/iptstate.1
	/bin/rm -rf $(MAN)/man8/iptstate.8

