#
# Copyright (C) 2002 - 2006 Phil Dibowitz.
#
# See iptstate.cc for copyright info
#
# Makefile for IPTState verion 2.1
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
LIBS?= -lncurses -lnetfilter_conntrack
OLDLIBS?= -lncurses

### YOU SHOULDN'T NEED TO CHANGE ANYTHING BELOW THIS

all:	iptstate


.make.welcome:
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

	@touch .make.welcome

iptstate:	.make.welcome iptstate.cc

	$(CXX) $(CXXFLAGS) $(CXXFILES) -o iptstate $(LIBS)
	@touch iptstate

	@\
	echo "" ;\
	echo "All done. Do 'make install' as root and you should be set to go!" ;\
	echo ""

iptstate_proc: .make.iptstate_proc

.make.iptstate_proc: welcome iptstate.cc
	@\
	echo "WARNING: You are compiling iptstate to use the /proc interface" ;\
	echo "	to netfilter. This is deprecated and will be removed from" ;\
	echo "	later versions of the code!" ;\
	echo ""

	$(CXX) $(CXXFLAGS) $(CXXFILES) -o iptstate $(OLDLIBS) -DIPTSTATE_USE_PROC
	@touch .make.iptstate_proc

	@\
	echo "" ;\
	echo "All done. Do 'make install' as root and you should be set to go!" ;\
	echo ""

strip:	iptstate
	$(STRIP) iptstate
	@touch .strip


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

