#
# Copyright (C) 2002 Phil Dibowitz.
#
# See iptstate.cc for copyright info
#
# Makefile for IPTState verion 1.0.1
#

### USERS CAN CHANGE STUFF HERE

PREFIX=/usr
SBIN=$(PREFIX)/sbin
INSTALL=/usr/bin/install

### YOU SHOULD NOT NEED TO CHANGE ANYTHING BELOW HERE

CXXFLAGS = -g -Wall
OBJS = iptstate.cc
LIBS= -lncurses


all:
	@echo "+-----------------------------------------------------------+"
	@echo "| Welcome to IP Tables State by Phil Dibowitz               |"
	@echo "|                                                           |"
	@echo "| PLEASE read the License in the README                     |"
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
	$(INSTALL) --mode=755 iptstate $(SBIN)/iptstate


clean:
	/bin/rm -rf iptstate


uninstall:
	/bin/rm -rf /usr/sbin/iptstate

