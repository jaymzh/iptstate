# IP Tables State (iptstate)

Please see the LICENSE file for license information.

## WHAT IS IP TABLES STATE?

IP Tables State (iptstate) was originally written to implement the "state top"
feature of IP Filter (see "The Idea" below) in IP Tables. "State top" displays
the states held by your stateful firewall in a top-like manner.

Since IP Tables doesn't have a built in way to easily display this information
even once, an option was added to just have it display the state table once.
 
Features include:
* Top-like realtime state table information
* Sorting by any field
* Reversible sorting
* Single display of state table
* Customizable refresh rate
* Display filtering
* Color-coding
* Open Source (specifically I'm using the zlib license)
* much more...
	
## PRE-INSTALATION

Make sure you have some version of curses installed (for most users this is
probably ncurses). Note that if you are using vendor packages you will most
likely need the packaged with '-dev' on the end of of it (i.e. ncurses-dev).

Starting with version 2.2.0 you also need libnetfilter_conntrack version 0.0.50
or later. These libraries also require nf_conntrack_netlink and nfnetlink
support in your kernel.

## INSTALLATION

### The quick version:

For most people the following should do all you need:

    make
    make install # this must be done as root

### The long version:

#### Configuration

The program is only one c++ source file, so the compile is very simple. For
this reason there is no config file.  The defaults in the Makefile should be
fine, but if you want to change something you can change where iptstate gets
installed by changing the "SBIN" variable in your environment. I can't imagine
a reason but if you have 'install' installed in a weird place change the
INSTALL variable in your environment. Other than that nothing should need
tweaking. Obviously advanced users may wish to do other stuff, but we'll leave
that as an excersize to the reader.

#### Compiling

The compiling should be as simple as running 'make.' If this doesn't work, feel
free to drop me an email, BUT MAKE SURE you put "IPTSTATE:" in the subject. In
the email include: Distribution, kernel version, make version, gcc version,
libc version, and the error messages.

Package maintainers may wish to override CXXFLAGS, and can do so like so:

    # CXXFLAGS=-O3 make

and/or use "make strip" which will build iptstate and then strip it.

If you get errors like:

    iptstate.cc:286: passing `in_addr *' as argument
    1 of `gethostbyaddr(const char *, size_t, int)'

then you need to upgrade your glibc. This is an important thing to keep
up-to-date anyway.

#### Installing

IPTState installs in /usr/sbin. This is because it should be a utility for the
superuser. You need root access (or CAP_NET_ADMIN) for iptstate to get the data
it needs anyway.  Installing should be as simple as 'make install' as root. If
this fails, feel free to do:

    # cp iptstate /usr/sbin/iptstate
    # chmod 755 /usr/sbin/iptstate
    # chown root:bin /usr/sbin/iptstate
    # cp iptstate.8 /usr/share/man/man8/iptstate.8
    # chmod 444 /usr/share/man/man1/iptstate.8

And that should do it. If 'make install' fails feel free to drop me an email
provided you put "IPTSTATE:" in the subject. Please see the BUGS file on how to
send proper bug reports.

## USAGE

IPTables State is extremely simple to use. Most of the time what you'll want is
just the command 'iptstate' as root. This will launch you into the 'statetop'
mode. In here, your state table is being sorted by Source IP. To change the
sorting, on the fly, type 'b.' This will rotate through the various sorting
possibilities. You can quit by typing 'q.' You can also change the sorting with
the -b ("sort BY") option. The -b option takes d (Destination IP), D
(Destination Port), S (Source IP), p (protocol), s (state), and t (TTL) as it's
possible options.  To sort by Source IP, just don't specify -b.

You can also change the refresh rate of the statetop by -R followed by an
integer. The integer represents the refresh rate in seconds.

To get help, hit 'h' from withint iptstate, or run iptstate with the '--help'
option.

To get a quick look at what's going across your firewall, try iptstate -1. This
is "single run" mode. It will just print out your state table at the moment you
requested it. This is where -b comes in handy. Again, the default sort is by
Source IP.

NOTE WELL: This is not meant to be a comprehensive guide. There are many other
features - check the man page, the -h option, and the interactive help page
within iptstate for more information. But this should give you the basics.

## DESIRED FEATURES

There is a list of features I plan and don't plan to implement in the WISHLIST
file.

## THE IDEA

The idea of statetop comes from IP Filter by Darren Reed.

This package's main purpose is to provide a state-top type interface for IP
Tables. I've added in the "single run" option since there's no nice way to do
that with IP Tables either.

## THE AUTHOR

IPTState was written by me, Phil Dibowitz. My day job is large-scale system
administration and automation. Outside of work I maintain several open source
projects. You can find out more about me at http://www.phildev.net/

Phil Dibowitz
phil AT ipom DOT com
