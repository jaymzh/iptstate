# IP Tables State - The leak

Back on April 3, 2002, Casey Webster submitted a [Debian Bug
Report](http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=141044&repeatmerged=yes)
about a memory leak he found in IPTState. There was certainly a leak SOMEWHERE,
because when he ran it, it increasingly ate up memory. But looking over my code
I used no dynamic data structures.

I started researching and for a small amount of time thought it was a bug in
libc... but it turned out that wasn't true. I then found increasing evidence
the bug was in ncurses... but nothing hard. I could never prove it. This was a
function of my own shortcomings.

On October 26, 2002, my Debian Maintainer, Brian Nelson emailed me to tell me
that Debian was doing a purge. At the end of the week all software with
outstanding bugs would be kicked out -- and IPTState was on the list. "Oh
Crap!" I thought. This is perhaps the busiest month I'd ever had. I didn't have
time to figure this out, I'd already put several hours into it and come up with
nothing.

Being open source software I called for help. I asked everyone at UUASC and
USCLUG to do what they could. I even asked for help from the author of Valgrind
who agreed to help. And many people started looking into it! A huge thanks goes
out to all of you.

On October 28, 2002, at 12:47am, Steve Augart emailed me with his findings:

```
Date: Mon, 28 Oct 2002 00:47:29 -0800
From: Steven Augart <steve@ugart.com>
To: Brian Nelson <bnelson@bloodclot.net>
Cc: Phil Dibowitz <phil@ipom.com>
Subject: Re: iptstate in debian

Well, I've been over it (my God, has it really been two and half hours
that I spent?) and it's a bug in ncurses.

If someone wants to look at it, ftp to ftp.augart.com and grab the two
tar files in the directory iptstate. That contains the debugging versions
I built, specifically:

I made a new version, called "iptstate-castrated.cc".  It takes a new flag,
-N, which means to not use Curses (kind of like -s, but not just running
once).  If you run it with -r 0 (meaning to never pause) and -N, you'll find
that the image never ever bloats.

Since the ncurses calls all look legitimate, it must be a bug in that interface.
I watched the # of allocated blocks go up during a long run of it.  So, every
so often ncurses must lose a memory block.

I've attached a shred-malloc trace.  You'll see that it initially is at
239/240 allocated blocks, and goes up to 240/241 around the 230th iteration.
(I generated the trace by redirecting stderr to memuse.out).

You can generate a similar trace easily by running iptstate-castrated with -r 0
and redirecting stderr to a file.

The shred_malloc package is also there, in libSAugart-advanced.tar.gz.

It's already all compiled under SuSE Linux 8.0 (glibc 2.2.5, g++ 2.95.3).

Just because it's a bug in ncurses doesn't mean that the debian folks
are going to be willing to give iptstate a break.  I would recommend
building ncurses with -ggdb3 and running one of the memory debuggers
you tried, one that lists what blocks are allocated and from where.  Get a
dump after 10 iterations or so.

Then run iptstate again with -r 0 and get a dump after about 2000 iterations.
Compare the two.

Anyway, that's what I found.
Please forward this note to the other maintainers.
```

You can find the output he mentions at [memuse.out](memuse.out).

As he said in the letter you can find his modified source, as well as his memory debugging software in the iptstate directory of [ftp.augart.com](ftp://ftp.augart.com/iptstate/).

In conclusion, this seems to be a bug in ncurses. My software does not leak when it doesn't use ncuses, but leaks very slowly when using ncurses. Brian hopefully will be notifying the ncurses maintainers as well as closing this bug - and iptstate should be able to stay in Debian (and hopefully move into testing).

With that I'd like to say special thanks to Steve Augart, Julian Seward, Todd Lyons, and **everyone** at UUASC and USCLUG who pitched in to help out. There were many of you, and I will try and add more names to this list, but for now I'm trying to post it before I fall asleep. But know that even if you tried, and didn't find anything and thus didn't email me, I still appreciate your effort.
