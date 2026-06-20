# IPTState Changelog

## 2.3.0 (2026-06-20)

- Makefile: respect LDFLAGS, CPPFLAGS
- Makefile: use pkg-config
- Add CI to the repo
- Cleanup table entries on all exit possibilities
- Don't leak entries when using filters
- Update CI to prevent supply-chain attacks
- Handle window size even when pipes on stdin/stdnout/stderr
- Fix compiler warnings

## 2.2.7 (2021-10-16)

- Fix compiler warnings

## 2.2.6 (2016-08-14)

- Fix `-b` option which didn't work in many cases
- When we turn `lookup` mode on, automatically turn `skipdns` mode on
- Move to dynamic memory for state entries. Fixes #3

## 2.2.5 (2012-06-02)

- Full support for ICMP6 including code/type display and state deletion
- Dynamically size "State" column
- If we can't resolve a protocol to a name, print the number instead of
  "UNKNOWN!"
- Don't leave a space for ":" if there's no port

## 2.2.4 (2012-06-01)

- Improved IPv6 support - truncate addresses if they don't fit and
  generally treat them like hostnames at display time
- CONTRIB and man page fixes (Chris Taylor <ctaylor@debian.org>)

## 2.2.3 (2011-04-04)

- IPv6 support. Closes #2848930.
- Handle filters as in6_addr and uints instead of strings
- Fix loopback filtering support
- Fix formatting for ICMP states. Closes #2969917.
- Total style overhaul: move away from tabs, use 2 spaces, various
  other style cleanups
- Documentation updates

## 2.2.2 (2009-09-19)

- Fix includes
- Add --version (closes bug 2792918)
- Some minor code abstractions
- Remove old /proc based code
- Dropped "Proto" field minimum width to 3 chars (changing title to
  "Prt") to make more room for counters
- If we can't fit counters and there's nothing we can truncate, show a
  warning and then disable counters rather than messing up the display
- Some style cleanups

## 2.2.1 (2007-03-19)

- Fix formatting bug (maxes not being cleared on each round)

## 2.2.0 (2007-03-19)

- Added some logic to handle state tables larger than 32767 entries
  which breaks ncurses if you try to make a pad that large.
- Cleanup the time.h includes
- Port to new libnetfilter_conntrack library
- Add support for byte/packet counters ('C' key)
- Add support for deleting states ('x' key)
- Move navigation help to top of interactive help so people can learn
  how to navigate without having to navigate to the bottom of the help
- When --lookup is enabled, resolve port names as well as hostnames
  (reported by Viliam Holub <holub@nenya.ms.mff.cuni.cz>)
- Display the ICMP ID on ICMP states
- Fix scrolling bug if totals or filters were enabled
- General improvement of all scrolling calculations
- Add 'B' as a way to sort by previous column (opposite of 'b')
- Add ^d for pagedown and ^u for pageup

## 2.1 (2006-10-05)

- Fixed bug where -s was doing what -S should do and -d was doing
  what -D should do. Thanks to Brian Nelson for catching this.
- Add comments on the 3 functions that didn't have them in 2.0

## 2.0 (2006-10-04)

- Moved man page to section 8
- Significantly re-factored code
- Fix long-protocol-names-break-formatting bug (reported by Bill
  Hudacek <hudaceks@verizon.net>)
- Move all flag bools into a new flags_t struct
- Move format-decisions to end
- Move all counters into a new counters_t struct
- Make the stable vector dynamic instead of a huge pre-allocation
- Move many variables to #defines
- Fix bug in "totals" line (numbers didn't always add up)
- Add display of skipped entries on "totals" line
- Move various char*'s to strings.
- Move most snprintf()s to stringstreams.
- Rewrite and significantly improve dynamic sizing of columns
- Add a new interactive help window
- Add srcpt and dstpt filtering
- Add long options
- Make interactive help scroll-able
- Make main window scroll-able
- Make having the main window be scrollable configurable and if not
  scrollable then use stdscr instead of a pad. Make this togglable
  interactively.
- Redo command-line options so they match interactive options
- Add ability to change all filters and the refresh rate interactively
- Handle window resizes (SIGWINCH) properly
- If we can't read ip_conntrack, error and exit rather than fail
  silently
- Cleanup nicely if we get killed (SIGINT or SIGTERM)
- Add color-coding of protocols

## 1.4 (2005-04-16)

- Added display of filters
- Added a "strip" target to the Makefile
- Changed ip/port separator to a colon instead of comma
- Some string concat and Makefile cleanups from Roland Illig
- Added new features to man page
- Added filtering for source and destination addresses
- Added filtering of DNS states option
- Added tagging of truncated hostnames
- Brought man page up-to-date
- Got rid of deprecated warnings
- Removed libgpm req from spec file.

## 1.3 (2003-05-27)

- Steve Augart finally proved the 'memory leak' was in ncurses as I'd
  always suspected but was unable to prove. Thanks Steve!
- Increased snprintf boundaries in printline function to ensure
  newlines don't get cut off (Thanks to Todd Lyons)
- Added dynamic sizing of iptstate based on term info.
- Updated Makefile to only recompile if needed
- Fixed gethostbyaddr() call to compile on more systems
- Fixed truncation bug that occasionally truncated one char too few
- Added NOTES section to man page, plus other docs on new features
- Fixed some man page bugs

## 1.2.1 (2002-07-01)

- Fixes for GCC3
   - cast 'x' in 'log' so GCC knows which log I mean
   - add -Wno-deprecated to Makefile
- Fix small bug in manpage that made -R not show up
- Fix crash if protocol is not found in /etc/protocols
- Update 'uninstall' in Makefile

## 1.2.0 (2002-04-20)

- Various doc updates
- Lots of code cleanups
- Added documentation for interactive-mode options
- Added interactive-mode toggles for -f -t -l
- Added option to display totals
- Added filtering of loopback
- Added sorting by hostname
- Added DNS hostname lookups
- Improved SrcIP and DstIP sorting
- Added sorting by port

## 1.1.0 (2002-03-30)

- Will now read in all connections instead of just 50; for single-line
  use, it will display them all as well.
- Added command line flag for reverse sorting
- Cleaned up reading of options
- Fixed sorting of TTL / cleaned up sorting code
- Fixed uninstall in Makefile

## 1.0.1 (2002-02-27)

- Added spec file so people can build RPMs if they like
- Fix 'timeval' compile error for certain platforms
- Take out src port and dst port for non tcp,udp cases
- Give 'rate' an initial value
- Fixed Big Endian Problem with command line arguments
- Fixed Makefile (put LIBS at end)
- Change "proto" field to look up by protocol number field of
  ip_conntrack instead of take it from the name field, supporting
  pretty much any protocol

## 1.0 (2002-02-23)

- Original release
