/*
 * vim:textwidth=78:
 *
 * iptstate.cc
 * IPTables State
 *
 * -----------------------------------
 *
 * Copyright (C) 2002 - 2007 Phil Dibowitz
 *
 * This software is provided 'as-is', without any express or
 * implied warranty. In no event will the authors be held
 * liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any
 * purpose, including commercial applications, and to alter it
 * and redistribute it freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you
 * must not claim that you wrote the original software. If you use
 * this software in a product, an acknowledgment in the product
 * documentation would be appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and
 * must not be misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source
 * distribution.
 *
 * -----------------------------------
 *
 * The idea of statetop comes from IP Filter by Darren Reed.
 *
 * This package's main purpose is to provide a state-top type
 * interface for IP Tables. I've added in the "single run"
 * option since there's no nice way to do that either.
 *
 * NOTE: IF YOU WANT TO PACKAGE THIS SOFTWARE FOR A 
 * LINUX DISTRIBUTION, CONTACT ME!
 *
 */ 

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdlib.h>
#include <ncurses.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <math.h>
#ifndef IPTSTATE_USE_PROC
extern "C" {
	#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
};
#else
	#warning "Compiling in backwards compatability proc mode. This is DEPRECATED and support for this will be removed in the future!"
	#define CONNTRACK "/proc/net/ip_conntrack"
#endif
using namespace std;

#define VERSION "2.2.0"
/* #define CONNTRACK "/proc/net/ip_conntrack" */
/*
 * MAXCONS is set to 16k, the default number of states in iptables. Generally
 * speaking the ncurses pad is this many lines long, but since ncurses
 * uses a short for their dimensions, a pad can never be longer than 32767.
 * Thus we define both of these values and NLINES as the lesser of the two.
 */
#define MAXCONS 16384
#define MAXLINES 32767
#if MAXCONS < MAXLINES
  #define NLINES MAXCONS
#else
  #define NLINES MAXLINES
#endif
#define MAXFIELDS 20
// This is the default format string if we don't dynamically determine it
#define DEFAULT_FORMAT "%-21s %-21s %-7s %-12s %-9s\n"
// The following MUST be the same as the above
#define DEFAULT_SRC 21
#define DEFAULT_DST 21
#define DEFAULT_PROTO 7
#define DEFAULT_STATE 12
#define DEFAULT_TTL 9
// This is the format string for the "totals" line, always.
#define TOTALS_FORMAT \
	"Total States: %i -- TCP: %i UDP: %i ICMP: %i Other: %i (Filtered: %i)\n"
// Options for truncating from the front or the back
#define TRUNC_FRONT 0
#define TRUNC_END 1
// Sorting options
#define SORT_SRC 0
#define SORT_SRC_PT 1
#define SORT_DST 2
#define SORT_DST_PT 3
#define SORT_PROTO 4
#define SORT_STATE 5
#define SORT_TTL 6
#ifndef IPTSTATE_USE_PROC
  #define SORT_BYTES 7
  #define SORT_PACKETS 8
  // This should ALWAYS the same as the above.
  #define SORT_MAX 8
#else
  // This should ALWAYS the same as the above.
  #define SORT_MAX 6
#endif

/*
 * GLOBAL CONSTANTS
 */

/*
 * GLOBAL VARS
 */
int sort_factor = 1;
bool need_resize = false;

#ifndef IPTSTATE_USE_PROC
/* shameless stolen from libnetfilter_conntrack_tcp.c */
static const char *states[] = {
        "NONE",
        "SYN_SENT",
        "SYN_RECV",
        "ESTABLISHED",
        "FIN_WAIT",
        "CLOSE_WAIT",
        "LAST_ACK",
        "TIME_WAIT",
        "CLOSE",
        "LISTEN"
};
#endif

/*
 * STRUCTS
 */
// One state-table entry
struct table_t {
	string proto, state, ttl, sname, dname, spname, dpname;
	in_addr src, dst;
	int srcpt, dstpt, bytes, packets;
};
// x/y of the terminal window
struct screensize_t {
	unsigned int x, y;
};
// Struct 'o flags
struct flags_t {
	bool single, totals, lookup, skiplb, staticsize, skipdns, tag_truncate,
	     	filter_src, filter_dst, filter_srcpt, filter_dstpt, noscroll,
		nocolor, counters;
};
// Struct 'o counters
struct counters_t {
	int total, tcp, udp, icmp, other, skipped;
};
// Various filters to be applied pending the right flags in flags_t
struct filters_t {
	string src, dst, srcpt, dstpt;
};
// The max-length of fields in the stable table
struct max_t {
	unsigned int src, dst, proto, state, ttl, bytes, packets;
};
#ifndef IPTSTATE_USE_PROC
struct hook_data {
	vector<table_t> *stable;
	flags_t *flags;
	max_t *max;
	counters_t *counts;
	const filters_t *filters;
};
#endif

/*
 * FUNCTIONS
 */

// Core functions
void build_table(flags_t &flags, const filters_t &filters,
		vector<table_t> &stable, counters_t &counts,
		max_t &max);
#ifndef IPTSTATE_USE_PROC
int conntrack_hook(enum nf_conntrack_msg_type nf_type, struct nf_conntrack *ct,
			void *tmp);
void delete_state(WINDOW *&win, const table_t &entry, const flags_t &flags);
#endif
void sort_table(const int &sortby, const bool &lookup, const int &sort_factor,
		vector<table_t> &stable, string &sorting);
void print_table(vector<table_t> &stable, const flags_t &flags,
		const string &format, const string &sorting,
		const filters_t &filters, const counters_t &counts,
		const screensize_t &ssize, const max_t &max,
		WINDOW *mainwin, unsigned int &curr);
void determine_format(max_t &max, screensize_t &ssize, string &format,
		const flags_t &flags);
void interactive_help(const string &sorting, const flags_t &flags,
		const filters_t &filters);
void printline(table_t &table, const flags_t &flags, const string &format,
		const max_t &max, WINDOW *mainwin, const bool curr);

// General helper functions
void split(char s, string line, string &p1, string &p2);
void splita(char s, string line, vector<string> &result);
unsigned int digits(int x);
bool check_ip(const char *arg);
void help();
void resolve_names(table_t &entry, max_t &max);
void resolve_host(const in_addr &ip, string &name);
void resolve_port(const int &port, string &name, const string &proto);
void truncate(table_t &table, const max_t &max, const flags_t &flags);
void winch_handler(int sig);
void kill_handler(int sig);
void initialize_maxes(max_t &max, flags_t &flags);

// Sort functions
int src_sort(const void *a, const void *b);
int dst_sort(const void *a, const void *b);
int srcpt_sort(const void *a, const void *b);
int dstpt_sort(const void *a, const void *b);
int proto_sort(const void *a, const void *b);
int state_sort(const void *a, const void *b);
int ttl_sort(const void *a, const void *b);
int sname_sort(const void *a, const void *b);
int dname_sort(const void *a, const void *b);
int bytes_sort(const void *a, const void *b);
int packets_sort(const void *a, const void *b);

// Curses helper functionsr
static WINDOW* start_curses(flags_t &flags);
void end_curses();
screensize_t get_size(const bool &single);
void term_too_small();
void switch_scroll(flags_t &flags, WINDOW *&mainwin);
void get_input(WINDOW *win, string &input, const string &prompt,
		const flags_t &flags);
void c_warn(WINDOW *win, const string &warning, const flags_t &flags);
void handle_resize(WINDOW *&win, const flags_t &flags, screensize_t &ssize);


/*
 * MAIN
 */
int main(int argc, char *argv[])
{

// Variables
string line, src, dst, srcpt, dstpt, proto, code, type, state, ttl, mins, secs,
       hrs, sorting, tmpstring, format, prompt;
ostringstream ostream;
vector<table_t> stable;
int tmpint = 0, sortby = 0, rate = 1, hdrs = 0;
unsigned int py = 0, px = 0, curr_state = 0;
timeval selecttimeout;
fd_set readfd;
flags_t flags;
counters_t counts;
screensize_t ssize;
filters_t filters;
max_t max;

/*
 * Initialize
 */
flags.single = flags.totals = flags.lookup = flags.skiplb = flags.staticsize
	= flags.skipdns = flags.tag_truncate = flags.filter_src
	= flags.filter_dst = flags.filter_srcpt = flags.filter_dstpt
	= flags.noscroll = flags.nocolor = flags.counters = false;
ssize.x = ssize.y = 0;
counts.tcp = counts.udp = counts.icmp = counts.other = counts.skipped = 0;
filters.src = filters.dst = filters.srcpt = filters.dstpt = "";
max.src = max.dst = max.proto = max.state = max.ttl = 0;
px = py = 0;

static struct option long_options[] = {
#ifndef IPTSTATE_USE_PROC
	{"counters", no_argument , 0, 'C'},
#endif
	{"dst-filter", required_argument, 0, 'd'},
	{"dstpt-filter", required_argument, 0, 'D'},
	{"help", no_argument, 0, 'h'},
	{"lookup", no_argument, 0, 'l'},
	{"mark-truncated", no_argument, 0, 'm'},
	{"no-color", no_argument, 0, 'c'},
	{"no-dynamic", no_argument, 0, 'o'},
	{"no-dns", no_argument, 0, 'L'},
	{"no-loopback", no_argument, 0, 'f'},
	{"no-scroll", no_argument, 0, 'p'},
	{"rate", required_argument, 0, 'R'},
	{"reverse", no_argument, 0, 'r'},
	{"single", no_argument, 0, '1'},
	{"sort", required_argument, 0, 'b'},
	{"src-filter", required_argument, 0, 's'},
	{"srcpt-filter", required_argument, 0, 'S'},
	{"totals", no_argument, 0, 't'},
	{0,0,0,0}
};
int option_index = 0;

// Command Line Arguments
#ifndef IPTSTATE_USE_PROC
while ((tmpint = getopt_long(argc,argv,"Cd:D:hlmcoLfpR:r1b:s:S:t",long_options,
				&option_index)) != EOF) {
#else
while ((tmpint = getopt_long(argc,argv,"d:D:hlmcoLfpR:r1b:s:S:t",long_options,
				&option_index)) != EOF) {
#endif
	switch (tmpint) {
		case 0:
			/* Apparently this test is needed?! Seems lame! */
			if (long_options[option_index].flag != 0)
				break;

			/*
			 * Long-only options go here, like so:
			 *
			 *   tmpstring = long_options[option_index].name;
			 *   if (tmpstring == "srcpt-filter") {
			 *	  ...
			 *   } else if (...) {
			 *	  ...
			 *   }
			 *
			 */

			break;
#ifndef IPTSTATE_USE_PROC
		// --counters
		case 'C':
			flags.counters = true;
			break;
#endif
		// --dst-filter
		case 'd':
			if (optarg == NULL)
				break;
			// See check_ip() note above
			if (!check_ip(optarg)) {
				cerr << "Invalid IP address: " << optarg
					<< endl;
				exit(1);
			}
			flags.filter_dst = true;
			filters.dst = optarg;
			break;
		// --dstpt-filter
		case 'D':
			/*
			 * even though this won't be an IP address
			 * aton() won't complain about anything that's
			 * just digits, so it's an easy check.
			 */
			if (optarg == NULL)
				break;
			if (!check_ip(optarg)) {
				cerr << "Invalid IP address: " << optarg
					<< endl;
				exit(1);
			}
			flags.filter_dstpt = true;
			filters.dstpt = optarg;
			break;
		// --help
		case 'h':
			help();
			break;
		// --lookup
		case 'l':
			flags.lookup = true;
			break;
		// --mark-truncated
		case 'm':
			flags.tag_truncate = true;
			break;
		// --color
		case 'c':
			flags.nocolor = false;
			break;
		// --no-dynamic
		case 'o':
			flags.staticsize = true;
			break;
		// --no-dns
		case 'L':
			flags.skipdns = true;
			break;
		// --no-loopback
		case 'f':
			flags.skiplb = true;
			break;
		// --no-scroll
		case 'p':
			flags.noscroll = true;
			break;
		// --reverse
		case 'r':
			sort_factor = -1;
			break;
		// --rate
		case 'R':
			rate = atoi(optarg);
			break;
		// --sort
		case 'b':
			if (*optarg == 'd')
				sortby=SORT_DST;
			else if (*optarg == 'D')
				sortby=SORT_DST_PT;
			else if (*optarg == 'S')
				sortby=SORT_SRC_PT;
			else if (*optarg == 'p')
				sortby=SORT_PROTO;
			else if (*optarg == 's')
				sortby=SORT_STATE;
			else if (*optarg == 't')
				sortby=SORT_TTL;
#ifndef IPTSTATE_USE_PROC
			else if (*optarg == 'b')
				sortby=SORT_BYTES;
			else if (*optarg == 'P')
				sortby=SORT_PACKETS;
			if (!flags.counters)
				sortby=SORT_SRC;
#endif
			break;
		// --single
		case '1':
			flags.single = true;
			break;
		// --src-filter
		case 's':
			if (optarg == NULL)
				break;
			if (!check_ip(optarg)) {
				cerr << "Invalid IP address: " << optarg
					<< endl;
				exit(1);
			}
			flags.filter_src = true;
			filters.src = optarg;
			break;
		// --srcpt-filter
		case 'S':
			if (optarg == NULL)
				break;
			if (!check_ip(optarg)) {
				cerr << "Invalid IP address: " << optarg
					<< endl;
				exit(1);
			}
			flags.filter_srcpt = true;
			filters.srcpt = optarg;
			break;
		// --totals
		case 't':
			flags.totals = true;
			break;
		// catch-all
		default:
			// getopts should already have printed a message
			exit(1);
	}
}

if (rate < 0 || rate > 60) {
	rate = 1;
}

// Initialize Curses Stuff
static WINDOW *mainwin = NULL;
if (!flags.single) {
	mainwin = start_curses(flags);
	keypad(mainwin,true);
}

// Initialize the max-size structure
initialize_maxes(max, flags);

/*
 * We want to keep going until the user stops us 
 * unless they use single run mode
 * in which case, we'll deal with that down below
 */
while(1) {

	/*
	 * We get the screensize_t up-front so we can die if the screen doesn't
	 * meet our minimum requirements without making the user wait while
	 * we gather and process all the data. We'll do it again afterwards
	 * just in case
	 */

	ssize = get_size(flags.single);

	if (ssize.x < 72) {
		term_too_small();
	}

	// And our header size
	hdrs = 3;
	if (flags.totals) {
		hdrs++;
	}
	if (flags.filter_src || flags.filter_dst || flags.filter_srcpt
	    || flags.filter_dstpt) {
		hdrs++;
	}

	// Build our table
	build_table(flags,filters,stable,counts,max);

	/*
	 * Now that we have the new table, make sure our page/cursor positions
	 * still make sense.
	 */
	if (curr_state > stable.size()-1) {
		curr_state = stable.size()-1;
	}

	/*
	 * The bottom of the screen is stable.size()+hdrs+1
	 *   (the +1 is so we can have a blank line at the end)
	 * but we want to never have py be more than that - ssize.y
	 * so we're showing a page full of states.
	 */
	int bottom = stable.size()+hdrs+1-ssize.y;
	if (bottom < 0)
		bottom = 0;
	if (py > (unsigned)bottom)
		py = bottom;

	/*
	 * Originally I strived to do this the "right" way by calling
	 * nfct_is_set(ct, ATTR_ORIG_COUNGERS) to determine if counters
	 * were enabled. BUT, if counters are not enabled, nfct_get_attr()
	 * returns NULL, so this test is just as valid.
	 *
	 * Conversely checking is_set and then get_attr() inside our callback
	 * is twice the calls per-state if they are enabled, for no additional
	 * benefit.
	 */
	if (flags.counters && stable[0].bytes == 0) {
		prompt = "Counters requested, but not enabled in the kernel!";
		flags.counters = 0;
		c_warn(mainwin,prompt,flags);
	}

	// Sort our table
	sort_table(sortby,flags.lookup,sort_factor,stable,sorting);

	/*
	 * From here on out 'max' is no longer "the maximum size of this field
	 * throughout the table", but is instead the actual size to print each
	 * field.
	 *
	 * BTW, we do "get_size" again here incase the window changed while we
	 * were off parsing and sorting data.
	 */
	determine_format(max,ssize,format,flags);

	/*
	 * Now we print out the table in whichever format we're configured for
	 */
	print_table(stable,flags,format,sorting,filters,counts,ssize,max,
			mainwin,curr_state);

	// Exit if we're only supposed to run once
	if (flags.single)
		exit(0);

	// Otherwise refresh the curses display
	if (flags.noscroll) {
		refresh();
	} else {
		prefresh(mainwin,py,px,0,0,ssize.y-1,ssize.x-1);
	}

	//check for key presses for one second
	//or whatever the user said
	selecttimeout.tv_sec = rate;
	selecttimeout.tv_usec = 0;
	// I don't care about fractions of seconds. I don't want them.
	FD_ZERO(&readfd);
	FD_SET(0, &readfd);
	select(1,&readfd, NULL, NULL, &selecttimeout);
	if (FD_ISSET(0, &readfd)) {
		tmpint = wgetch(mainwin);
		switch (tmpint) {
			// This is ^L
			case 12:
				handle_resize(mainwin,flags,ssize);
				break;
			/*
			 * This is at the top because the rest are in
			 * order of longopts, and q isn't in longopts
			 */
			case 'q':
				goto out;
				break;
			/*
			 * General option toggles
			 */
			case 'c':
				/*
				 * we only want to pay attention to this
				 * command if colors are available
				 */
				if (has_colors())
					flags.nocolor = !flags.nocolor;
				break;
#ifndef IPTSTATE_USE_PROC
			case 'C':
				flags.counters = !flags.counters;
				if (sortby >= SORT_BYTES)
					sortby = SORT_BYTES-1;
				break;
#endif
			case 'h':
				interactive_help(sorting,flags,filters);
				break;
			case 'l':
				flags.lookup = !flags.lookup;
				break;
			case 'm':
				flags.tag_truncate = !flags.tag_truncate;
				break;
			case 'o':
				flags.staticsize = !flags.staticsize;
				break;
			case 'L':
				flags.skipdns = !flags.skipdns;
				break;
			case 'f':
				flags.skiplb = !flags.skiplb;
				break;
			case 'p':
				switch_scroll(flags,mainwin);
				break;
			case 'r':
				sort_factor = -sort_factor;
				break;
			case 'b':
				if (sortby < SORT_MAX) {
					sortby++;
#ifndef IPTSTATE_USE_PROC
					if (!flags.counters
					    && sortby >= SORT_BYTES)
						sortby = 0;
#endif
				} else {
					sortby = 0;
				}
				break;
			case 'B':
				if (sortby > 0) {
					sortby--;
				} else {
#ifndef IPTSTATE_USE_PROC
					if (flags.counters)
						sortby=SORT_MAX;
					else
						sortby=SORT_BYTES-1;
#else
					sortby=SORT_MAX;
#endif
				}
				break;
			case 't':
				flags.totals = !flags.totals;
				break;
			/*
			 * Update-filters
			 */
			case 'd':
				prompt = "New Destination Filter? (leave blank";
				prompt += " for none): ";
				get_input(mainwin,tmpstring,prompt,flags);
				if (tmpstring == "") {
					flags.filter_dst = false;
					filters.dst = "";
				} else {
					if (!check_ip(tmpstring.c_str())) {
						prompt = "Invalid IP,";
						prompt += " ignoring!";
						c_warn(mainwin,prompt,flags);
					} else {
						flags.filter_dst = true;
						filters.dst = tmpstring;
					}
				}
				break;
			case 'D':
				prompt = "New dstpt filter? (leave blank for";
				prompt += " none): ";
				get_input(mainwin,tmpstring,prompt,flags);
				if (tmpstring == "") {
					flags.filter_dstpt = false;
					filters.dstpt = "";
				} else {
					if (!check_ip(tmpstring.c_str())) {
						prompt = "Invalid IP,";
						prompt += " ignoring!";
						c_warn(mainwin,prompt,flags);
					} else {
						flags.filter_dstpt = true;
						filters.dstpt = tmpstring;
					}
				}
				wmove(mainwin,0,0);
				wclrtoeol(mainwin);
				break;
			case 'R':
				prompt = "Rate: ";
				get_input(mainwin,tmpstring,prompt,flags);
				if (tmpstring != "") {
					int i = atoi(tmpstring.c_str());
					if (i < 1) {
						prompt = "Invalid rate,";
						prompt += " ignoring!";
						c_warn(mainwin,prompt,flags);
					} else {
						rate = i;
					}
				}
				break;
			case 's':
				prompt = "New src filter? (leave blank for";
				prompt += " none): ";
				get_input(mainwin,tmpstring,prompt,flags);
				if (tmpstring == "")  {
					flags.filter_src = false;
					filters.src = "";
				} else {
					if (!check_ip(tmpstring.c_str())) {
						prompt = "Invalid IP,";
						prompt += " ignoring!";
						c_warn(mainwin,prompt,flags);
					} else {
						flags.filter_src = true;
						filters.src = tmpstring;
					}
				}
				wmove(mainwin,0,0);
				wclrtoeol(mainwin);
				break;
			case 'S':
				prompt = "New srcpt filter? (leave blank for";
				prompt += " none): ";
				get_input(mainwin,tmpstring,prompt,flags);
				if (tmpstring == "") {
					flags.filter_srcpt = false;
					filters.srcpt = "";
				} else {
					if (!check_ip(tmpstring.c_str())) {
						prompt = "Invalid IP,";
						prompt += " ignoring!";
						c_warn(mainwin,prompt,flags);
					} else {
						flags.filter_srcpt = true;
						filters.srcpt = tmpstring;
					}
				}
				wmove(mainwin,0,0);
				wclrtoeol(mainwin);
				break;
#ifndef IPTSTATE_USE_PROC
			case 'x':
				delete_state(mainwin, stable[curr_state], flags);
				break;
#endif
			/*
			 * Window navigation
			 */
			case KEY_DOWN:
			case 'j':
				if (flags.noscroll)
					break;
				/*
				 * GENERAL NOTE:
				 * py is the top of the window,
				 * ssize.y is the height of the window,
				 * so py+ssize.y is the bottom of the window.
				 *
				 * BOTTOM OF SCROLLING:
				 * Since stable.size()+hdrs+1 is
				 * the bottom of the text we've written, if
				 *    py+ssize.y == stable.size()+hdrs+1
				 * then the bottom of the screen as at the
				 * bottom of the text, no more scrolling.
				 *
				 * However, we only want to scroll the page
				 * when the cursor is at the bottom, i.e.
				 * when curr_state+4 == py+ssize.y
				 */

				/*
				 * If we have room to scroll down AND if cur is
				 * at the bottom of a page scroll down.
				 */
				if ((py + ssize.y <= stable.size()+hdrs+1)
				    && (curr_state+4 == py + ssize.y))
						py++;

				/*
				 * As long as the cursor isn't at the end,
				 * move it down one.
				 */
				if (curr_state < stable.size()-1)
					curr_state++;
				prefresh(mainwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			case KEY_UP:
			case 'k':
				if (flags.noscroll)
					break;

				/*
				 * This one is tricky.
				 *
				 * First thing we need to know is when the cursor
				 * is at the top of the page. This is simply when
				 * curr_state+hdrs+1 cursor location), is
				 * exactly one more than the top of the window
				 * (py), * i.e. when curr_state+hdrs+1 == py+1.
				 *
				 * PAGE SCROLLING:
				 * IF we're not page-scrolled all the way up
				 *    (i.e. py > 0)
				 *    AND the cursor is at the top of the page
				 * OR the cursor is at the top of the list,
				 *    AND we're not yet at the top (showing
				 *    the headers).
				 * THEN we scroll up.
				 *
				 * CURSOR SCROLLING:
				 * Unlike KEY_DOWN, we don't break just because
				 * the cursor can't move anymore - on the way
				 * ip we may still have page-scrolling to do. So
				 * test to make sure we're not at state 0, and if
				 * so, we scroll up.
				 */

				/*
				 * Basically:
				 *  IF the cursor bumps the top of the screen
				 *  OR we need to scroll up for headers
				 */
				if (  (py > 0 && (curr_state+hdrs+1) == (py+1))
				   || (curr_state == 0 && py > 0              ) )
					py--;

				if (curr_state > 0)
					curr_state--;
				prefresh(mainwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			// 4 is ^d
			case 4:
			case KEY_NPAGE:
			case KEY_SNEXT:
				if (flags.noscroll)
					break;
				/*
				 * If the screen is bigger than the text,
				 * and the cursor is at the bottom, ignore.
				 */
				if (stable.size()+hdrs+1 < ssize.y
				    && curr_state == stable.size())
					break;

				/*
				 * Otherwise, if the bottom of the screen
				 *    (current position + screen size
				 *     == py + ssize.y)
				 * were to go down one screen (thus:
				 *     py + ssize.y*2),
				 * and that is bigger than the whole pad, just
				 * go to the bottom.
				 *
				 * Otherwise, go down a screen size.
				 */
				if (py + ssize.y*2 > stable.size()+hdrs+1) {
					py = stable.size()+hdrs+1-ssize.y;
				} else {
					py += ssize.y;
				}

				/*
				 * For the cursor, we try to move it down one
				 * screen as well, but if that's too far,
				 * we bring it up to the largest number it can
				 * be.
				 */
				curr_state += ssize.y;
				if (curr_state > stable.size()) {
					curr_state = stable.size();
				}
				prefresh(mainwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			// 21 is ^u
			case 21:
			case KEY_PPAGE:
			case KEY_SPREVIOUS:
				if (flags.noscroll)
					break;
				/*
				 * If we're at the top, ignore
				 */
				if (py == 0 && curr_state == 0)
					break;
				/*
				 * Otherwise if we're less than a page from the
				 * top, go to the top, else go up a page.
				 */
				if (py < ssize.y) {
					py = 0;
				} else {
					py -= ssize.y;
				}

				/*
				 * We bring the cursor up a page too, unless
				 * that's too far.
				 */
				if (curr_state < ssize.y) {
					curr_state = 0;
				} else {
					curr_state -= ssize.y;
				}
				prefresh(mainwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			case KEY_HOME:
				if (flags.noscroll)
					break;
				px = py = curr_state = 0;
				prefresh(mainwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			case KEY_END:
				if (flags.noscroll)
					break;
				py = stable.size()+hdrs+1-ssize.y;
				if (py < 0)
					py = 0;
				curr_state = stable.size();
				prefresh(mainwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
		}
	}
	/*
	 * If we got a sigwinch, we need to redraw
	 */
	if (need_resize) {
		handle_resize(mainwin,flags,ssize);
		need_resize = false;
	}
} // end while(1)

out:

/*
 * The user has broken out of the loop, take down the curses
 */
end_curses();

// And we're done
return(0);

} // end main

/*
 * BEGIN FUNCTIONS
 */


/*
 * This is the core of this program - build a table of states.
 *
 * For the new libnetfilter_conntrack code, the bulk of build_table was moved
 * to the conntrack callback function.
 */

#ifndef IPTSTATE_USE_PROC
void build_table(flags_t &flags, const filters_t &filters,
		vector<table_t> &stable, counters_t &counts,
		max_t &max)
{

	/*
	 * Variables
	 */
	int res=0;
	vector<string> fields(MAXFIELDS);
	static struct nfct_handle *cth;
	u_int8_t family = AF_INET;

	/*
	 * This is the ugly struct for the nfct hook, that holds pointers to
	 * all of the things the callback will need to fill our table
	 */
	struct hook_data hook;
	hook.stable = &stable;
	hook.flags = &flags;
	hook.max = &max;
	hook.counts = &counts;
	hook.filters = &filters;

	/*
	 * Initialization
	 */
	stable.clear();
	counts.tcp = counts.udp = counts.icmp = counts.other = counts.skipped
		= 0;


	cth = nfct_open(CONNTRACK, 0);
	if (!cth) {
		end_curses();
		printf("ERROR: couldn't establish conntrack connection\n");
		exit(2);
	}
	nfct_callback_register(cth, NFCT_T_ALL, conntrack_hook, (void *)&hook);
	res = nfct_query(cth, NFCT_Q_DUMP, &family);
	if (res < 0) {
		end_curses();
		printf("ERROR: Couldn't retreive conntrack table: %s\n",
			strerror(errno));
		exit(2);
	}
	nfct_close(cth);

}

int conntrack_hook(enum nf_conntrack_msg_type nf_type, struct nf_conntrack *ct,
			void *tmp)
{

	/*
	 * start by getting our struct back
	 */
	struct hook_data *data = static_cast<struct hook_data *>(tmp);

	/*
	 * and pull out the pieces
	 */
	vector<table_t> *stable = data->stable;
	flags_t *flags = data->flags;
	max_t *max = data->max;
	counters_t *counts = data->counts;
	const filters_t *filters = data->filters;

	// our table entry
	table_t entry;

	// some vars
	struct protoent* pe = NULL;
	int seconds, minutes, hours;
	char ttlc[11];
	ostringstream typecode;

	/*
	 * Clear the entry
	 */
	entry.sname = "";
	entry.dname = "";
	entry.srcpt = 0;
	entry.dstpt = 0;
	entry.proto = "";
	entry.ttl = "";
	entry.state = "";

	/*
	 * First, we read stuff into the array that's always the
	 * same regardless of protocol
	 */

	pe = getprotobynumber(
		nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO));
	if (pe == NULL) {
		entry.proto = "unknown";
	} else {
		entry.proto = pe->p_name;
	}

	// ttl
	seconds = nfct_get_attr_u32(ct, ATTR_TIMEOUT);
	minutes = seconds/60;
	hours = minutes/60;
	minutes = minutes%60;
	seconds = seconds%60;
	// Format it with snprintf and store it in the table
	snprintf(ttlc,11,"%3i:%02i:%02i",hours,minutes,seconds);
	entry.ttl = ttlc; 

	// Everything has addresses
	entry.src.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
	entry.dst.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);

	// Counters
	entry.bytes = nfct_get_attr_u32(ct, ATTR_ORIG_COUNTER_BYTES);
	entry.packets = 
		nfct_get_attr_u32(ct, ATTR_ORIG_COUNTER_PACKETS);

	if (digits(entry.bytes) > max->bytes) {
		max->bytes = digits(entry.bytes);
	}
	if (digits(entry.packets) > max->packets) {
		max->packets = digits(entry.packets);
	}

	// OK, proto dependent stuff
	if (entry.proto == "tcp" || entry.proto == "udp") {
		entry.srcpt = htons(
			nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
		entry.dstpt = htons(
			nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));
	}

	if (entry.proto == "tcp") {

		entry.state =
			states[nfct_get_attr_u8(ct, ATTR_TCP_STATE)];
		counts->tcp++;

	} else if (entry.proto == "udp") {

		entry.state = "";
		counts->udp++;

	} else if (entry.proto == "icmp") {

		typecode.str("");
		typecode << (int)nfct_get_attr_u8(ct, ATTR_ICMP_TYPE)
			<< "/" << (int)nfct_get_attr_u8(ct, ATTR_ICMP_CODE)
			<< " (" << nfct_get_attr_u16(ct, ATTR_ICMP_ID)
			<< ")";


		entry.state = typecode.str();
		counts->icmp++;

	} else {
		/*
		 * If the protocol is something else, then we need
		 * to know how long the name of the protocol is so
		 * we can format accordingly later.
		 */
		if (entry.proto.size() > max->proto)
			max->proto = entry.proto.size();

		counts->other++;

	}

	/*
	 * FILTERING
	 */

	/*
	 * FIXME: There's some awesome stupidity here. But it's here
	 * 	for a reason. filters.* should be real ints
	 * 	or inet_addrs as necessary, but if we do that
	 * 	we'll break the #ifdef'd code below that's there for
	 * 	backwards compatibility. Once we nuke that code
	 * 	we make this MUCH cleaner.
	 *
	 * FIXME: Also, filtering can probably be pulled out to
	 * 	it's own function once the other copy of build_table()
	 * 	is gone.
	 */
	if (flags->skiplb && (inet_ntoa(entry.src) == "127.0.0.1")) {
		counts->skipped++;
		return NFCT_CB_CONTINUE;
	}

	if (flags->skipdns && (entry.dstpt == 53)) {
		counts->skipped++;
		return NFCT_CB_CONTINUE;
	}

	if (flags->filter_src
	    && (inet_ntoa(entry.src) != filters->src)) {
		counts->skipped++;
		return NFCT_CB_CONTINUE;
	}

	if (flags->filter_srcpt
	    && (entry.srcpt != atoi(filters->srcpt.c_str()))) {
		counts->skipped++;
		return NFCT_CB_CONTINUE;
	}

	if (flags->filter_dst
	    && (inet_ntoa(entry.dst) != filters->dst)) {
		counts->skipped++;
		return NFCT_CB_CONTINUE;
	}

	if (flags->filter_dstpt
	    && (entry.dstpt != atoi(filters->dstpt.c_str()))) {
		counts->skipped++;
		return NFCT_CB_CONTINUE; 
	}

	/*
	 * RESOLVE AND TRUNCATE
	 */

	// Resolve Names if we need to
	if (flags->lookup)
		resolve_names(entry,*max);

	/*
	 * Add this to the array
	 */
	stable->push_back(entry);

	return NFCT_CB_CONTINUE;
}

#else
void build_table(flags_t &flags, const filters_t &filters,
		vector<table_t> &stable, counters_t &counts,
		max_t &max)
{

	/*
	 * Variables
	 */

	// Temporary strings for holding/formatting/etc.
	string line, mins, secs, hrs, tmpstring;
	/*
	 * These are ascii representations of various fields we parse in
	 * before they get converted to in_addr/int/etc.
	 */
	string src, dst, srcpt, dstpt, proto, code, type, state, ttl;
	/*
	 * snprintf() require a real char*, unfortunately - this is just
	 * for formatting the TTL.
	 */
	char ttlc[11];
	int seconds=0, minutes=0, hours=0;
	// this is the array we parse the line into
	vector<string> fields(MAXFIELDS);
	struct protoent* pe = NULL;
	table_t entry;

	/*
	 * Initialization
	 */
	stable.clear();
	counts.tcp = counts.udp = counts.icmp = counts.other = counts.skipped
		= 0;

	// Open the file
	ifstream input(CONNTRACK);
	if (!input.is_open()) {
		if (!flags.single)
			end_curses();
		cerr << "ERROR: Couldn't open " << CONNTRACK <<
			": " << strerror(errno) << endl;
		exit(2);
	}

	while (getline(input,line) && stable.size() < MAXCONS) {

		/*
		 * Clear the entry
		 */
		entry.sname = "";
		entry.dname = "";
		entry.srcpt = 0;
		entry.dstpt = 0;
		entry.proto = "";
		entry.ttl = "";
		entry.state = "";

		/* 
		 * BEGIN PARSING
		 */
		splita(' ',line,fields);

		/*
		 * First, we read stuff into the array that's always in the
		 * same place regardless of protocol
		 */

		/*
		 * Get the protocol number from field[1]
		 * We don't want to get it from field[0] because
		 * ip_conntrack doesn't seem to support this field
		 * for anything other than tcp, udp, and icmp
		 */
		if ((pe = getprotobynumber(atoi(fields[1].c_str()))) == NULL) {
			entry.proto = "unknown";
		} else {
			entry.proto = pe->p_name;
		}
				
		// ttl
		seconds = atoi(fields[2].c_str());
		minutes = seconds/60;
		hours = minutes/60;
		minutes = minutes%60;
		seconds = seconds%60;
		// Format it with snprintf and store it in the table
		snprintf(ttlc,11,"%3i:%02i:%02i",hours,minutes,seconds);
		entry.ttl = ttlc; 

		// OK, proto dependent stuff
		if (entry.proto == "tcp") {
			/*
			 * Split each field into the part we don't care about
			 * (tmpstring), and the part we do (src,dst, etc...)
			 */
			split('=',fields[4],tmpstring,src);
			split('=',fields[5],tmpstring,dst);
			split('=',fields[6],tmpstring,srcpt);
			split('=',fields[7],tmpstring,dstpt);
			split('=',fields[3],tmpstring,state);
	
			// Do some conversions...
			inet_aton(src.c_str(), &(entry.src));
			inet_aton(dst.c_str(), &(entry.dst));
			entry.srcpt = atoi(srcpt.c_str());
			entry.dstpt = atoi(dstpt.c_str());
			entry.state = state;

			counts.tcp++;
			
		} else if (entry.proto == "udp") {
			split('=',fields[3],tmpstring,src);
			split('=',fields[4],tmpstring,dst);
			split('=',fields[5],tmpstring,srcpt);
			split('=',fields[6],tmpstring,dstpt);

			inet_aton(src.c_str(), &(entry.src));
			inet_aton(dst.c_str(), &(entry.dst));
			entry.srcpt = atoi(srcpt.c_str());
			entry.dstpt = atoi(dstpt.c_str());
			entry.state = "";

			counts.udp++;

		} else if (entry.proto == "icmp") {
			split('=',fields[3],tmpstring,src);
			split('=',fields[4],tmpstring,dst);
			split('=',fields[5],tmpstring,type);
			split('=',fields[6],tmpstring,code);

			inet_aton(src.c_str(), &entry.src);
			inet_aton(dst.c_str(), &entry.dst);
			entry.state = type + "/" + code;

			counts.icmp++;

		} else {
			// If we're not TCP, or UDP
			// There's no ports involved
			split('=',fields[3],tmpstring,src);
			split('=',fields[4],tmpstring,dst);

			inet_aton(src.c_str(), &entry.src);
			inet_aton(dst.c_str(), &entry.dst);

			/*
			 * If the protocol is something else, then we need
			 * to know how long the name of the protocol is so
			 * we can format accordingly later.
			 */
			if (entry.proto.size() > max.proto)
				max.proto = entry.proto.size();

			counts.other++;

		}

		/*
		 * FILTERING
		 */

		if (flags.skiplb && (src == "127.0.0.1")) {
			counts.skipped++;
			continue;
		}

		if (flags.skipdns && (dstpt == "53")) {
			counts.skipped++;
			continue;
		}

		if (flags.filter_src && (src != filters.src)) {
			counts.skipped++;
			continue;
		}

		if (flags.filter_srcpt && (srcpt != filters.srcpt)) {
			counts.skipped++;
			continue;
		}

		if (flags.filter_dst && (dst != filters.dst)) {
			counts.skipped++;
			continue;
		}

		if (flags.filter_dstpt && (dstpt != filters.dstpt)) {
			counts.skipped++;
			continue; 
		}

		/*
		 * RESOLVE AND TRUNCATE
		 */

		// Resolve Names if we need to
		if (flags.lookup)
			resolve_names(entry, max);

		/*
		 * Add this to the array
		 */
		stable.push_back(entry);

	} // end while (getline)
	input.close(); // close the ip_conntrack

}
#endif

/*
 * This sorts the table based on the current sorting preference
 */
void sort_table(const int &sortby, const bool &lookup, const int &sort_factor,
		vector<table_t> &stable, string &sorting)
{

	switch (sortby) {
		// This is ^L
		case SORT_SRC:
			if (lookup) {
				qsort(&(stable[0]),stable.size(),
						sizeof(table_t),sname_sort);
				sorting = "SrcName";
			} else {
				qsort(&(stable[0]),stable.size(),
						sizeof(table_t),src_sort);
				sorting = "SrcIP";
			}
			break;

		case SORT_SRC_PT:
			qsort(&(stable[0]),stable.size(),sizeof(table_t),
					srcpt_sort);
			sorting = "SrcPort";
			break;

		case SORT_DST:
			if (lookup) {
				qsort(&(stable[0]),stable.size(),
						sizeof(table_t),dname_sort);
				sorting = "DstName";
			} else {
				qsort(&(stable[0]),stable.size(),
						sizeof(table_t),dst_sort);
				sorting = "DstIP";
			}
			break;

		case SORT_DST_PT:
			qsort(&(stable[0]),stable.size(),sizeof(table_t),
					dstpt_sort);
			sorting = "DstPort";
			break;

		case SORT_PROTO:
			qsort(&(stable[0]),stable.size(),sizeof(table_t),
					proto_sort);
			sorting = "Proto";
			break;

		case SORT_STATE:
			qsort(&(stable[0]),stable.size(),sizeof(table_t),
					state_sort);
			sorting = "State";
			break;

		case SORT_TTL:
			qsort(&(stable[0]),stable.size(),sizeof(table_t),
					ttl_sort);
			sorting = "TTL";
			break;

#ifndef IPTSTATE_USE_PROC
		case SORT_BYTES:
			qsort(&(stable[0]),stable.size(),sizeof(table_t),
					bytes_sort);
			sorting = "Bytes";
			break;

		case SORT_PACKETS:
			qsort(&(stable[0]),stable.size(),sizeof(table_t),
					packets_sort);
			sorting = "Packets";
			break;
#endif

		default:
			//we should never get here
			sorting = "??unknown??";
			break;

	} //switch

	if (sort_factor == -1)
		sorting = sorting + " reverse";

}

/*
 * This does all the work of actually printing the table including
 * various bits of formatting. It handles both curses and non-curses runs.
 */
void print_table(vector<table_t> &stable, const flags_t &flags,
		const string &format, const string &sorting,
		const filters_t &filters, const counters_t &counts,
		const screensize_t &ssize, const max_t &max,
		WINDOW *mainwin, unsigned int &curr)
{

	/*
	 * Print headers
	 */

	if (flags.single) {
		cout << "IP Tables State Top -- Sort by: " << sorting << endl;
	} else {
		wmove(mainwin,0,0);
		wclrtoeol(mainwin);
		wmove(mainwin,0,ssize.x/2-15);
		wattron(mainwin,A_BOLD);
		wprintw(mainwin,"IPTState - IPTables State Top\n");
	
		wprintw(mainwin,"Version: ");
		wattroff(mainwin,A_BOLD);
		wprintw(mainwin,"%-13s", VERSION);
	
		wattron(mainwin,A_BOLD);
		wprintw(mainwin,"Sort: ");
		wattroff(mainwin,A_BOLD);
		wprintw(mainwin,"%-16s", sorting.c_str());
		
		wattron(mainwin,A_BOLD);
		wprintw(mainwin,"b");
		wattroff(mainwin,A_BOLD);
		wprintw(mainwin,"%-19s", ": change sorting");

		wattron(mainwin,A_BOLD);
		wprintw(mainwin,"h");
		wattroff(mainwin,A_BOLD);
		wprintw(mainwin,"%-s\n", ": help");
	}

	/*
	 * If enabled, print totals
	 */
	if (flags.totals) {
		if (flags.single)
			printf(TOTALS_FORMAT,stable.size()+counts.skipped,
				counts.tcp,counts.udp,counts.icmp,counts.other,
				counts.skipped);
		else
			wprintw(mainwin,TOTALS_FORMAT,
				stable.size()+counts.skipped,counts.tcp,
				counts.udp,counts.icmp,counts.other,
				counts.skipped);
	}

	/*
	 * If any, print filters
	 */
	if (flags.filter_src || flags.filter_dst || flags.filter_srcpt
			|| flags.filter_dstpt) {

		if (flags.single) {
			printf("Filters: ");
		} else {
			wattron(mainwin,A_BOLD);
			wprintw(mainwin,"Filters: ");
			wattroff(mainwin,A_BOLD);
		}

		bool printed_a_filter = false;

		if (flags.filter_src) {
			(flags.single)
				? printf("src: %s",filters.src.c_str())
				: wprintw(mainwin,"src: %s",
						filters.src.c_str());
			printed_a_filter = true;
		}
		if (flags.filter_srcpt) {
			if (printed_a_filter) {
				(flags.single)
					? printf(", ")
					: waddstr(mainwin,", ");
			}
			(flags.single)
				? printf("sport: %s",filters.srcpt.c_str())
				:  wprintw(mainwin,"sport: %s",
						filters.srcpt.c_str());
			printed_a_filter = true;
		}
		if (flags.filter_dst) {
			if (printed_a_filter) {
				(flags.single)
					? printf(", ")
					: waddstr(mainwin,", ");
			}
			(flags.single)
				? printf("dst: %s",filters.dst.c_str())
				: wprintw(mainwin,"dst: %s",
						filters.dst.c_str());
			printed_a_filter = true;
		}
		if (flags.filter_dstpt) {
			if (printed_a_filter) {
				(flags.single)
					? printf(", ")
					: waddstr(mainwin,", ");
			}
			(flags.single)
				? printf("dport: %s",filters.dstpt.c_str())
				: wprintw(mainwin,"dport: %s",
						filters.dstpt.c_str());
			printed_a_filter = true;
		}
		(flags.single)
			? printf("\n")
			: wprintw(mainwin,"\n");
	}

	/*
	 * Print column headers
	 */
	if (flags.single) {
		if (flags.counters) {
			printf(format.c_str(),"Source","Destination","Proto",
				"State","TTL","B","P");
		} else {
			printf(format.c_str(),"Source","Destination","Proto",
				"State","TTL");
		}
	} else {
		wattron(mainwin,A_BOLD);
		if (flags.counters) {
			wprintw(mainwin,format.c_str(),"Source","Destination",
				"Proto", "State","TTL","B","P");
		} else {
			wprintw(mainwin,format.c_str(),"Source","Destination",
				"Proto","State","TTL");
		}
		wattroff(mainwin,A_BOLD);
	}

	/*
	 * Print the state table
	 */
	unsigned int limit = (stable.size() < NLINES) ? stable.size() : NLINES;
	for (unsigned int tmpint=0; tmpint < limit; tmpint++) {
		printline(stable[tmpint],flags,format,max,mainwin,
			(curr == tmpint));
		if (!flags.single && flags.noscroll && 
				(tmpint >= ssize.y-4 ||
				   (flags.totals && tmpint >= ssize.y-5)))
			break;

	}

	/*
	 * We don't want to lave things on the screen we didn't draw
	 * this time.
	 */
	if (!flags.single)
		wclrtobot(mainwin);
	
}

/*
 * Dynamically build a format to fit the most amount of data on the screen
 */
void determine_format(max_t &max, screensize_t &ssize, string &format,
		const flags_t &flags)
{

	/*
	 * NOTE: When doing proper dynamic format building, we fill the
	 *       entire screen, so curses puts in a newline for us. However
	 *       with "staticsize" we must add a newline. Also with "single"
	 *       mode we must add it as well since there's no curses there.
	 *
	 *       Thus DEFAULT_FORMAT (only used for staticsize) has it, and
	 *       at the bottom of this function we add a \n if flags.single
	 *       is set.
	 */
	if (flags.staticsize) {
		format = DEFAULT_FORMAT;
		max.src = DEFAULT_SRC;
		max.dst = DEFAULT_DST;
		max.proto = DEFAULT_PROTO;
		max.state = DEFAULT_STATE;
		max.ttl = DEFAULT_TTL;
		return;
	}

	ssize = get_size(flags.single);

	// These three, are easy
	/*
	unsigned int ttl = max.ttl;
	unsigned int state = max.state;
	unsigned int proto = max.proto;
	*/

	/* what's left is the above three, plus 4 spaces
	 * (one between each of 5 fields)
	 */
	unsigned int left = ssize.x - max.ttl - max.state - max.proto
				- 4;
	if (flags.counters) {
		//cerr << "left is " << left << " bytes is " << max.bytes
		//	<< " packs is " << max.packets << endl;
		left -= (max.bytes + max.packets + 2);
	}

	/*
	 * The rest is *prolly* going to be divided between src
	 * and dst, so we see if that works. If 'left' is odd though
	 * we give the extra space to src.
	 */
	unsigned int src, dst;
	src = dst = left/2;
	bool left_odd = false;
	if ((left%2) == 1) {
		left_odd = true;
		src++;
	}
	if ((max.src + max.dst) < left) {
		/*
		 * This means we can fit without an truncation, but it doesn't
		 * necessarily mean that we can just give half to src and half
		 * to dst... so lets figure that out.
		 */

		if (max.src < src && max.dst < dst) {
			/*
			 * This case applies if:
			 *   we're even and they both fit in left/2
			 * OR
			 *   we're odd and dst fits in left/2
			 *             and src fits in left/2+1
			 *
			 * Since we've already calculated src/dst that way
			 * we just combine this check as they both require
			 * the same outcome.
			 */
		} else if (left_odd && (src < left/2) && (dst < left/2+1)) {
			/*
			 * If src can fit in left/2 and dst in left/2+1
			 * then we switch them.
			 */
			src = dst;
			dst++;
		} else if (max.src > max.dst) { 
			/*
		 	 * If we're here, we can fit them, but we can't fit them
			 * and still keep the two columns relatively equal. Ah
			 * well.
			 *
			 * Either max gets the bigger chunk and everything else
			 * to dst...
		 	 */
			src = max.src;
			dst = left - max.src;
		} else {
			/*
			 * ...or the other way around
			 */
			dst = max.dst;
			src = left - max.dst;
		}
	} else if (max.src < src) {
		/*
		 * If we're here, we do have to truncate, but if one column is
		 * very small, we should not give it more space than it needs.
		 */
		src = max.src;
		dst = left - max.src;
	} else if (max.dst < dst) {
		/*
		 * same as above.
		 */
		dst = max.dst;
		src = left - max.dst;
	}

	/*
	 * If nothing matched, then they're both bigger than left/2, so we'll
	 * leave the default we set above.
	 */

	ostringstream buffer;
	buffer << "\%-" << src << "s \%-" << dst << "s \%-" << max.proto << "s \%-"
		<< max.state << "s \%-" << max.ttl << "s";

	if (flags.counters) {
		buffer << " \%-" << max.bytes << "s \%-" << max.packets << "s";
	}

	if (flags.single)
		buffer << "\n";

	format = buffer.str();

/*
	max.ttl = ttl;
	max.state = state;
	max.proto = proto;
*/
	max.dst = dst;
	max.src = src;

}

/*
 * Interactive help
 */
void interactive_help(const string &sorting, const flags_t &flags,
		const filters_t &filters)
{

	/*
	 * This is the max we need the pad to be, and thus how
	 * big we're going to create the pad.
	 * 
	 * In many cases we'd make the pad very very large and not
	 * worry about it. However, in this case:
	 *   1. We know exactly how big we need it to be, and it's
	 *      not going to change interactively.
	 *   2. We want to draw a "box" around the window and if the
	 *      pad is huge then the box will get drawn around that.
	 *
	 * So... we have 32 lines of help, plus a top and bottom border,
	 * thus maxrows is 34.
	 *
	 * Our help text is not wider than 80, so we'll se that standard
	 * width.
	 *
	 * If the screen is bigger than this, we deal with it below.
	 */
#ifndef IPTSTATE_USE_PROC
	unsigned int maxrows = 41;
#else
	unsigned int maxrows = 39;
#endif
	unsigned int maxcols = 80;

	/*
	 * The actual screen size
	 */
	screensize_t ssize = get_size(flags.single);

	/*
	 * If the biggest we think we'll need is smaller than the screen,
	 * then lets grow the pad to the size of the screen so that the
	 * main window isn't peeking through.
	 */
	if (maxrows < ssize.y)
		maxrows = ssize.y;
	if (maxcols < ssize.x)
		maxcols = ssize.x;

	/*
	 * Where we are withing the pad (for printing). We can't just print
	 * newlines and expect it to work. Cause, well, it doesn't. You have
	 * to tell it where on the pad to print, specifically.
	 */
	unsigned int x,y;
	x = y = 0;

	/*
	 * The current position on the pad we're showing (top left)
	 */
	unsigned int px,py;
	px = py = 0;

	/*
	 * As noted above, we create the biggest pad we might need
	 */
	static WINDOW *helpwin;
	helpwin = newpad(maxrows,maxcols);

	/*
	 * Create a box, and then add one to "x" and "y" so we don't write
	 * on the line, 
	 */
	box(helpwin,ACS_VLINE,ACS_HLINE);
	x++;
	y++;


	/*
	 * we want arrow keys to work
	 */
	keypad(helpwin,true);

	// Prolly not needed
	wmove(helpwin,0,0);

	// Print opener
	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"IPTState ");
	waddstr(helpwin,VERSION);
	wattroff(helpwin,A_BOLD);
	// this is \n
	y++;

	// We don't want anything except the title up against the
	// border
	x++;

	string nav = "Up/j, Down/k, Left/h, Right/l, PageUp/^u, PageDown/^d,";
	nav += " Home, or End";
	// Print instructions first
	mvwaddstr(helpwin,y++,x,"Navigation:");
	mvwaddstr(helpwin,y++,x,nav.c_str());
	mvwaddstr(helpwin,y++,x,"  Press any other key to continue...");
	y++;

	// Print settings
	mvwaddstr(helpwin,y++,x,"Current settings:");

	mvwaddstr(helpwin,y++,x,"  Sorting by: ");
	wattron(helpwin,A_BOLD);
	waddstr(helpwin,sorting.c_str());
	wattroff(helpwin,A_BOLD);

	mvwaddstr(helpwin,y++,x,"  Dynamic formatting: ");
	wattron(helpwin,A_BOLD);
	waddstr(helpwin,(!flags.staticsize) ? "yes" : "no");
	wattroff(helpwin,A_BOLD);

	mvwaddstr(helpwin,y++,x,"  Skip loopback states: ");
	wattron(helpwin,A_BOLD);
	waddstr(helpwin,(flags.skiplb) ? "yes" : "no");
	wattroff(helpwin,A_BOLD);

	mvwaddstr(helpwin,y++,x,"  Resolve hostnames: ");
	wattron(helpwin,A_BOLD);
	waddstr(helpwin,(flags.lookup) ? "yes" : "no");
	wattroff(helpwin,A_BOLD);

	mvwaddstr(helpwin,y++,x,"  Mark truncated hostnames: ");
	wattron(helpwin,A_BOLD);
	waddstr(helpwin,(flags.tag_truncate) ? "yes" : "no");
	wattroff(helpwin,A_BOLD);

	mvwaddstr(helpwin,y++,x,"  Colors: ");
	wattron(helpwin,A_BOLD);
	waddstr(helpwin,(!flags.nocolor) ? "yes" : "no");
	wattroff(helpwin,A_BOLD);

	mvwaddstr(helpwin,y++,x,"  Skip outgoing DNS lookup states: ");
	wattron(helpwin,A_BOLD);
	waddstr(helpwin,(flags.skipdns) ? "yes" : "no");
	wattroff(helpwin,A_BOLD);

	mvwaddstr(helpwin,y++,x,"  Enable scroll: ");
	wattron(helpwin,A_BOLD);
	waddstr(helpwin,(!flags.noscroll) ? "yes" : "no");
	wattroff(helpwin,A_BOLD);

	mvwaddstr(helpwin,y++,x,"  Display totals: ");
	wattron(helpwin,A_BOLD);
	waddstr(helpwin,(flags.totals) ? "yes" : "no");
	wattroff(helpwin,A_BOLD);

	mvwaddstr(helpwin,y++,x,"  Display counters: ");
	wattron(helpwin,A_BOLD);
	waddstr(helpwin,(flags.counters) ? "yes" : "no");
	wattroff(helpwin,A_BOLD);

	if (flags.filter_src) {
		mvwaddstr(helpwin,y++,x,"  Source filter: ");
		wattron(helpwin,A_BOLD);
		waddstr(helpwin,filters.src.c_str());
		wattroff(helpwin,A_BOLD);
	}
	if (flags.filter_dst) {
		mvwaddstr(helpwin,y++,x,"  Destination filter: ");
		wattron(helpwin,A_BOLD);
		waddstr(helpwin,filters.dst.c_str());
		wattroff(helpwin,A_BOLD);
	}
	if (flags.filter_srcpt) {
		mvwaddstr(helpwin,y++,x,"  Source port filter: ");
		wattron(helpwin,A_BOLD);
		waddstr(helpwin,filters.srcpt.c_str());
		wattroff(helpwin,A_BOLD);
	}
	if (flags.filter_dstpt) {
		mvwaddstr(helpwin,y++,x,"  Destination port filter: ");
		wattron(helpwin,A_BOLD);
		waddstr(helpwin,filters.dstpt.c_str());
		wattroff(helpwin,A_BOLD);
	}

	y++;

	// Print commands
	mvwaddstr(helpwin,y++,x,"Interactive commands:");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  c");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tUse colors");

#ifndef IPTSTATE_USE_PROC
	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  C");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tToggle display of bytes/packets counters");
#endif

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  b");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tSort by next column");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  B");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tSort by previous column");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  d");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tChange destination filter");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  D");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tChange destination port filter");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  f");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tToggle display of loopback states");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  h");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tDisplay this help message");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  l");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tToggle DNS lookups");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  L");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tToggle display of outgoing DNS states");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  m");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tToggle marking truncated hostnames with a '+'");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  o");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tToggle dynamic or old formatting");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  p");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tToggle scrolling");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  q");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tQuit");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  r");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tToggle reverse sorting");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  R");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tChange the refresh rate");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  s");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tChange source filter");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  S");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tChange source port filter");

	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  t");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,"\tToggle display of totals");

#ifndef IPTSTATE_USE_PROC
	wattron(helpwin,A_BOLD);
	mvwaddstr(helpwin,y++,x,"  x");
	wattroff(helpwin,A_BOLD);
	waddstr(helpwin,
		"\tDelete the currently highlighted state from netfilter");
#endif

	y++;

	wmove(helpwin,0,0);

	/*
	 * refresh from wherever we are the pad
	 * and the top of the window to the bottom of the window.
	 */
	prefresh(helpwin,py,px,0,0,ssize.y-1,ssize.x-1);
	// kill line buffering
	cbreak();
	// nodelay with a 0 here causes getch() to block until key is pressed.
	nodelay( helpwin, 0 );
	int c;
	while ((c = wgetch(helpwin))) {
		switch (c) { 
			case ERR:
				continue;
				break;
			case KEY_DOWN:
			case 'j':
				/*
				 * py is the top of the window,
				 * ssize.y is the height of the window,
				 * so py+ssize.y is the bottom of the window.
				 *
				 * Since y is the bottom of the text we've
				 * written, if
				 *    py+ssize.y == y
				 * then the bottom of the screen as at the
				 * bottom of the text, no more scrolling.
				 */
				if (py + ssize.y < y)
					py++;
				prefresh(helpwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			case KEY_UP:
			case 'k':
				if (py > 0)
					py--;
				prefresh(helpwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			case KEY_RIGHT:
			case 'l':
				/*
				 * px is the left of the window,
				 * ssize.x is the width of the window,
				 * so px+ssize.x os the right side of the window.
				 *
				 * So if px+ssize.x == 80 (more than the width
				 * of our text), no more scrolling.
				 */
				if (px + ssize.x < 80)
					px++;
				prefresh(helpwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			case KEY_LEFT:
			case 'h':
				if (px > 0)
					px--;
				prefresh(helpwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			case KEY_HOME:
			case KEY_SHOME:
			case KEY_FIND:
				px = py = 0;
				prefresh(helpwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			case KEY_END:
				py = y-ssize.y;
				prefresh(helpwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			case 4:
			case KEY_NPAGE:
			case KEY_SNEXT:
				if (flags.noscroll)
					break;
				/*
				 * If the screen is bigger than the text,
				 * ignore
				 */
				if (y < ssize.y)
					break;
				/*
				 * Otherwise, if the bottom of the screen
				 *    (current position + screen size
				 *     == py + ssize.y)
				 * were to go down one screen (thus:
				 *     py + ssize.y*2),
				 * and that is bigger than the whole text, just
				 * go to the bottom.
				 *
				 * Otherwise, go down a screen size.
				 */
				if (py + ssize.y*2 > y) {
					py = y-ssize.y;
				} else {
					py += ssize.y;
				}
				prefresh(helpwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;
			case 21:
			case KEY_PPAGE:
			case KEY_SPREVIOUS:
				if (flags.noscroll)
					break;
				/*
				 * If we're at the top, ignore this.
				 */
				if (py == 0)
					break;
				/*
				 * Otherwise if we're less than a page from the
				 * top, go to the top, else, go up a page.
				 */
				if (py < ssize.y)
					py = 0;
				else
					py -= ssize.y;
				prefresh(helpwin,py,px,0,0,ssize.y-1,ssize.x-1);
				break;

			case 'q':
			default:
				goto out;
				break;
		}
		if (need_resize) {
			goto out;
		}
	}
out:
	// once a key is pressed, tear down the help window.
	delwin(helpwin);
	refresh();
	halfdelay(1);
}

/*
 * An abstraction of priting a line for both single/curses modes
 */
void printline(table_t &table, const flags_t &flags, const string &format,
		const max_t &max, WINDOW *mainwin, const bool curr)
{
	ostringstream buffer;
	buffer.str("");
	string src,dst,b,p;
	
	if (flags.lookup)
		truncate(table,max,flags);

	if (table.proto == "tcp" || table.proto == "udp") {
		if (flags.lookup && (table.sname != "")) {
			buffer << table.sname << ":" << table.spname;
		} else {
			buffer << inet_ntoa(table.src) << ":" << table.srcpt;
		}
		src = buffer.str();
		buffer.str("");
		if (flags.lookup && (table.dname != "")) {
			buffer << table.dname << ":" << table.dpname;
		} else {
			buffer << inet_ntoa(table.dst) << ":" << table.dstpt;
		}
		dst = buffer.str();
		buffer.str("");
	} else {
		if (flags.lookup && (table.sname != "")) {
			src = table.sname;
		} else {
			src = inet_ntoa(table.src);
		}
		if (flags.lookup && (table.dname != "")) {
			dst = table.dname;
		} else {
			dst = inet_ntoa(table.dst);
		}
	}

	if (flags.counters) {
		buffer << table.bytes;
		b = buffer.str();
		buffer.str("");
		buffer << table.packets;
		p = buffer.str();
		buffer.str("");
	}
		
	if (flags.single) {
		if (flags.counters) {
			printf(format.c_str(), src.c_str(), dst.c_str(),
				table.proto.c_str(), table.state.c_str(),
				table.ttl.c_str(), b.c_str(),p.c_str());
		} else {
			printf(format.c_str(), src.c_str(), dst.c_str(),
				table.proto.c_str(), table.state.c_str(),
				table.ttl.c_str());
		}
	} else {
		int color = 0;
		if (!flags.nocolor) {
			if (table.proto == "tcp")
				color = 1;
			else if (table.proto == "udp")
				color = 2;
			else if (table.proto == "icmp")
				color = 3;
			if (curr)
				color += 4;
			wattron(mainwin,COLOR_PAIR(color));
				
		}
		if (flags.counters) {
			wprintw(mainwin,format.c_str(), src.c_str(), dst.c_str(),
				table.proto.c_str(), table.state.c_str(),
				table.ttl.c_str(),b.c_str(),p.c_str());
		} else {
			wprintw(mainwin,format.c_str(), src.c_str(), dst.c_str(),
				table.proto.c_str(), table.state.c_str(),
				table.ttl.c_str());	
		}
	
		if (!flags.nocolor && color != 0)
			wattroff(mainwin,COLOR_PAIR(color));
	}
}

/*
 * split a string into two strings based on the first occurance
 * of any character
 */
void split(char s, string line, string &p1, string &p2)
{
	int pos = line.find(s);
	p1 = line.substr(0,pos);
	p2 = line.substr(pos+1,line.size()-pos);
}

/*
 * split a string into an array of strings based on 
 * any character
 */
void splita(char s, string line, vector<string> &result)
{
	int pos, size;
	int i=0;
	string temp, temp1;
	temp = line;
	while ((temp.find(s) != string::npos) && (i < MAXFIELDS-1)){
		pos = temp.find(s);
		result[i] = temp.substr(0,pos);
		size = temp.size();
		temp = temp.substr(pos+1,size-pos-1);
		if (result[i] != "") {
			i++;
		}
	}
	result[i] = temp;
}

/*
 * This determines the length of an integer (i.e. number of digits)
 */
unsigned int digits(int x)
{
	return (unsigned int) floor(log10((double)x))+1;
}

/*
 * Check to ensure an IP is valid
 */
bool check_ip(const char *arg)
{
	in_addr tmp_addr;
	if (inet_aton(arg,&tmp_addr) == 0) {
		return false;
	}
	return true;
}

/*
 * The help
 */
void help()
{
	cout << "IPTables State Top Version " << VERSION << endl;
	cout << "Usage: iptstate [<options>]\n\n";
	cout << "  -c, --no-color\n";
	cout << "	Toggle color-code by protocol\n\n";
#ifndef IPTSTATE_USE_PROC
	cout << "  -C, --counters\n";
	cout << "	Toggle display of bytes/packets counters\n\n";
#endif
	cout << "  -d, --dst-filter <IP>\n";
	cout << "	Only show states with a destination of <IP>\n";
	cout << "	Note, that this must be an IP, hostname matching is"
		<< " not yet supported.\n\n";
	cout << "  -D --dstpt-filter <port>\n";
	cout << "	Only show states with a destination port of <port>\n\n";
	cout << "  -h, --help\n";
	cout << "	This help message\n\n";
	cout << "  -l, --lookup\n";
	cout << "	Show hostnames instead of IP addresses\n\n";
	cout << "  -m, --mark-truncated\n";
	cout << "	Mark truncated hostnames with a '+'\n\n";
	cout << "  -o, --no-dynamic\n";
	cout << "	Toggle dynamic formatting\n\n";
	cout << "  -L, --no-dns\n";
	cout << "	Skip outgoing DNS lookup states\n\n";
	cout << "  -f, --no-loopback\n";
	cout << "	Filter states on loopback\n\n";
	cout << "  -p, --no-scroll\n";
	cout << "	No scrolling (don't use a \"pad\")\n\n";
	cout << "  -r, --reverse\n";
	cout << "	Reverse sort order\n\n";
	cout << "  -R, --rate <seconds>\n";
	cout << "	Refresh rate, followed by rate in seconds\n";
	cout << "	Note: For statetop, not applicable for -s\n\n";
	cout << "  -1, --single\n";
	cout << "	Single run (no curses)\n\n";
	cout << "  -b, --sort <column>\n";
	cout << "	This determines what column to sort by. Options:\n";
	cout << "	   d: Destination IP (or Name)\n";
	cout << "	   p: Protocol\n";
	cout << "	   s: State\n";
	cout << "	   t: TTL\n";
	cout << "	   b: Bytes\n";
	cout << "	   P: Packets\n";
	cout << "	To sort by Source IP (or Name), don't use -b.\n";
	cout << "	Note that bytes/packets are only available when"
		<< " supported in the kernel,\n";
	cout << "	and enabled with -C\n\n";
	cout << "  -s, --src-filter <IP>\n";
	cout << "	Only show states with a source of <IP>\n";
	cout << "	Note, that this must be an IP, hostname matching is"
		<< " not yet supported.\n\n";
	cout << "  -S, --srcpt-filter <port>\n";
	cout << "	Only show states with a source port of <port>\n\n";
	cout << "  -t, --totals\n";
	cout << "	Toggle display of totals\n\n";
	cout << "See man iptstate(8) or the interactive help for more"
		<< " information.\n";
	exit(0);
}

/*
 * Resolve hostnames
 */
void resolve_names(table_t &entry, max_t &max)
{
	unsigned int size = 0;

	resolve_host(entry.src,entry.sname);
	resolve_host(entry.dst,entry.dname);
	resolve_port(entry.srcpt,entry.spname,entry.proto);
	resolve_port(entry.dstpt,entry.dpname,entry.proto);

	size = entry.sname.size() + entry.spname.size() + 1;
	if (size > max.src)
		max.src = size;

	size = entry.dname.size() + entry.dpname.size() + 1;
	if (size > max.dst)
		max.dst = size;

}
void resolve_host(const in_addr &ip, string &name)
{
	struct hostent *hostinfo = NULL;

	if ((hostinfo = gethostbyaddr((char *)&ip,sizeof(ip), AF_INET))
			!= NULL) {
		name = hostinfo->h_name;
	} else {
		name = inet_ntoa(ip);
	}
}

void resolve_port(const int &port, string &name, const string &proto)
{
	struct servent *portinfo = NULL;

	if ((portinfo = getservbyport(htons(port),proto.c_str())) != NULL) {
		name = portinfo->s_name;
	} else {
		ostringstream buf;
		buf.str("");
		buf << port;
		name = buf.str();
	}
}

/*
 * Based on the format pre-chosen, truncate src/dst as needed.
 */
void truncate(table_t &table, const max_t &max, const flags_t &flags)
{
	int length;
	if (table.sname.size() + table.spname.size() + 1 > max.src) {
		length = max.src - 1 - table.spname.size();
		table.sname = table.sname.substr(0,length);
		if (flags.tag_truncate)
			table.sname[table.sname.size()-1] = '+';
	}

	if (table.dname.size() + table.dpname.size() + 1 > max.dst) {
		length = max.dst - 1 - table.dpname.size();
		table.dname = table.dname.substr(0,length);
		if (flags.tag_truncate)
			table.dname[0] = '+';
	}
}


/*
 * what follows are the sort
 * functions that qsort requires
 */
int src_sort(const void *a, const void *b)
{
	return sort_factor * memcmp(&((table_t *)a)->src, &((table_t *)b)->src,
			sizeof(uint32_t));
}
int dst_sort(const void *a, const void *b)
{
	return sort_factor * memcmp(&((table_t *)a)->dst, &((table_t *)b)->dst,
			sizeof(uint32_t));
}
int srcpt_sort(const void *a, const void *b)
{
	if(((table_t *)a)->srcpt == ((table_t *)b)->srcpt) {
		return 0;
	} else if (((table_t *)a)->srcpt > ((table_t *)b)->srcpt) {
		return sort_factor;
	}
	return -sort_factor;
}
int dstpt_sort(const void *a, const void *b)
{
	if(((table_t *)a)->dstpt == ((table_t *)b)->dstpt) {
		return 0;
	} else if (((table_t *)a)->dstpt > ((table_t *)b)->dstpt) {
		return sort_factor;
	}
	return -sort_factor;
}
int proto_sort(const void *a, const void *b)
{
	if(((table_t *)a)->proto == ((table_t *)b)->proto) {
		return 0;
	} else if (((table_t *)a)->proto > ((table_t *)b)->proto) {
		return sort_factor;
	}
	return -sort_factor;
}
int state_sort(const void *a, const void *b)
{
	if(((table_t *)a)->state == ((table_t *)b)->state) {
		return 0;
	} else if (((table_t *)a)->state > ((table_t *)b)->state) {
		return sort_factor;
	}
	return -sort_factor;
}
int ttl_sort(const void *a, const void *b)
{
	if(((table_t *)a)->ttl == ((table_t *)b)->ttl) {
		return 0;
	} else if (((table_t *)a)->ttl > ((table_t *)b)->ttl) {
		return sort_factor;
	}
	return -sort_factor;
}
int sname_sort(const void *a, const void *b)
{
	if(((table_t *)a)->sname == ((table_t *)b)->sname) {
		return 0;
	} else if (((table_t *)a)->sname > ((table_t *)b)->sname) {
		return sort_factor;
	}
	return -sort_factor;
}
int dname_sort(const void *a, const void *b)
{
	if(((table_t *)a)->dname == ((table_t *)b)->dname) {
		return 0;
	} else if (((table_t *)a)->dname > ((table_t *)b)->dname) {
		return sort_factor;
	}
	return -sort_factor;
}
#ifndef IPTSTATE_USE_PROC
int bytes_sort(const void *a, const void *b)
{
	if(((table_t *)a)->bytes == ((table_t *)b)->bytes) {
		return 0;
	} else if (((table_t *)a)->bytes > ((table_t *)b)->bytes) {
		return sort_factor;
	}
	return -sort_factor;
}
int packets_sort(const void *a, const void *b)
{
	if(((table_t *)a)->packets == ((table_t *)b)->packets) {
		return 0;
	} else if (((table_t *)a)->packets > ((table_t *)b)->packets) {
		return sort_factor;
	}
	return -sort_factor;
}
#endif

/*
 * Start-up for curses environment
 *
 * NOTE: That by default we create a pad. A pad is a special type of window that
 *       can be bigger than the screen. See the comments in interactive_help()
 *       below for how to use it and how it works.
 *
 *       However, pad's lack the double-buffering and other features of standard
 *       ncurses windows and thus can appear slower. Thus we allow the user to
 *       downgrade to standard windows if they choose. See the comments
 *       switch_scroll() for more details.
 *
 */
static WINDOW* start_curses(flags_t &flags)
{
	int y,x;
	initscr();
	cbreak();
	noecho();
	halfdelay(1);

	/*
	 * If we're starting curses, we care about SIGWNCH, SIGINT, and SIGTERM
	 * so this seems like as good a place as any to setup our signal
	 * handler.
	 */
	// Resize
	signal(28,winch_handler);
	// Shutdown
	signal(2,kill_handler);
	signal(15,kill_handler);

	if (has_colors()) {
		start_color();
		// for tcp
		init_pair(1,COLOR_GREEN,COLOR_BLACK);
		// for udp
		init_pair(2,COLOR_YELLOW,COLOR_BLACK);
		// for icmp
		init_pair(3,COLOR_RED,COLOR_BLACK);
		// for prompts
		init_pair(4,COLOR_BLACK,COLOR_RED);
		// for the currently selected row
		init_pair(5,COLOR_BLACK,COLOR_GREEN);
		init_pair(6,COLOR_BLACK,COLOR_YELLOW);
		init_pair(7,COLOR_BLACK,COLOR_RED);
	} else {
		flags.nocolor = true;
	}

	if (!flags.noscroll) {
		getmaxyx(stdscr,y,x);
		return newpad(NLINES,x);
	}
	return stdscr;
}

/*
 * Finish-up for curses environment
 */
void end_curses()
{
	curs_set(1);
	nocbreak();
	endwin();
	cout << endl;
}

/*
 * Figure out the best way to get the screensize_t, and then do it
 */
screensize_t get_size(const bool &single)
{
	int maxx = 0, maxy = 0;
	if (!single) {          
		getmaxyx(stdscr, maxy, maxx);
	} else {                             
		maxx=72;
		if (getenv("COLS"))
			maxx=atoi(getenv("COLS"));
	}

	screensize_t a;
	a.x = maxx;
	a.y = maxy;

	return a;
}

/*
 * Error function for screen being too small.
 */
void term_too_small()
{
	end_curses();
	cout << "I'm sorry, your terminal must be atleast 72 columns"
	     << "wide to run iptstate\n";
	exit(3);
}

/*
 * This is one of those "well, I should impliment it to be complete, but
 * I doubt it'll get used very often features." It was a nice-thing-to-do
 * to impliment the ability for iptstate to use stdscr instead of a pad
 * as this provides the doulbe-buffering and other features that pads
 * do not. This is probably useful to a small subset of users. It's pretty
 * unlikely people will want to interactively want to change this during
 * runtime, but since I implimented noscroll, it's only proper to impliment
 * interactive toggling.
 *
 * TECH NOTE:
 *      This is just a note for myself so I remember why this is the way it is.
 *
 *      The syntax WINDOW *&mainwin is right, thought it's doing what you'd
 *      expect WINDOW &*mainwin to do... except that's invalid. So it's just a
 *      &foo pass on a WINDOW*.
 */
void switch_scroll(flags_t &flags, WINDOW *&mainwin)
{
	int x,y;
	if (flags.noscroll) {
		getmaxyx(stdscr,y,x);
		// remove stuff from the bottom window
		erase();
		// build pad
		wmove(mainwin,0,0);
		mainwin = newpad(NLINES,x);
		wmove(mainwin,0,0);
		keypad(mainwin,1);
		halfdelay(1);
	} else {
		// delete pad
		delwin(mainwin);
		mainwin = stdscr;
		keypad(mainwin,1);
		halfdelay(1);
	}

	flags.noscroll = !flags.noscroll;
}

/*
 * Prompt the user for something, and get an answer.
 */
void get_input(WINDOW *win, string &input, const string &prompt,
		const flags_t &flags)
{

	/*
	 * This function is here so that we can prompt and get an answer
	 * and the user can get an echo of what they're inputting. This is
	 * already a non-straight-forward thing to do in cbreak() mode, but
	 * it turns out that using pads makes it even more difficult.
	 *
	 * It's worth noting that I tried doin a simple waddch() and then
	 * prefresh as one would expect, but it didn't echo the chars.
	 * Because we're using pads I have to do a waddchar() and then
	 * a prefresh().
	 *
	 * Note, that the documentation says that if we're using waddchar()
	 * we shouldn't need any refresh, but it doesn't echo without it.
	 * This is probably because waddch() calls wrefresh() instead of
	 * prefresh().
	 */
	
	input = "";
	int x,y;
	getmaxyx(stdscr,y,x);
	WINDOW *cmd = subpad(win,1,x,0,0);
	if (!flags.nocolor)
		wattron(cmd,COLOR_PAIR(4));
	keypad(cmd,true);
	wprintw(cmd,prompt.c_str());
	wclrtoeol(cmd);
	prefresh(cmd,0,0,0,0,0,x);


	int ch;
	int charcount = 0;
	echo();
	nodelay(cmd,0);

	while (1) {
		ch = wgetch(cmd);
		switch (ch) {
			case '\n':
			// 7 is ^G
			case 7:
				if (ch == 7)
					input = "";
				if (!flags.nocolor)
					wattroff(cmd,COLOR_PAIR(4));
				delwin(cmd);
				noecho();
				wmove(win,0,0);
				return;
				break;
			// 8 is shift-backspace - just incase
			case KEY_BACKSPACE:
			case 8:
				if (charcount > 0) {
					input = input.substr(0,input.size()-1);
					wechochar(cmd,'\b');
					wechochar(cmd,' ');
					wechochar(cmd,'\b');
					charcount--;
				}
				break;
			case ERR:
				continue;
				break;
			default:
				input += ch;
				charcount++;
				wechochar(cmd,ch);
		}
		prefresh(cmd,0,0,0,0,0,x);
	}
}

/*
 * Create a window with noticable colors (if colors are enabled)
 * and print a warning. Means curses_warning.
 */
void c_warn(WINDOW *win, const string &warning, const flags_t &flags)
{

	/*
	 * This function is here so that we can warn a user in curses,
	 * usually about bad input.
	 */
	
	int x,y;
	getmaxyx(stdscr,y,x);
	WINDOW *warn = subpad(win,1,x,0,0);
	if (!flags.nocolor)
		wattron(warn,COLOR_PAIR(4));
	wprintw(warn,warning.c_str());
	wprintw(warn," Press any key to continue...");
	wclrtoeol(warn);
	prefresh(warn,0,0,0,0,0,x);
	while ((y = getch())) {
		if (y != ERR) {
			break;
		}
		prefresh(warn,0,0,0,0,0,x);
	}
	if (!flags.nocolor)
		wattroff(warn,COLOR_PAIR(4));
	delwin(warn);
	noecho();
	wmove(win,0,0);
	return;
}

/*
 * SIGWINCH signal handler.
 */
void winch_handler(int sig)
{
	sigset_t mask_set;
	sigset_t old_set;
	// Reset signal handler
	signal(28,winch_handler);
	// ignore this signal for a bit
	sigfillset(&mask_set);
	sigprocmask(SIG_SETMASK, &mask_set, &old_set);

	need_resize = true;
}

/*
 * SIGKILL signal handler
 */
void kill_handler(int sig)
{
	end_curses();
	printf("Caught signal %d, cleaning up.\n",sig);
	exit(0);
}

/*
 * Initialize the max_t structure with some sane defaults. We'll grow
 * them later as needed.
 */
void initialize_maxes(max_t &max, flags_t &flags)
{
	/*
	 * For NO lookup:
	 * src/dst IP can be no bigger than 21 chars:
	 *    IP (max of 15) + colon (1) + port (max of 5) = 21
	 *
	 * For lookup:
	 * if it's a name, we start with the width of the header, and we can
	 * grow from there as needed.
	 */
	if (flags.lookup) {
		max.src = 6;
		max.dst = 11;
	} else {
		max.src = max.dst = 21;
	}
	/*
	 * The proto header is 5, so we can't drop below 6.
	 */
	max.proto = 5;
	/*
	 * "ESTABLISHED" is generally the longest state, we almost always have
	 * several, so we'll start with this. It also looks really bad if state
	 * is changing size a lot, so we start with a common minumum.
	 */
	max.state = 11;
	// TTL we statically make 7: xxx:xx:xx
	max.ttl = 9;

	// Start with something sane
	max.bytes = 2;
	max.packets = 2;
}

/*
 * The actual work of handling a resize.
 */
void handle_resize(WINDOW *&win, const flags_t &flags, screensize_t &ssize)
{
	if (flags.noscroll) {
		endwin();
		refresh();
		return;
	}

	/*
	 * OK, the above case without pads is easy. But pads is tricker.
	 * In order to properly handle SIGWINCH we need to:
	 * 
	 *    - Tear down the pad (delwin)
	 *    - Reset the terminal settings to non-visual mode (endwin)
	 *    - Return to visual mode (refresh)
	 *    - Get the new size (getmaxyx)
	 *    - Rebuild the pad
	 *
	 * Note that we don't get the new size without the endwin/refresh
	 * and thus the new pad doesn't get built right, and everything wraps.
	 *
	 * This order must be preserved.
	 */

	/*
	 * Tear down...
	 */
	delwin(win);
	endwin();
	/*
	 * Start up...
	 */
	refresh();
	getmaxyx(stdscr,ssize.y,ssize.x);
	win = newpad(NLINES,ssize.x);
	keypad(win,true);
	wmove(win,0,0);

	return;
}

#ifndef IPTSTATE_USE_PROC
/*
 * Take in a 'curr' value, and delete a given conntrack
 */
void delete_state(WINDOW *&win, const table_t &entry, const flags_t &flags)
{
	struct nfct_handle *cth;
	struct nf_conntrack *ct;
	cth = nfct_open(CONNTRACK, 0);
	ct = nfct_new();
	int ret;
	string response;
	string src = inet_ntoa(entry.src);
	string dst = inet_ntoa(entry.dst);

	ostringstream msg;
	msg.str("");
	msg << "Deleting state: ";
	if (entry.proto == "tcp" || entry.proto == "udp") {
		msg << src << ":" << entry.srcpt
			<< " -> " << dst << ":" << entry.dstpt;
	} else {
		msg << src << " -> " << dst;
	}
	msg << " -- Are you sure? (y/n)";
	get_input(win,response,msg.str(),flags);

	if (response != "y" && response != "Y" && response != "yes" &&
		response != "YES" && response != "Yes") {
		c_warn(win,"NOT deleting state.",flags);
		return;
	}

	nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, AF_INET);

	nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, entry.src.s_addr);
	nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, entry.dst.s_addr);

	nfct_set_attr_u8(ct, ATTR_ORIG_L4PROTO,
			getprotobyname(entry.proto.c_str())->p_proto);

	if (entry.proto == "tcp" || entry.proto == "udp") {
		nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC,
			htons(entry.srcpt));
		nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST,
			htons(entry.dstpt));
	} else if (entry.proto == "icmp") {
		string type, code, id, tmp;
		split('/',entry.state,type,tmp);
		split(' ',tmp,code,tmp);
		split('(',tmp,tmp,id);
		split(')',id,id,tmp);

		nfct_set_attr_u8(ct, ATTR_ICMP_TYPE, atoi(type.c_str()));
		nfct_set_attr_u8(ct, ATTR_ICMP_CODE, atoi(code.c_str()));
		nfct_set_attr_u16(ct, ATTR_ICMP_ID, atoi(id.c_str()));
	}

	ret = nfct_query(cth, NFCT_Q_DESTROY, ct);
	if (ret < 0) {
		string msg = "Failed to delete state: ";
		msg += strerror(errno);
		c_warn(win, msg.c_str(), flags);
	}

}
#endif


