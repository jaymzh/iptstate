/*
* iptstate.cc
* IPTables State
*
*  -----------------------------------
*
* Copyright (C) 2002 - 2005 Phil Dibowitz
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
*  -----------------------------------
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
// Begin old-style includes includes
#include <time.h>
#include <stdlib.h>
#include <ncurses.h>
// note some versions of gcc
// won't take sys/select.h
// or time.h, but take sys/time.h
#include <sys/time.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <math.h>
using namespace std;

//
// GLOBAL CONSTANTS
//
const string VERSION="1.4";
// Maybe one day I'll get this from kernel params
const int MAXCONS=16384;
const int MAXFIELDS=20;

//
// GLOBAL VARS
//
int sort_factor = 1;
bool handle_resize = 0;

//
// FUNCTIONS AND STRUCTS
//
struct table {
	string proto, state, ttl, sname, dname;
	in_addr src, dst;
	int srcpt, dstpt;
};
void split(char s, string line, string &p1, string &p2);
void splita(char s, string line, vector<string> &result);
int digits(int x);
void printline(table stable, bool lookup, bool single, char *format);
void check_ip(const char *arg);

int src_sort(const void *a, const void *b);
int dst_sort(const void *a, const void *b);
int srcpt_sort(const void *a, const void *b);
int dstpt_sort(const void *a, const void *b);
int proto_sort(const void *a, const void *b);
int state_sort(const void *a, const void *b);
int ttl_sort(const void *a, const void *b);
int sname_sort(const void *a, const void *b);
int dname_sort(const void *a, const void *b);

//
// MAIN
//
int main(int argc, char *argv[]) {

// Variables
string line, src, dst, srcpt, dstpt, proto, code, type, state, 
	ttl, mins, secs, hrs, sorting, tmpstring, dst_filter, src_filter;
char ttlc[11], foo[3], format[30] = "%-21s %-21s %-7s %-12s %-7s\n";
vector<table> stable(MAXCONS);
vector<string> fields(MAXFIELDS);
int seconds=0, minutes=0, hours=0, num, maxx, maxy, tmpint, sortby=0, rate=1,
	numtcp=0, numudp=0, numicmp=0, numother=0, reslength=21;
timeval selecttimeout;
fd_set readfd;
bool single = false, totals = false, lookup = false, skiplb = false,
	defaultsize = false, skipdns = false, tag_truncate = false,
	filter_src = false, filter_dst = false;
struct hostent* hostinfo = NULL;
struct protoent* pe = NULL;
unsigned int length;


// Command Line Arguments
while ((tmpint = getopt(argc,argv,"sdfhtlRr:b:LD:S:")) != EOF) {
	switch (tmpint) {
		case 's':
			single = true;
			break;
		case 't':
			totals = true;
			break;
		case 'b':
			if (*optarg == 'd')
				sortby=2;
			else if (*optarg == 'p')
				sortby=4;
			else if (*optarg == 's')
				sortby=5;
			else if (*optarg == 't')
				sortby=6;
			break;
		case 'R':
			sort_factor = -1;
			break;
		case 'r':
			rate = atoi(optarg);
			break;
		case 'l':
			lookup = true;
			break;
		case 'f':
			skiplb = true;
			break;
		case 'd':
			defaultsize = true;
			break;
		case 'L':
			skipdns = true;
			break;
		case 'S':
			if (optarg == NULL)
				break;
			check_ip(optarg);
			filter_src = true;
			src_filter = optarg;
			break;
		case 'D':
			if (optarg == NULL)
				break;
			check_ip(optarg);
			filter_dst = true;
			dst_filter = optarg;
			break;
		case 'h':
			cout << "IPTables State Version " << VERSION << endl;
			cout << "Usage: iptstate [-dfhlLRst] [-b [d|p|s|t]] [-D <address>] [-S <address>] [-r <seconds>]\n";
			cout << "	b: Sort by\n";
			cout << "	   d: Destination IP (or Name)\n";
			cout << "	   p: Protocol\n";
			cout << "	   s: State\n";
			cout << "	   t: TTL\n";
			cout << "	   (to sort by Source IP (or Name), don't use -b)\n\n";
			cout << "	d: Do not dynamically choose sizing, use default\n";
			cout << "	D: Only show states with a destination of the IP address given\n";
			cout << "	f: Filter loopback\n";
			cout << "	h: This help message\n";
			cout << "	l: Show hostnames instead of IP addresses\n";
			cout << "	L: Hide DNS lookups\n";
			cout << "	r: Refresh rate, followed by rate in seconds\n";
			cout << "           (for statetop, not applicable for -s)\n";
			cout << "	R: reverse sort order\n";
			cout << "	s: Single run (no curses)\n";
			cout << "	S: Only show states with a source of the IP address given\n";
			cout << "	t: Print totals\n";
			cout << "";
			cout << "See man iptstate(1) for more information.\n";
			exit(0);
			break;
	}
}

if (rate < 0 || rate > 60) {
	rate = 1;
}

// Initialize Curses Stuff
if (!single) {
	initscr();
	cbreak();
	noecho();
}


// We want to keep going until the user stops us 
// unless they use single run mode
// in which case, we'll deal with that down below
while(1) {

	// Lets get the terminal size in the most
	// reliable way possible
	if (!single) {          
		getmaxyx(stdscr, maxy, maxx);
	} else {                             
		maxx=72;
		if (getenv("COLS"))
			maxx=atoi(getenv("COLS"));
	}

	// OK, now we have maxy and maxx, lets use 'em
	if (defaultsize && maxx >= 72) {
		strncpy(format,"%-21s %-21s %-7s %-12s %-7s\n",30);
		reslength = 21;
	} else if (maxx > 72) {                                      
		// TTL, proto and state should probably stay constant
		// so we won't worry about them. They're total       
		// is 30. We want a space on either side for
		// aesthetics, plus make room for xterm scrollbars
		// and the like
		tmpint=(maxx-34)/2;
		if (tmpint > 99) { 
			tmpint = 99;
	               }                 
		snprintf(foo,3,"%2i",tmpint);
		// The string() allows the contact here for the char[3]
		tmpstring = string() + "\%-" + foo + "s \%-" + foo + "s \%-7s \%-12s \%-7s\n";
		strncpy(format,tmpstring.c_str(),30);
		reslength=tmpint;
	} else if (maxx < 72) {
		nocbreak();                  
		endwin();  
		cout << endl;
		cout << "I'm sorry, your terminal must be atleast 72 columns wide to run iptstate.\n";
		exit(0);
	}


	// And now on with the show...
	num = 0;
	numtcp = 0;
	numudp = 0;
	numicmp = 0;
	numother = 0;

	// Open the file
	ifstream input("/proc/net/ip_conntrack");
	while (getline(input,line) && num < MAXCONS) {
		
		//Clear this element in the array
		//To avoid false data
		stable[num].sname = "";
		stable[num].dname = "";
		stable[num].srcpt = 0;
		stable[num].dstpt = 0;
		stable[num].proto = "";
		stable[num].ttl = "";
		stable[num].state = "";

		/* 
		 * BEGIN PARSING
		 */
		splita(' ',line,fields);

		// Read stuff into the array
		// that's always in the same place
		// regardless of protocol

		// Get the protocol number from field[1]
		// We don't want to get it from field[0] because
		// ip_conntrack doesn't seem to support this field
		// for anything other than tcp, udp, and icmp
		if ((pe = getprotobynumber(atoi(fields[1].c_str()))) == NULL) {
			stable[num].proto = "unknown";
		} else {
			stable[num].proto = pe->p_name;
		}
				
		// ttl
		seconds = atoi(fields[2].c_str());
		minutes = seconds/60;
		hours = minutes/60;
		minutes = minutes%60;
		seconds = seconds%60;
		//want strings
		snprintf(ttlc,11,"%3i:%02i:%02i",hours,minutes,seconds);
		stable[num].ttl = ttlc; 

		// OK, proto dependent stuff
		if (stable[num].proto == "tcp") {
			split('=',fields[4],tmpstring,src);
			split('=',fields[5],tmpstring,dst);
			split('=',fields[6],tmpstring,srcpt);
			split('=',fields[7],tmpstring,dstpt);
			split('=',fields[3],tmpstring,state);
	
			inet_aton(src.c_str(), &stable[num].src);
			inet_aton(dst.c_str(), &stable[num].dst);
			stable[num].srcpt = atoi(srcpt.c_str());
			stable[num].dstpt = atoi(dstpt.c_str());
			stable[num].state = state;

			numtcp++;
			
		} else if (stable[num].proto == "udp") {
			split('=',fields[3],tmpstring,src);
			split('=',fields[4],tmpstring,dst);
			split('=',fields[5],tmpstring,srcpt);
			split('=',fields[6],tmpstring,dstpt);

			inet_aton(src.c_str(), &stable[num].src);
			inet_aton(dst.c_str(), &stable[num].dst);
			stable[num].srcpt = atoi(srcpt.c_str());
			stable[num].dstpt = atoi(dstpt.c_str());
			stable[num].state = "";

			numudp++;

		} else if (stable[num].proto == "icmp") {
			split('=',fields[3],tmpstring,src);
			split('=',fields[4],tmpstring,dst);
			split('=',fields[5],tmpstring,type);
			split('=',fields[6],tmpstring,code);

			inet_aton(src.c_str(), &stable[num].src);
			inet_aton(dst.c_str(), &stable[num].dst);
			stable[num].state = type + "/" + code;

			numicmp++;

		} else {
			// If we're not TCP, or UDP
			// There's no ports involved
			split('=',fields[3],tmpstring,src);
			split('=',fields[4],tmpstring,dst);

			inet_aton(src.c_str(), &stable[num].src);
			inet_aton(dst.c_str(), &stable[num].dst);

			numother++;

		}

		/*
		 * END PARSING
		 */

		/*
		 * BEGIN FILTERING
		 */
		if (skiplb && (!strcmp("127.0.0.1",src.c_str())))
			continue;

		if (skipdns && (!strcmp("53",dstpt.c_str())))
			continue;

		if (filter_src && (src != src_filter))
			continue;

		if (filter_dst && (dst != dst_filter))
			continue;

		/*
		 * END FILTERING
		 */

		// Resolve Names if we need to
		if (lookup) {
			if ((hostinfo = gethostbyaddr((char *)&stable[num].src,sizeof(stable[num].src), AF_INET)) != NULL) {
				stable[num].sname = hostinfo->h_name;
				if (stable[num].proto == "tcp" || stable[num].proto == "udp") {
					// We truncate the Source from the right
					// Since they are all likely from the same
					// domain anyway
					// Note Length is reslength - 1(for comma) - 1 (need a space) - port
					length = reslength - 2 - digits(stable[num].srcpt);
					if (stable[num].sname.size() > length) {
						stable[num].sname = stable[num].sname.substr(0,length);
						if (tag_truncate)
							stable[num].sname[length-1] = '+';
					}
				} else {
					length = reslength;
					if (stable[num].sname.size() > length) {
						stable[num].sname = stable[num].sname.substr(0,length);
						if (tag_truncate)
							stable[num].sname[length-1]='+';
					}
				}
			} else {
				//this else is here for troubleshooting
				//herror("gethostbyaddr");
			}
			if ((hostinfo = gethostbyaddr((char *)&stable[num].dst,sizeof(stable[num].dst),AF_INET)) != NULL) {
				stable[num].dname = hostinfo->h_name;
				if (stable[num].proto == "tcp" || stable[num].proto == "udp") {
					// We truncate the Destination from the left
					// Since "images.server4" doens't help -- we want domains
					length = reslength - 1 - digits(stable[num].dstpt);
					if (stable[num].dname.size() > length) {
						stable[num].dname = stable[num].dname.substr(stable[num].dname.size()-length,length);
						if (tag_truncate)
							stable[num].dname[0] = '+';
					}
				} else {
					length = reslength;
					if (stable[num].dname.size() > length) {
						stable[num].dname = stable[num].dname.substr(stable[num].dname.size()-length,length);
						if (tag_truncate)
							stable[num].dname[0] = '+';
					}
				}
			} else {
				//herror("gethostbyaddr");
			}
			
		}

		// How many lines have we printed?
		num++;

	} // end while (getline)
	input.close(); // close the ip_conntrack

	//sort the fucker AND define 'sorting' (recently combined)
	if (sortby == 0) {
		if (lookup) {
			qsort(&(stable[0]),num,sizeof(table),sname_sort);
			sorting = "SrcName";
		} else {
			qsort(&(stable[0]),num,sizeof(table),src_sort);
			sorting = "SrcIP";
		}
	} else if (sortby == 1) {
		qsort(&(stable[0]),num,sizeof(table),srcpt_sort);
		sorting = "SrcPort";
	} else if (sortby == 2) {
		if (lookup) {
			qsort(&(stable[0]),num,sizeof(table),dname_sort);
			sorting = "DstName";
		} else {
			qsort(&(stable[0]),num,sizeof(table),dst_sort);
			sorting = "DstIP";
		}
	} else if (sortby == 3) {
		qsort(&(stable[0]),num,sizeof(table),dstpt_sort);
		sorting = "DstPort";
	} else if (sortby == 4) {
		qsort(&(stable[0]),num,sizeof(table),proto_sort);
		sorting = "Proto";
	} else if (sortby == 5) {
		qsort(&(stable[0]),num,sizeof(table),state_sort);
		sorting = "State";
	} else if (sortby == 6) {
		qsort(&(stable[0]),num,sizeof(table),ttl_sort);
		sorting = "TTL";
	} else {
		//we should never get here
		sorting = "??unknown??";
	}

	if (sort_factor == -1)
		sorting = sorting + " reverse";
	


	// if in single line mode, do everything and exit
	if (single) {
		// print the state table
		cout << "IP Tables State Top -- Sort by: " << sorting << endl;;

		// although I SHOULD use cout for formatted printing
		// this makes it easy to change printw and printf statements
		// at the same time
		if (totals)
			printf("Total States: %i -- TCP: %i UDP: %i ICMP: %i OTHER: %i\n", num, numtcp, numudp, numicmp, numother);
		if (filter_src || filter_dst) {
			printf("Filters:   ");
			if (filter_src)  {
				printf("Source: %s",src_filter.c_str());
				if (filter_dst)
					printw(" -- ");
			}
			if (filter_dst )
				printf("Destination: %s",dst_filter.c_str());
			printf("\n");
		}
		printf(format, "Source", "Destination", "Proto", "State", "TTL");
		for (tmpint=0; tmpint < num; tmpint++) {
			printline(stable[tmpint],lookup,single,format);
		}
		exit(0);
	}

	// From here on out we're not in single
	// run mode, so lets do the curses stuff
	erase();
	move (0,0);

	// Why y comes BEFORE x I have NO clue
	move (0,maxx/2-10);
	attron(A_BOLD);
	printw("IPTables - State Top\n");

	// Print headers
	printw("Version: ");
	attroff(A_BOLD);
	printw("%-13s", VERSION.c_str());
	attron(A_BOLD);
	printw("Sort: ");
	attroff(A_BOLD);
	printw("%-16s", sorting.c_str());
	attron(A_BOLD);
	printw("s");
	attroff(A_BOLD);
	printw("%-20s\n", " to change sorting");
	if (totals)
		printw("Total States: %i -- TCP: %i UDP: %i ICMP: %i OTHER: %i\n",num,numtcp,numudp,numicmp,numother);
	if (filter_src || filter_dst) {
		attron(A_BOLD);
		printw("Filters:   ");
		attroff(A_BOLD);
		if (filter_src)  {
			printw("Source: %s",src_filter.c_str());
			if (filter_dst)
				printw(" -- ");
		}
		if (filter_dst )
			printw("Destination: %s",dst_filter.c_str());
		printw("\n");
	}

	attron(A_BOLD);
	printw(format, "Source", "Destination", "Proto", "State", "TTL");
	attroff(A_BOLD);

	//print the state table
	for (tmpint=0; tmpint < num; tmpint++) {
		printline(stable[tmpint],lookup,single,format);
		if (tmpint >= maxy-4 || (totals && tmpint >= maxy-5))
			break;
	}
	
	refresh();

	//check for key presses for one second
	//or whatever the user said
	selecttimeout.tv_sec = rate;
	selecttimeout.tv_usec = 0;
	// I don't care about fractions of seconds. I don't want them.
	FD_ZERO(&readfd);
	FD_SET(0, &readfd);
	select(1,&readfd, NULL, NULL, &selecttimeout);
	if (FD_ISSET(0, &readfd)) {
		tmpint = wgetch(stdscr);
		if (tmpint == 'q') {
			//EXIT
			break;
		} else if (tmpint == 's') {
			if (sortby <6)
				sortby++;
			else
				sortby=0;
		} else if (tmpint == 'r') {
			sort_factor = -sort_factor;
		} else if (tmpint == 'f') {
			skiplb = !skiplb;
		} else if (tmpint == 'l') {
			lookup = !lookup;
		} else if (tmpint == 't') {
			totals = !totals;
		} else if (tmpint == 'd') {
			defaultsize = !defaultsize;
		} else if (tmpint == 'n') {
			skipdns = !skipdns;
		} else if (tmpint == 'm') {
			tag_truncate = !tag_truncate;
		}
	}


} // end while(1)

// Take down the curses stuff
printw("\n");
curs_set(1);
nocbreak();
endwin();


// And we're done
return(0);

} // end main

///
/// BEGIN FUNCTIONS
///

// split a string into two strings based on the first occurance
// of any character
void split(char s, string line, string &p1, string &p2) {
	int pos = line.find(s);
	p1 = line.substr(0,pos);
	p2 = line.substr(pos+1,line.size()-pos);
}

// split a string into an array of strings based on 
// any character
void splita(char s, string line, vector<string> &result) {
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

// This determines the length of an integer (i.e. number of digits)
int digits(int x) {
	return (int) floor(log10((double)x))+1;
}

// what follows are the sort
// functions that qsort requires
int src_sort(const void *a, const void *b) {
	return sort_factor * memcmp(&((table *)a)->src, &((table *)b)->src, sizeof(uint32_t));
}
int dst_sort(const void *a, const void *b) {
	return sort_factor * memcmp(&((table *)a)->dst, &((table *)b)->dst, sizeof(uint32_t));
}
int srcpt_sort(const void *a, const void *b) {
	if(((table *)a)->srcpt == ((table *)b)->srcpt) {
		return 0;
	} else if (((table *)a)->srcpt > ((table *)b)->srcpt) {
		return sort_factor;
	}
	return -sort_factor;
}
int dstpt_sort(const void *a, const void *b) {
	if(((table *)a)->dstpt == ((table *)b)->dstpt) {
		return 0;
	} else if (((table *)a)->dstpt > ((table *)b)->dstpt) {
		return sort_factor;
	}
	return -sort_factor;
}
int proto_sort(const void *a, const void *b) {
	if(((table *)a)->proto == ((table *)b)->proto) {
		return 0;
	} else if (((table *)a)->proto > ((table *)b)->proto) {
		return sort_factor;
	}
	return -sort_factor;
}
int state_sort(const void *a, const void *b) {
	if(((table *)a)->state == ((table *)b)->state) {
		return 0;
	} else if (((table *)a)->state > ((table *)b)->state) {
		return sort_factor;
	}
	return -sort_factor;
}
int ttl_sort(const void *a, const void *b) {
	if(((table *)a)->ttl == ((table *)b)->ttl) {
		return 0;
	} else if (((table *)a)->ttl > ((table *)b)->ttl) {
		return sort_factor;
	}
	return -sort_factor;
}
int sname_sort(const void *a, const void *b) {
	if(((table *)a)->sname == ((table *)b)->sname) {
		return 0;
	} else if (((table *)a)->sname > ((table *)b)->sname) {
		return sort_factor;
	}
	return -sort_factor;
}
int dname_sort(const void *a, const void *b) {
	if(((table *)a)->dname == ((table *)b)->dname) {
		return 0;
	} else if (((table *)a)->dname > ((table *)b)->dname) {
		return sort_factor;
	}
	return -sort_factor;
}


void printline(table stable, bool lookup, bool single, char *format) {
	ostringstream buffer;
	buffer.str("");
	string src,dst;
	
	if (stable.proto == "tcp" || stable.proto == "udp") {
		if (lookup && (stable.sname != "")) {
			buffer << stable.sname << ":" << stable.srcpt;
		} else {
			buffer << inet_ntoa(stable.src) << ":" << stable.srcpt;
		}
		src = buffer.str();
		buffer.str("");
		if (lookup && (stable.dname != "")) {
			buffer << stable.dname << ":" << stable.dstpt;
		} else {
			buffer << inet_ntoa(stable.dst) << ":" << stable.dstpt;
		}
		dst = buffer.str();
		buffer.str("");
	} else {
		if (lookup && (stable.sname != "")) {
			src = stable.sname;
		} else {
			src = inet_ntoa(stable.src);
		}
		if (lookup && (stable.dname != "")) {
			dst = stable.dname;
		} else {
			dst = inet_ntoa(stable.dst);
		}
	}
	if (single)
		printf(format, src.c_str(), dst.c_str(), stable.proto.c_str(), stable.state.c_str(), stable.ttl.c_str());
	else
		printw(format, src.c_str(), dst.c_str(), stable.proto.c_str(), stable.state.c_str(), stable.ttl.c_str());	
}

void check_ip(const char *arg) {
	in_addr tmp_addr;
	if (inet_aton(arg,&tmp_addr) == 0) {
		cerr << "Invalid IP address: " << arg << endl;
		exit (-1);
	}
}

