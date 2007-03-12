/*
  iptstate.cc
  IPTables State

  -----------------------------------

  Copyright (C) 2002 Phil Dibowitz

  This software is provided 'as-is', without any express or
  implied warranty. In no event will the authors be held
  liable for any damages arising from the use of this software.

  Permission is granted to anyone to use this software for any
  purpose, including commercial applications, and to alter it
  and redistribute it freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you
  must not claim that you wrote the original software. If you use
  this software in a product, an acknowledgment in the product
  documentation would be appreciated but is not required.

  2. Altered source versions must be plainly marked as such, and
  must not be misrepresented as being the original software.

  3. This notice may not be removed or altered from any source
  distribution.

  -----------------------------------

  The idea of statetop comes from IP Filter by Darren Reed.

  This package's main purpose is to provide a state-top type
  interface for IP Tables. I've added in the "single run"
  option since there's no nice way to do that either.

*/ 

#include <iostream>
#include <time.h>
#include <string>
#include <vector>
#include <stdlib.h>
#include <fstream.h>
#include <ncurses.h>
// note some versions of gcc
// won't take sys/select.h
// or time.h, but take sys/time.h
#include <sys/time.h>
#include <getopt.h>
#include <netdb.h>
using namespace std;

//
// GLOBAL CONSTANTS
//
const string VERSION="1.0.1";

//
// FUNCTIONS AND STRUCTS
// Why can't structs be referenced now and
// defined later? I hate that.
//
struct table {
	string src, dst, srcpt, dstpt, proto, state, ttl;
};
void split(char s, string line, string &p1, string &p2);
void splita(char s, string line, vector<string> &result);
int src_sort(const void *a, const void *b);
int dst_sort(const void *a, const void *b);
int proto_sort(const void *a, const void *b);
int state_sort(const void *a, const void *b);
int ttl_sort(const void *a, const void *b);
int src_rsort(const void *a, const void *b);
int dst_rsort(const void *a, const void *b);
int proto_rsort(const void *a, const void *b);
int state_rsort(const void *a, const void *b);
int ttl_rsort(const void *a, const void *b);

//
// MAIN
//
int main(int argc, char *argv[]) {

// Variables
string line, src, dst, srcpt, dstpt, proto, code, type, state, 
	ttl, mins, secs, hrs, sorting, crap;
char min[5], sec[5], hr[5];
vector<table> stable(50);
int seconds=0, minutes=0, hours=0, num, maxx, maxy, temp, sortby=0, rate=1;
vector<string> fields(50);
timeval selecttimeout;
fd_set readfd;
bool are_hours = false, single = false, gotsort=false, reverse=false;


// Command Line Arguments
while ((temp = getopt(argc,argv,"shr:b:")) != EOF) {
	switch (temp) {
		case 's':
			single = true;
			break;
		case 'b':
			crap = optarg;
			gotsort = true;
			break;
		case 'r':
			rate = atoi(optarg);
			break;
		case 'h':
			cout << "IPTables State Version " << VERSION << endl;
			cout << "Usage: iptstate [-sh] [-r rate] [-b [d|p|s|t]]\n";
			cout << "	s: single run (no ncurses)\n";
			cout << "	h: this help message\n";
			cout << "	r: refresh rate, followed by rate in seconds\n";
			cout << "           (for statetop, not applicable for -s)\n";
			cout << "	b: sort by\n";
			cout << "	   d: Destination IP\n";
			cout << "	   p: Protocol\n";
			cout << "	   s: State\n";
			cout << "	   t: TTL\n";
			cout << "	   (to sort by Source IP, don't use -b)\n";
			exit(0);
			break;
	}
}

if (gotsort) {
	if (crap == "d")
		sortby=1;
	else if (crap == "p")
		sortby=2;
	else if (crap == "s")
		sortby=3;
	else if (crap == "t")
		sortby=4;
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
	num = 0;
	
	// Open the file
	ifstream input("/proc/net/ip_conntrack");
	while (getline(input,line) && num < 50) {
		splita(' ',line,fields);

		// Read stuff into the array
		// that's always in the same place
		// regardless of protocol

		// Get the protocol number from field[1]
		// We don't want to get it from field[0] because
		// ip_conntrack doesn't seem to support this field
		// for anything other than tcp, udp, and icmp
		stable[num].proto = getprotobynumber(atoi(fields[1].c_str()))->p_name;
		
		// ttl
		seconds = atoi(fields[2].c_str());
		minutes = seconds/60;
		if (minutes > 59) {
			are_hours = true;
			hours = minutes/60;
			minutes = minutes%60;
		}
		seconds = seconds%60;
		//want strings
		sprintf(min,"%i",minutes);
		sprintf(sec,"%i",seconds);
		mins = min;
		secs = sec;
		if (are_hours == true) {
			sprintf(hr,"%i",hours);
			hrs = hr;
			stable[num].ttl = hrs + ":" + mins + ":" + secs;
		} else {
			stable[num].ttl = "0:" + mins + ":" + secs;
		}
		are_hours = false;

		// OK, proto dependent stuff
		if (stable[num].proto == "tcp") {
			split('=',fields[4],crap,src);
			split('=',fields[5],crap,dst);
			split('=',fields[6],crap,srcpt);
			split('=',fields[7],crap,dstpt);
			split('=',fields[3],crap,state);
	
			stable[num].src = src + "," + srcpt;
			stable[num].dst = dst + "," + dstpt;
			stable[num].state = state;
			
		} else if (stable[num].proto == "udp") {
			split('=',fields[3],crap,src);
			split('=',fields[4],crap,dst);
			split('=',fields[5],crap,srcpt);
			split('=',fields[6],crap,dstpt);
	
			stable[num].src = src + "," + srcpt;
			stable[num].dst = dst + "," + dstpt;
			stable[num].state = "";

		} else if (stable[num].proto == "icmp") {
			split('=',fields[3],crap,src);
			split('=',fields[4],crap,dst);
			split('=',fields[5],crap,type);
			split('=',fields[6],crap,code);

			stable[num].state = type + "/" + code;
			stable[num].src = src;
			stable[num].dst = dst;

		} else {
			// If we're not TCP, or UDP
			// There's no ports involved
			split('=',fields[3],crap,src);
			split('=',fields[4],crap,dst);

			stable[num].src = src;
			stable[num].dst = dst;
		}

		// How many lines have we printed?
		num++;

	} // end while (getline)
	input.close(); // close the ip_conntrack

	//sort the fucker
	if (!reverse) {
		if (sortby == 0)
			qsort(&(stable[0]),num,sizeof(table),src_sort);
		else if (sortby == 1)
			qsort(&(stable[0]),num,sizeof(table),dst_sort);
		else if (sortby == 2)
			qsort(&(stable[0]),num,sizeof(table),proto_sort);
		else if (sortby == 3)
			qsort(&(stable[0]),num,sizeof(table),state_sort);
		else if (sortby == 4)
			qsort(&(stable[0]),num,sizeof(table),ttl_sort);
	} else {
		if (sortby == 0)
			qsort(&(stable[0]),num,sizeof(table),src_rsort);
		else if (sortby == 1)
			qsort(&(stable[0]),num,sizeof(table),dst_rsort);
		else if (sortby == 2)
			qsort(&(stable[0]),num,sizeof(table),proto_rsort);
		else if (sortby == 3)
			qsort(&(stable[0]),num,sizeof(table),state_rsort);
		else if (sortby == 4)
			qsort(&(stable[0]),num,sizeof(table),ttl_rsort);
	}

	//define 'sorting'
	if (sortby == 0)
		sorting ="SrcIP";
	else if (sortby == 1)
		sorting = "DstIP";
	else if (sortby == 2)
		sorting = "Proto";
	else if (sortby == 3)
		sorting = "State";
	else if (sortby == 4)
		sorting = "TTL";
	else
		sorting = "??unkown??";
	
	// if in single line mode, do everything and exit
	if (single) {
		// print the state table
		cout << "IP Tables State Top -- Sort by: " << sorting << endl;;

		// although I SHOULD use cout for formatted printing
		// this makes it easy to change printw and printf statements
		// at the same time
		printf("%-21s %-21s %-7s %-12s %-7s\n", "Source IP", "Destination IP", "Proto", "State", "TTL");
		for (temp=0; temp < num; temp++) {
			printf("%-21s %-21s %-7s %-12s %-7s\n", stable[temp].src.c_str(), stable[temp].dst.c_str(), stable[temp].proto.c_str(), stable[temp].state.c_str(), stable[temp].ttl.c_str());
			if (temp >= maxy-4)
				break;
		}
		exit(0);
	}


	// From here on out we're not in single
	// run mode, so lets do the curses stuff
	erase();
	getmaxyx(stdscr, maxy, maxx);
	move (0,0);

	// this is ugly, and I'll fix it later
	for (temp=0;temp<(maxx/2)-10;temp++) {
		printw(" ");
	}
	attron(A_BOLD);
	printw("IPTables - State Top\n");

	// Print headers
	printw("Version: ");
	attroff(A_BOLD);
	printw("%-13s", VERSION.c_str());
	attron(A_BOLD);
	printw("Sort: ");
	attroff(A_BOLD);
	if (reverse)
		sorting = sorting + " reverse";
	printw("%-16s", sorting.c_str());
	attron(A_BOLD);
	printw("s");
	attroff(A_BOLD);
	printw("%-20s\n", " to change sorting");
	attron(A_BOLD);
	printw("%-21s %-21s %-7s %-12s %-7s\n", "Source IP", "Destination IP", "Proto", "State", "TTL");
	attroff(A_BOLD);

	//print the state table
	for (temp=0; temp < num; temp++) {
		printw("%-21s %-21s %-7s %-12s %-7s\n", stable[temp].src.c_str(), stable[temp].dst.c_str(), stable[temp].proto.c_str(), stable[temp].state.c_str(), stable[temp].ttl.c_str());
		if (temp >= maxy-4)
			break;
	}
	
	refresh();

	//check for key presses for one second
	//or whatever the user said
	selecttimeout.tv_sec = rate;
	selecttimeout.tv_usec = 0;
	FD_ZERO(&readfd);
	FD_SET(0, &readfd);
	select(1,&readfd, NULL, NULL, &selecttimeout);
	if (FD_ISSET(0, &readfd)) {
		temp = wgetch(stdscr);
		if (temp == 'q') {
			break;
		} else if (temp == 's') {
			if (sortby <4)
				sortby++;
			else
				sortby=0;
		} else if (temp == 'r') {
			if (reverse == true)
				reverse = false;
			else
				reverse = true;
		}
	}


} // end while(1)

// Take down the curses stuff
printw("\n");
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
	while (temp.find(s) != string::npos) {
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

// what follows are the sort
// functions that qsort requires
int src_sort(const void *a, const void *b) {
	if(((table *)a)->src == ((table *)b)->src) {
		return 0;
	} else if (((table *)a)->src > ((table *)b)->src) {
		return 1;
	}
	return -1;
}
int dst_sort(const void *a, const void *b) {
	if(((table *)a)->dst == ((table *)b)->dst) {
		return 0;
	} else if (((table *)a)->dst > ((table *)b)->dst) {
		return 1;
	}
	return -1;
}
int proto_sort(const void *a, const void *b) {
	if(((table *)a)->proto == ((table *)b)->proto) {
		return 0;
	} else if (((table *)a)->proto > ((table *)b)->proto) {
		return 1;
	}
	return -1;
}
int state_sort(const void *a, const void *b) {
	if(((table *)a)->state == ((table *)b)->state) {
		return 0;
	} else if (((table *)a)->state > ((table *)b)->state) {
		return 1;
	}
	return -1;
}
int ttl_sort(const void *a, const void *b) {
	if(((table *)a)->ttl == ((table *)b)->ttl) {
		return 0;
	} else if (((table *)a)->ttl > ((table *)b)->ttl) {
		return 1;
	}
	return -1;
}

//and now their counterparts
int src_rsort(const void *a, const void *b) {
	if(((table *)a)->src == ((table *)b)->src) {
		return 0;
	} else if (((table *)a)->src < ((table *)b)->src) {
		return 1;
	}
	return -1;
}
int dst_rsort(const void *a, const void *b) {
	if(((table *)a)->dst == ((table *)b)->dst) {
		return 0;
	} else if (((table *)a)->dst < ((table *)b)->dst) {
		return 1;
	}
	return -1;
}
int proto_rsort(const void *a, const void *b) {
	if(((table *)a)->proto == ((table *)b)->proto) {
		return 0;
	} else if (((table *)a)->proto < ((table *)b)->proto) {
		return 1;
	}
	return -1;
}
int state_rsort(const void *a, const void *b) {
	if(((table *)a)->state == ((table *)b)->state) {
		return 0;
	} else if (((table *)a)->state < ((table *)b)->state) {
		return 1;
	}
	return -1;
}
int ttl_rsort(const void *a, const void *b) {
	if(((table *)a)->ttl == ((table *)b)->ttl) {
		return 0;
	} else if (((table *)a)->ttl < ((table *)b)->ttl) {
		return 1;
	}
	return -1;
}
