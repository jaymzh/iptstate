%define name iptstate
%define version	1.3
%define release 1

Name: %{name}
Summary: Display IP Tables state table information in a "top"-like interface
Version: %{version}
Release: %{release}
Group: Monitoring
License: zlib License
Source: http://www.phildev.net/iptstate/%{name}-%{version}.tar.gz
URL: http://www.phildev.net/iptstate/
BuildRoot: %{_tmppath}/%{name}-buildroot
BuildRequires: libncurses.so.5 libgpm.so.1

%description
 IP Tables State (iptstate) was originally written to
 impliment the "state top" feature of IP Filter.
 "State top" displays the states held by your stateful 
 firewall in a "top"-like manner.

 Since IP Tables doesn't have a built in way to easily
 display this information even once, an option was
 added to just display the state table once and exit.

%prep
rm -rf $RPM_BUILD_ROOT
%setup

%build
make

%install
make install PREFIX=$RPM_BUILD_ROOT/usr

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(755, root, bin, 755)
/usr/sbin/%{name}
/usr/share/man/man1/%{name}.1*
%doc README BUGS Changelog LICENSE CONTRIB WISHLIST

