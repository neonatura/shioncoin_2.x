Name:           share-coin
Version:        2.26
Release:        1%{?dist}
Summary:        A libshare compatible USDe server.

Group:          System Environment/Libraries
License:        GPLv3+
URL:            http://www.sharelib.net/
Source0:        http://www.sharelib.net/release/share-coin-2.26.tar.gz

#BuildRequires:  gcc
#Requires:       info 

%description




%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'


%check
make check


%clean
rm -rf $RPM_BUILD_ROOT


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%doc
%{_sbindir}/shcoind
%{_bindir}/shcoin
%{_docdir}/share-coin/shcoin_html.tar.xz

%changelog
* Fri May  9 2015 Neo Natura <support@neo-natura.com> - 2.26
- Initial RPM release version of this package.
