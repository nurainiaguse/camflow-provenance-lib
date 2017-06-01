Summary: CamFlow userspace library
Name: camflow-provenance-lib
Version: 0.3.2
Release: 1
Group: audit/camflow
License: GPLv3
Source: %{expand:%%(pwd)}
BuildRoot: %{_topdir}/BUILD/%{name}-%{version}-%{release}

%description
%{summary}

%prep
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/local/include
cd $RPM_BUILD_ROOT
cp -f %{SOURCEURL0}/src/provenancelib.a ./usr/bin/provenancelib.a
cp -f %{SOURCEURL0}/include/provenancelib.h ./usr/local/include/provenancelib.h
cp -f %{SOURCEURL0}/include/provenancefilter.h ./usr/local/include/provenancefilter.h
cp -f %{SOURCEURL0}/include/provenanceutils.h ./usr/local/include/provenanceutils.h
cp -f %{SOURCEURL0}/include/provenancePovJSON.h ./usr/local/include/provenancePovJSON.h

%clean
rm -r -f "$RPM_BUILD_ROOT"

%files
%defattr(644,root,root)
/usr/bin/provenancelib.a
/usr/local/include/provenancelib.h
/usr/local/include/provenancefilter.h
/usr/local/include/provenanceutils.h
/usr/local/include/provenancePovJSON.h
