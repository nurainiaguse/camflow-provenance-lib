version=0.3.2

all:
	cd ./threadpool && $(MAKE) all
	cd ./src && $(MAKE) all

clean:
	cd ./threadpool && $(MAKE) clean
	cd ./src && $(MAKE) clean
	rm -rf output

prepare:
	cd ./threadpool && $(MAKE) prepare
	cd ./uthash && $(MAKE) prepare

install:
	cd ./src && sudo $(MAKE) install
	cd ./include && sudo $(MAKE) install

rpm:
	mkdir -p ~/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}
	cp -f ./camflow-provenance-lib.spec ~/rpmbuild/SPECS/camflow-provenance-lib.spec
	rpmbuild -bb camflow-provenance-lib.spec
	mkdir -p output
	cp ~/rpmbuild/RPMS/x86_64/* ./output

publish:
	cd ./output && package_cloud push camflow/provenance/fedora/25 camflow-provenance-lib-$(version)-1.x86_64.rpm
