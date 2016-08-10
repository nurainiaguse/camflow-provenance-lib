all:
	cd ./simplelogger && $(MAKE) all
	cd ./threadpool && $(MAKE) all
	cd ./src && $(MAKE) all
	cd ./service && $(MAKE) all
	cd ./tool && $(MAKE) all

clean:
	cd ./simplelogger && $(MAKE) clean
	cd ./threadpool && $(MAKE) clean
	cd ./src && $(MAKE) clean
	cd ./service && $(MAKE) clean
	cd ./tool && $(MAKE) clean

prepare:
	cd ./simplelogger && $(MAKE) prepare
	cd ./threadpool && $(MAKE) prepare

install:
	cd ./service && sudo $(MAKE) install
	cd ./tool && sudo $(MAKE) install
