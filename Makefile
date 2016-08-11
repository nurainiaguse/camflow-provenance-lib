all:
	cd ./simplelogger && $(MAKE) all
	cd ./threadpool && $(MAKE) all
	cd ./src && $(MAKE) all
	cd ./tool && $(MAKE) all
	cd ./service && $(MAKE) all

clean:
	cd ./simplelogger && $(MAKE) clean
	cd ./threadpool && $(MAKE) clean
	cd ./src && $(MAKE) clean
	cd ./tool && $(MAKE) clean
	cd ./service && $(MAKE) clean

prepare:
	cd ./simplelogger && $(MAKE) prepare
	cd ./threadpool && $(MAKE) prepare

install:
	cd ./service && sudo $(MAKE) install
	cd ./tool && sudo $(MAKE) install
	cd ./src && sudo $(MAKE) install
	cd ./include && sudo $(MAKE) install
