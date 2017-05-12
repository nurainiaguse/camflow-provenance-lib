all:
	cd ./threadpool && $(MAKE) all
	cd ./src && $(MAKE) all

clean:
	cd ./threadpool && $(MAKE) clean
	cd ./src && $(MAKE) clean

prepare:
	cd ./threadpool && $(MAKE) prepare
	cd ./uthash && $(MAKE) prepare

install:
	cd ./src && sudo $(MAKE) install
	cd ./include && sudo $(MAKE) install
