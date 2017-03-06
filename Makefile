all:
	cd ./threadpool && $(MAKE) all
	cd ./src && $(MAKE) all
	cd ./service && $(MAKE) all

clean:
	cd ./threadpool && $(MAKE) clean
	cd ./src && $(MAKE) clean
	cd ./service && $(MAKE) clean

prepare:
	cd ./threadpool && $(MAKE) prepare
	cd ./uthash && $(MAKE) prepare

install:
	cd ./service && sudo $(MAKE) install
	cd ./src && sudo $(MAKE) install
	cd ./include && sudo $(MAKE) install

restart:
	cd ./service && sudo $(MAKE) restart
