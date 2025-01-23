.PHONY: default
default: include/client.h include/controller.h \
		 src/client.c src/controller.c src/main.c
	gcc -g -O3 -I include -I third_party -I $$SDE_INSTALL/include -L /usr/local/lib \
	-L $$SDE_INSTALL/lib src/client.c src/controller.c src/main.c \
	-o l7lb_control_plane -ldriver -lbfsys -lbfutils -lbf_switchd_lib -lcjson \
	-Wl,-rpath=$$SDE_INSTALL/lib -rdynamic -Wl,-rpath=/usr/local.lib -rdynamic