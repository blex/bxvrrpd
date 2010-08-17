CC=gcc -std=gnu99
#CC=clang -std=gnu99
CFLAGS=-Wall -Werror -O2 -DDMSG
LDFLAGS=-lpthread

RM=rm -rf
STRIP=strip -s
INSTALL=install

EXE=bxvrrpd2 bxvrrpd3
V2OBJS=vrrp_v2.o
V3OBJS=vrrp_v3.o
OBJS=main.o vrrp_common.o ifconfig.o arp.o iproute.o libnetlink.o ll_map.o daemon.o

all: ${EXE}

bxvrrpd2: ${OBJS} ${V2OBJS}
	${CC} ${LDFLAGS} $^ -o $@

bxvrrpd3: ${OBJS} ${V3OBJS}
	${CC} ${LDFLAGS} $^ -o $@

.PHONY: clean strip
clean:
	${RM} *.o ${EXE}

strip:
	${STRIP} ${EXE}

install:
	${INSTALL} ${EXE} ${INSTALL_DIR}
