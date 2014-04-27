#
# Makefile for ivpn software developed for VPN Lab 
# of Internet Security course
#

CLIENT = ivpn-client
SERVER = ivpn-server

COMMON  = util.c
COMMON += control.c
COMMON += log.c
COMMON += sslutil.c
COMMON += tcputil.c

CLI_SRC  = client.c
CLI_SRC += $(COMMON)

SRV_SRC  = server.c
SRV_SRC += $(COMMON)

CLI_OBJS    := $(patsubst %.c,%.o,$(CLI_SRC))
SRV_OBJS    := $(patsubst %.c,%.o,$(SRV_SRC))

CFLAGS  += -Wall -Werror
LDFLAGS += -lssl -lcrypto

all: install

install: $(CLIENT) $(SERVER)
	cp -v $(CLIENT) $(SERVER) /tmp
	
$(CLIENT): $(CLI_OBJS)
	cc -o $@ $^ $(LDFLAGS)

$(SERVER): $(SRV_OBJS)
	cc -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(CLIENT) $(SERVER) $(CLI_OBJS) $(SRV_OBJS) *~
