#
# Makefile for ivpn software developed for VPN Lab 
# of Internet Security course
#

TARGET   = ivpn

SOURCES  = ivpn.c
SOURCES += util.c
SOURCES += server.c
SOURCES += client.c

OBJS    := $(patsubst %.c,%.o,$(SOURCES))

CFLAGS += -Wall -Werror

all: install

install: $(TARGET)
	cp -v $< /tmp
	
$(TARGET): $(OBJS)
	cc -o $@ $^

clean:
	rm -f $(TARGET) $(OBJS) *~
