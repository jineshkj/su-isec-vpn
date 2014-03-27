#
# Makefile for ivpn software developed for VPN Lab 
# of Internet Security course
#

TARGET   = ivpn
SOURCES  = ivpn.c
OBJS    := $(patsubst %.c,%.o,$(SOURCES))

$(TARGET): $(OBJS)
	cc -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)
