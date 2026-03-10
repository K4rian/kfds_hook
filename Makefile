CC      = gcc
CFLAGS  = -D_GNU_SOURCE -std=gnu99 -m32 -fPIC -O1 -Wall -Wextra -g
CFLAGS  += -Ivendor
LDFLAGS = -shared -lpthread -m32

OUT     = kfds_hook.so
SRCS    = src/kfds_hook.c \
          src/hook_config.c \
          src/hook_engine.c \
          src/hook_log.c \
          src/hook_trampoline.c \
          src/hook_ucs2.c \
		  vendor/inih/ini.c

.PHONY: all clean

all: $(OUT)
	@echo ""
	@echo "Built $(OUT)"
	@echo "Run with:"
	@echo "  LD_LIBRARY_PATH=. LD_PRELOAD=\$$(pwd)/$(OUT) ./ucc-bin-real server KF-WestLondon.rom?game=KFmod.KFGameType?VACSecured=true?MaxPlayers=6 ini=KillingFloor.ini -nohomedir"

$(OUT): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(OUT)