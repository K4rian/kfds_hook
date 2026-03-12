CC         = gcc
CFLAGS     = -D_GNU_SOURCE -std=gnu99 -m32 -fPIC -O1 -Wall -Wextra -g
CFLAGS    += -Ivendor
CFLAGS    += -DJSMN_STATIC
LDFLAGS    = -shared -lpthread -m32

OUT        = kfds_hook.so
OUT_DEBUG  = debug_kfds_hook.so
SRCS_ALL   = $(wildcard src/*.c) $(wildcard vendor/inih/*.c)
SRCS_DEBUG = $(filter %_debug.c, $(SRCS_ALL))
SRCS       = $(filter-out %_debug.c, $(SRCS_ALL))

.PHONY: all debug clean

all: $(OUT)
	@echo ""
	@echo "Built $(OUT)"
	@echo "Run with:"
	@echo "  LD_LIBRARY_PATH=. LD_PRELOAD=\$$(pwd)/$(OUT) ./ucc-bin-real server KF-WestLondon.rom?game=KFmod.KFGameType?VACSecured=true?MaxPlayers=6 ini=KillingFloor.ini -nohomedir"

debug: clean
	$(CC) $(CFLAGS) -DDEBUG $(LDFLAGS) -o $(OUT_DEBUG) $(SRCS) $(SRCS_DEBUG)
	@echo "[DEBUG] Built $(OUT_DEBUG)"
	@echo "Run with:"
	@echo "  LD_LIBRARY_PATH=. LD_PRELOAD=\$$(pwd)/$(OUT_DEBUG) ./ucc-bin-real server KF-WestLondon.rom?game=KFmod.KFGameType?VACSecured=true?MaxPlayers=6 ini=KillingFloor.ini -nohomedir"

$(OUT): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(OUT) $(OUT_DEBUG)