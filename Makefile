# N Scan Makefile
INCLUDES=-I include
INDENT_FLAGS=-br -ce -i4 -bl -bli0 -bls -c4 -cdw -ci4 -cs -nbfda -l100 -lp -prs -nlp -nut -nbfde -npsl -nss

OBJS = \
	release/main.o \
	release/tcpscan.o \
	release/forgetcp.o

all: host

internal: prepare
	@echo "  CC    src/main.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/main.c -o release/main.o
	@echo "  CC    src/tcpscan.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/tcpscan.c -o release/tcpscan.o
	@echo "  CC    src/forgetcp.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/forgetcp.c -o release/forgetcp.o
	@echo "  LD    release/nscan"
	@$(LD) -o release/nscan $(OBJS) -pthread $(LDFLAGS)

prepare:
	@mkdir -p release

host:
	@make internal \
		CC=gcc \
		LD=gcc \
		CFLAGS='-c -Wall -Wextra -O3 -ffunction-sections -fdata-sections' \
		LDFLAGS='-s -Wl,--gc-sections -Wl,--relax'

install:
	@cp -v release/nscan /usr/bin/nscan

uninstall:
	@rm -fv /usr/bin/nscan

indent:
	@indent $(INDENT_FLAGS) ./*/*.h
	@indent $(INDENT_FLAGS) ./*/*.c
	@rm -rf ./*/*~

clean:
	@echo "  CLEAN ."
	@rm -rf release

analysis:
	@scan-build make
	@cppcheck --force */*.h
	@cppcheck --force */*.c
