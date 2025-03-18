PARAMS = sphincs-shake-256s
THASH = simple

LDLIBS=-lcrypto
CC=/usr/bin/g++
CXXFLAGS=-Wall -Wextra -Wpedantic -O3 -std=c++11 -Wconversion -DPARAMS=$(PARAMS) $(EXTRA_CFLAGS)

SOURCES =          address.c randombytes.c merkle.cpp wots.c wotsx1.cpp utils.cpp utilsx1.cpp sign.cpp counters.c PPRF/PunPRF.cpp PRG/prg.cpp AE/AES_GCM_SIV.cpp AE/aes_emulation_tables.c AE/aes_emulation.c AE/clmul_emulator.c FSDGS/func.cpp 
HEADERS = params.h address.h randombytes.h merkle.h wots.h wotsx1.h utils.h utilsx1.h api.h hash.h thash.h counters.h PPRF/PunPRF.h PRG/prg.h AE/AES_GCM_SIV.h AE/aes_emulation.h AE/clmul_emulator.h FSDGS/func.h FSDGS/MoMST.h

ifneq (,$(findstring shake,$(PARAMS)))
	SOURCES += fips202.c hash_shake.cpp thash_shake_$(THASH).c
	HEADERS += fips202.h
endif

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

BENCHMARK = test/benchmark

PPRFS = PPRF/main

PRGS=PRG/gen

AES=AE/authenc

FSDGSS=FSDGS/main

.PHONY: clean test benchmark

default: fsdgss

all:fsdgss pprfs prgs aes benchmarks

benchmarks: $(BENCHMARK)

benchmark: $(BENCHMARK:=.exec)

pprfs: $(PPRFS)

pprf: $(PPRFS:=.exec)

prgs: $(PRGS)

prg: $(PRGS:=.exec)

aes: $(AES)

ae: $(AES:=.exec)

fsdgss: $(FSDGSS)

fsdgs: $(FSDGSS:=.exec)

test/benchmark: test/benchmark.cpp test/cycles.c $(SOURCES) $(HEADERS)
	$(CC) $(CXXFLAGS) -o $@ test/cycles.c $(SOURCES) $< $(LDLIBS)

PPRF/main:PPRF/main.cpp $(SOURCES) $(HEADERS)
	$(CC) $(CXXFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

PPRF/main.exec:PPRF/main
	@$<

PRG/gen:PRG/gen.cpp $(SOURCES) $(HEADERS)
	$(CC) $(CXXFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

PRG/gen.exec:PRG/gen
	@$<

AE/authenc:AE/authenc.cpp $(SOURCES) $(HEADERS)
	$(CC) $(CXXFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

AE/authenc.exec:AE/authenc
	@$<

FSDGS/main:FSDGS/main.cpp $(SOURCES) $(HEADERS)
	$(CC) $(CXXFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

FSDGS/main.exec:FSDGS/main
	@$<

clean:
	-$(RM) $(BENCHMARK)
	-$(RM) $(PPRFS)
	-$(RM) $(PRGS)
	-$(RM) $(AES)
	-$(RM) $(FSDGSS)
	-$(RM) FSDGS_*.rsp
	-$(RM) Vt
