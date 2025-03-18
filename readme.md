AES-GCM-SIV code is from [AES_GCM_SIV_256/AES_GCM_SIV_256_Reference_Code](https://github.com/Shay-Gueron/AES-GCM-SIV/tree/master/AES_GCM_SIV_256/AES_GCM_SIV_256_Reference_Code)
SPHINCSPLUSC code is from https://github.com/ eyalr0/sphincsplusc

**run**
cd ref
make
./FSDGS/main

--result: it will generate two files : ../ref/PFSGS_256.rsp  and  ../ref/Vt

**benchmark**
make benchmarks
./test/benchmark