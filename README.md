# HGS
This is a simple implementation of FSDGS

AES-GCM-SIV code is from [AES_GCM_SIV_256](https://github.com/Shay-Gueron/AES-GCM-SIV/tree/master/AES_GCM_SIV_256/AES_GCM_SIV_256_Reference_Code)

SPHINCSPLUSC code is from [sphincsplusc](https://github.com/eyalr0/sphincsplusc)

---
## Installation instructions
### 1. Install Toolchain (if not installed)
To compile C/C++ programs and use Makefiles, install the GCC compiler and build tools on Ubuntu/Debian-based systems:

```
sudo apt update
sudo apt install build-essential
```

### 2. Install Dependencies (if not installed)
Install OpenSSL Development Package
```
sudo apt install libssl-dev
```

### 3. Clone Repository
Make sure to install the git to clone respository
```
sudo apt insatll git -y
git clone https://github.com/WithoutNi/GS.git
cd GS
```

---
## Dependencies
For the PPRF\PRG functions, we rely on OpenSSL (OpenSSL 1.1.1 is used in the experiment). Make sure to install the OpenSSL development headers. If not installed,see the above **2. Install Dependencies**

---
## Project Structure (in Directory `ref/`)

| Directory       | Description                                                                 |
|-----------------|-----------------------------------------------------------------------------|
| `AE/`           | AES-GCM-SIV-256 authenticated encryption (`Enc()`, `Dec()`)                 |
| `FSDGS/`        | Forward-secure dynamic group signature algorithms                           |
| `PPRF/`         | Puncturable PRF implementation (`Punc()`, `Eval()`)                         |
| `PPG/`          | PRG by using counter-mode AES                                               |
| `params/`       | Parameters configuration (security parameter,hybertree parameters...)       |
| `test/`         | Performance benchmarks and functional tests                                 |
| `sign.cpp`      | The modified SPHINCS+C functions (`GetAuth()`, `AuthVrfy()`)                |

---
## How to run
**Open the terminal in the directory `GS` and execute the following commands in order**

```
cd ref
make
./FSDGS/main
```

**result: it will generate two files in directory ref :**
`ref/PFSGS_***.rsp`, `ref/Vt`

## Benchmark

```
cd ref
make benchmarks
./test/benchmark
```
