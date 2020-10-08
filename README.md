# Chaos Duck

Chaos Duck as a name suggests creates chaos. In our case, however, chaos is good because it allows us to find out something that we couldn't otherwise. 

Chaos Duck grabs a given binary (x86_64,x86_32, or ARM) and produces new binaries out of it with the injected faults. It can fault branch instruction targets, flip bits, zero bytes or even words in some instructions, and even NOP isntructions completely. For each fault injected a new "faulty" binary is generated automatically. The Chaos Duck then proceeds to run all of the generated "faulty" binaries and collects the results of their execution (stdout, stderr, exit code, and if the execution was halted by a timeout). 

If the input binary is an implementation of some encryption algorithm, there is a high chance that Chaos Duck will be able to generate a "faulty" binary that would output plain text instead of a cipher.

## Prerequisites

Chaos Duck requires several Linux packages to be installed in order to be able to compile and run binaries for ARM architecture.

```
sudo apt update && sudo apt install gcc-arm-linux-gnueabi qemu-user
```

Chaos Duck must be run with Python v3.7 or later. Install it with the following command:

```
sudo apt install python3
```

**Note**: Chaos Duck uses multiprocessing library to run faulted binaries in parallel. Due to the [35182 bug](https://bugs.python.org/issue35182) Python v3.5 would crash randomly, so be sure to use the latest version of Python 3 with the fixes (i.e. v3.7+).

There are two Python packages that need to be installed before running Chaos Duck, namely `capstone` and `pyelftools`. You can install both dependencies by running the following command:

```
pip install -r requirements.txt
```

## Crosscompiling

You will need to compile original C source-code files for a desired architecture. Currently, Chaos Duck supports x86 (32 or 64 mode) and ARM architectures. We use dynamically compiled binaries since statically compiled ones are way too big and it's hard to operate with those. Note, Chaos Duck CAN be used with statically compiled binaries but you need to make sure you have enough disk space available for all the faulty binaries. 

To compile for x86 use standard gcc:
```
gcc -g -m32 test.c -o test.out
```

To crosscompile the same test.c file on x86 machine for ARM architecture use the following command:
```
arm-linux-gnueabi-gcc -g test.c -o test-arm.out
```

## [Optional] Disassembling (for debugging)

If you want to disassemble a given compiled binary use the following commands:

for x86-compiled binaries:
```
objdump -S test.out
```
or for ARM binaries:
```
arm-linux-gnueabi-objdump -S test-arm.out
```

## Running

Run Chaos Duck expects two CLI arguments and can be run using the following command:

```
python3 chaosduck.py <binary-to-fault> <architecture>
```

where, `<binary-to-fault>` is a binary file you want to check with fault injection attack, and `<architecture>` is an architecture you target: `x86` or `arm`

For example,
```
python3 chaosduck.py sepfunc32 x86

Disassembling the binary and looking for jump instructions...
Number of detected jumps:  37
Number of new binaries with changed jumps:  411
Running the faulty binaries and recording the results...

This may take a while...

BINGO! Plaintext instead of cipher in jmp_at_0x105b_from_0x1020_to_0x1628
BINGO! Plaintext instead of cipher in jbe_at_0x155c_from_0x124c_to_0x1192
BINGO! Plaintext instead of cipher in jmp_at_0x1247_from_0x1558_to_0x1186
BINGO! Plaintext instead of cipher in jmp_at_0x1247_from_0x1558_to_0x1192
BINGO! Plaintext instead of cipher in jmp_at_0x1247_from_0x1558_to_0x1142
BINGO! Plaintext instead of cipher in jbe_at_0x155c_from_0x124c_to_0x1186
BINGO! Plaintext instead of cipher in jbe_at_0x155c_from_0x124c_to_0x1142

```

Running the above command will produce a `faulted-binaries` directory with 411 "faulty" binaries in it.  When running those Chaos Duck should find 7 binaries that output plain text instead of a cipher.
The results will be compiled in `results.csv` file.

## Hardening

The `hardening` folder contains C code samples implementing several techniques aiming to protect the source code against the fault attack on jump instructions. Read `README.md` for more info. 


## Acknowledgement
Chaos Duck uses SWIFI tool (developed by Antoine Chenoy) to inject faults.


