# r2-retdec

PoC of Radare2 and RetDec integration.

## Setup

1. Install [Radare2](https://github.com/radare/radare2) (r2).
2. Install [RetDec](https://github.com/avast-tl/retdec).
3. Install [r2pipe](https://github.com/radare/radare2-r2pipe) for Python.

## Run

* Get both the PoC script `r2-retdec.py` and test file `ack.x86.gcc.O0.g.exe`.
* Decompile function at address `0x4015ED` (`_main`):
```
python r2-retdec.py ack.x86.gcc.O0.g.exe -r <path_to_retdec-decompiler.py> -f 0x4015ED
```
```c
//
// This file was generated by the Retargetable Decompiler
// Website: https://retdec.com
// Copyright (c) 2018 Retargetable Decompiler <info@retdec.com>
//

#include <stdint.h>

// ------------------- Function Prototypes --------------------

int32_t ___main(void);
int32_t _ack(int32_t a1, int32_t a2);
int32_t _main(int32_t argc, char ** argv);
int32_t _printf(int32_t a1, int32_t a2, int32_t a3, int32_t a4);
int32_t _scanf(int32_t a1, int32_t a2, int32_t a3);

// ------------------------ Functions -------------------------

// Address range: 0x4015bb - 0x40163f
int32_t _main(int32_t argc, char ** argv) {
    // 0x4015bb
    ___main();
    int32_t x = 0; // bp-24
    int32_t y = 0; // bp-28
    _scanf((int32_t)"%d %d", (int32_t)&x, (int32_t)&y);
    int32_t result = _ack(x, y); // 0x40160c
    _printf((int32_t)"ackerman( %d , %d ) = %d\n", x, y, result);
    return result;
}

// --------------------- Meta-Information ---------------------

// Detected compiler/packer: mingw gcc (4.7.3)
// Detected language: C
// Detected functions: 1
// Decompilation date: 2018-10-10 14:52:11
```
* Decompile function at address `0x401580` (`_ack`):
```
python r2-retdec.py ack.x86.gcc.O0.g.exe -r <path_to_retdec-decompiler.py> -f 0x401580
```
```c
//
// This file was generated by the Retargetable Decompiler
// Website: https://retdec.com
// Copyright (c) 2018 Retargetable Decompiler <info@retdec.com>
//

#include <stdint.h>

// ------------------- Function Prototypes --------------------

int32_t _ack(int32_t m, int32_t n);

// ------------------------ Functions -------------------------

// Address range: 0x401560 - 0x4015bb
int32_t _ack(int32_t m, int32_t n) {
    // 0x401560
    if (m == 0) {
        // 0x40156c
        // branch -> 0x4015b9
        // 0x4015b9
        return n + 1;
    }
    // 0x401574
    int32_t result; // 0x4015ba
    if (n != 0) {
        // 0x401592
        result = _ack(m - 1, _ack(m, n - 1));
        // branch -> 0x4015b9
    } else {
        // 0x40157a
        result = _ack(m - 1, 1);
        // branch -> 0x4015b9
    }
    // 0x4015b9
    return result;
}

// --------------------- Meta-Information ---------------------

// Detected compiler/packer: mingw gcc (4.7.3)
// Detected language: C
// Detected functions: 1
// Decompilation date: 2018-10-10 15:32:31
```

## State

* Minimum information is exported from r2:
   * Missing global variables.
   * Missing data types.
* RetDec behaves like it was decompiling via IDA plugin. This might not be ideal.
* Even decompilation via IDA plugin is experimental and not working correctly all the times.
