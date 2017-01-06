# r2m2 - use miasm2 as a radare2 plugin


## Overview

r2m2 is a [radare2](https://github.com/radare/radare2) plugin that uses
[miasm2](https://github.com/cea-sec/miasm) as its backend. It aims at easing
reversing new architectures by leveraging
[radare2](https://github.com/radare/radare2) and
[miasm2](https://github.com/cea-sec/miasm) features. It was designed to be as
architecture independent as possible.

The `R2M2_ARCH` environment variable is used to select the architecture that
will be used by miasm2.


## Author

  * Guillaume VALADON <guillaume@valadon.net>


## Demos

### Assemble and disassemble MIPS32 using rasm2

```
r2m2$ export R2M2_ARCH=mips32l; rasm2 -a r2m2 'addiu a0, a1, 2' |rasm2 -a r2m2 -d -
ADDIU      A0, A1, 0x2
```

### Disassemble random MSP430 instructions in r2

```
r2m2$ R2M2_ARCH=msp430 r2 -a r2m2 -qc 'woR; pd 5' -
            0x00000000      07fa           and.w      R10, R7
            0x00000002      47ad           dadd.b     R13, R7
            0x00000004      f05e0778       add.b      @R14+, 0x7807(PC)
            0x00000008      f46d81ed       addc.b     @R13+, 0xED81(R4)
            0x0000000c      3fdc           bis.w      @R12+, R15
```

### Assemble MIPS32 using rasm2 and display the call graph using r2

```
r2m2$ R2M2_ARCH=mips32b rasm2 -a r2m2 'j 0x4; nop' -B > j_nop.bin

r2m2$ R2M2_ARCH=mips32b r2 -a r2m2 j_nop.bin -qc 'pd 2'
        ,=< 0x00000000      0c000001       JAL        0x4
        `-> 0x00000004      00000000       NOP
```


## Building and testing r2m2

Note that r2m2 was only tested on Linux.

### Docker

The `Dockerfile` takes care of everything, and builds r2m2.  The following
command lines show how to build the [Docker](https://www.docker.com/) image,
run a temporary container, and test r2m2:

```
$ docker build -t guedou/r2m2 .

$ docker run --rm -it -e 'R2M2_ARCH=mips32l' guedou/r2m2 bash
root@11da1889a490:/home/r2m2# rasm2 -L |grep r2m2            
adAe  32         r2m2        LGPL3   miasm2 backend
root@11da1889a490:/home/r2m2# rasm2 -a r2m2 "addiu a0, a1, 2" 
0200a424

$ docker run --rm -it -e 'R2M2_ARCH=x86_64' guedou/r2m2
 -- *(ut64*)buffer ought to be illegal
[0x00000000]> o /bin/ls
[0x000048c5]> pd 2
            ;-- entry0:
            0x000048c5      31ed           xor ebp, ebp
            0x000048c7      4989d1         mov r9, rdx
```

### Debian

The following softwares must be installed:

1. radare2

2. miasm2

3. CFFI Python module (>= 1.6)

r2m2 can be built as follows:
```
$ rm src/r2m2.h  # ensure that r2m2 uses up-to-date r2 headers
$ make all install
[..]
cp -f r2m2_ad.so r2m2_Ae.so [..]
```

You can type the following command to check that everything went fine:
```
$ rasm2 -L |grep r2m2            
adAe  32         r2m2        LGPL3   miasm2 backend
```


## Compilation warnings

If you get the following error, the CFFI Python module version is not >= 1.6.
You need to upgrade it, for example using PIP in a virtualenv.
```
AttributeError: 'FFI' object has no attribute 'set_source'
```
