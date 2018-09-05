# r2m2 - use miasm2 as a radare2 plugin

[![Build Status](https://travis-ci.org/guedou/r2m2.svg?branch=master)](https://travis-ci.org/guedou/r2m2)
[![GitHub tag](https://img.shields.io/github/tag/guedou/r2m2.svg)](https://github.com/guedou/r2m2/releases)
[![Docker Automated buil](https://img.shields.io/docker/automated/guedou/r2m2.svg)](https://hub.docker.com/r/guedou/r2m2/)
<a href="https://dply.co/b/GmWkkvVs"><img src="https://dply.co/b.svg" height=20/></a>
[![Twitter Follow](https://img.shields.io/twitter/follow/guedou.svg?style=social)](https://twitter.com/intent/follow?screen_name=guedou)

r2m2 is a [radare2](https://github.com/radare/radare2) plugin that aims at easing reversing new architectures by leveraging radare2 and [miasm2](https://github.com/cea-sec/miasm) features. Its goal is to be as architecture independent as possible.

It bridges the radare2 and miasm2 communities: radare2 being the graphical interface of miasm2, and miasm2 simplifying the implementation of new architectures.

Currently, r2m2 is able to assemble, disassemble, split blocs, using miasm2,  and convert internal miasm2 expressions to radare2 ESIL.

Interested? Watch the video, or check the [presentation and design slides](https://guedou.github.io/).
[![asciicast](https://asciinema.org/a/3x0i1ejw5x9s0ep9aghhm848c.png)](https://asciinema.org/a/3x0i1ejw5x9s0ep9aghhm848c)


## Demos

r2m2 provides a single radare2 plugin, that can be enabled using the `-a` option used in most radare2 commands. The `R2M2_ARCH` environment variable is used to select the architecture that will be used.

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

r2m2$ R2M2_ARCH=mips32b r2 -a r2m2 -qc 'pd 2' j_nop.bin
        ,=< 0x00000000      0c000001       JAL        0x4
        `-> 0x00000004      00000000       NOP
```


## Testing r2m2

[Docker](https://www.docker.com/) is the recommended solution to use r2m2. Each pull requests are tested with Travis. Upon success, a Docker image is built on [Docker Hub](https://hub.docker.com) and can easily be pulled as follows:

```
r2m2$ docker pull guedou/r2m2

r2m2$ docker run --rm -it -e 'R2M2_ARCH=mips32l' guedou/r2m2 rasm2 -a r2m2 "addiu a0, a1, 2"
0200a424
```

If you associated a SSH key with your github account, you can try r2m2 on a free [Dply VM](https://dply.co/b/GmWkkvVs). The [installation script](examples/dply_cloud-init.sh) prepared the VM by installing Docker and pulling the r2m2 image.


## Building r2m2

### Docker

The `Dockerfile` takes care of everything, and builds r2m2.  The following command lines show how to build the Docker image, run a temporary container, and test r2m2:

```
r2m2$ docker build -t guedou/r2m2 .

r2m2$ docker run --rm -it -e 'R2M2_ARCH=mips32l' guedou/r2m2 bash
root@11da1889a490:/home/r2m2# rasm2 -L |grep r2m2
adAe  32         r2m2        LGPL3   miasm2 backend
root@11da1889a490:/home/r2m2# rasm2 -a r2m2 "addiu a0, a1, 2"
0200a424

r2m2$ docker run --rm -it -e 'R2M2_ARCH=x86_64' guedou/r2m2
 -- One does not simply write documentation.
[0x00000000]> o /bin/ls
4
[0x0000487f]> e anal.arch=r2m2
[0x0000487f]> e asm.emu=true
[0x0000487f]> pd 10
            ;-- entry0:
            0x0000487f      31ed           xor ebp, ebp                ; zf=0x1  ; nf=0x0 
            0x00004881      4989d1         mov r9, rdx                 ; r9=0x0 
            0x00004884      5e             pop rsi                     ; rsp=0x8  ; rsi=0x0 
            0x00004885      4889e2         mov rdx, rsp                ; rdx=0x8 
            0x00004888      4883e4f0       and rsp, 0xfffffffffffffff0 ; zf=0x1  ; nf=0x0 
            0x0000488c      50             push rax                    ; rsp=0x10 
            0x0000488d      54             push rsp                    ; rsp=0x18 
            0x0000488e      49c7c0301d41.  mov r8, 0x411d30            ; r8=0x411d30 -> 0xffffff00
            0x00004895      48c7c1c01c41.  mov rcx, 0x411cc0           ; rcx=0x411cc0 -> 0xffffff00
            0x0000489c      48c7c7c02840.  mov rdi, 0x4028c0           ; rdi=0x4028c0 -> 0xffffff00
```

### Linux & OS X

**Note:** automatic builds are performed on Ubuntu, Arch Linux, and Mac OS X.  Other distributions might not work due to libraries incompatibilities.

The following softwares must be installed:

1. radare2 (>= 2.9.0)

2. miasm2

3. CFFI Python module (>= 1.6)

4. jinja2 Python module (>= 1.6)

r2m2 can be built as follows:
```
r2m2$ make all install
[..]
mkdir -p [..]
```

You can type the following command to check that everything went fine:
```
r2m2$ rasm2 -L |grep r2m2
adAe  32         r2m2        LGPL3   miasm2 backend
```


## Compilation warnings

If you get the following error, the CFFI Python module version is not >= 1.6.  You need to upgrade it, for example using PIP in a virtualenv.
```
AttributeError: 'FFI' object has no attribute 'set_source'
```
