db
==

[![Build Status](https://travis-ci.org/scott-linder/db.svg?branch=master)](https://travis-ci.org/scott-linder/db)

A simple x86_64 debugger written with ptrace and
[Udis86](http://udis86.sourceforge.net/)

Building
--------

`db` depends on [Udis86](http://udis86.sourceforge.net/) to provide
disassembly. This is an essential feature of any debugger, so the dependency is
not optional.

In order to build `db`, ensure:
* `libudis86.{so,a}` is available
* Your `cc` is `c99` compliant
* Your `libc` is POSIX.1-2008 compliant

There is no configure step, and no install target, so simply run:

```
make
```

Usage
-----

`db` accepts only positional arguments: the command-line of the program to be
debugged.

Assuming you have placed the `db` executable somewhere in your `PATH`, run:
```
db command
```

Interface
---------

Prompts begin with `(db) `, and have limited line-editing support.

Errors are printed before the next prompt.

Commands
--------

All commands in `db` are identified as a single character mnemonic, followed by
any arguments.

`db` supports the following commands:

    commands:
            s             | step single instruction
            d             | dissassemble current instruction
            r <reg>       | read register
            w <reg> <val> | write register
            g <adr>       | get memory
            p <adr> <val> | poke memory
            e             | exit
    registers:
            r15
            r14
            r13
            r12
            rbp
            rbx
            r11
            r10
            r9
            r8
            rax
            rcx
            rdx
            rsi
            rdi
            orig_rax
            rip
            cs
            eflags
            rsp
            ss
            fs_base
            gs_base
            ds
            es
            fs
            gs


Values and addresses are expected to be in hexadecimal.

Future Plans
------------

Desired features include:

* Breakpoints
* Visual (TUI) mode
* Arbitrary code execution while single-stepping
