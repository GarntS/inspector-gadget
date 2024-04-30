# inspector-gadget

A cli-based, multi-architecture gadget-finding tool, designed for fast
operation, even with large binaries like browser engines and OS kernels.

[![Crates.io](https://img.shields.io/crates/v/inspector-gadget.svg)](https://crates.io/crates/inspector-gadget)

## Main Features
- Detects and parses PE/COFF, ELF, and Mach-O object files to pull
architecture, endianness, and executable section/segment flags.
- Support for arm, arm64, x86, x86_64, mips, mips64, ppc, ppc64, riscv,
riscv64, sparc64, and s390x/systemz architectures.
- Located gadgets are de-duplicated, with all load addresses for a given gadget
listed in the output.
- Built-in regex engine for pre-filtering mnemonics of gadget results.
- Configurable gadget instruction counts and ending instructions.
- It's _fast._

## Usage

The minimal invocation of `inspector-gadget` is very simple:
```bash
inspector-gadget /usr/bin/grep
```
`inspector-gadget`'s default behavior is to:
1. Parse the input binary, which is assumed to be an object file.
2. Find every gadget in sections and segments marked as executable, by
default finding only gadgets ending with a return instruction.
3. De-duplicate the gadgets.
4. Print to `stdout` the gadget mnemonic and the list of start addresses
for each unique gadget that was found.

### Changing Output Destination

Use the `-o` (`--out-file`) flag:

```bash
inspector-gadget -o gadgets.txt /usr/bin/grep
```

Alternatively, the gadgets get written to `stdout`, but progress messages get
written to `stderr`, so just redirecting the output to a file will also result
in the gadgets getting written to a file:

```bash
inspector-gadget /usr/bin/grep > gadgets.txt
```

### Filtering Gadgets

To make the initial filtering easier, or to make working with binaries that
have smaller file sizes take fewer steps, `inspector-gadget` supports
filtering the resulting gadget mnemonics using regular expressions via
@burntsushi's excellent [regex](https://docs.rs/regex) library.

**When working with binaries that have larger file sizes, I recommend finding
all gadgets matching a loose set of constraints, writing them to a file, then
grepping that file repeatedly to find anything specific you might be looking
for.** If you want a similarly-performant `grep` implementation, I recommend
[ripgrep](https://github.com/BurntSushi/ripgrep) (also written by @burntsushi),
which can be obtained via `cargo install` or through the package manager on most
linux distros (or `brew` on mac).

Use the `-r` (`--regex-str`) flag:

```bash
inspector-gadget -r "^pop rdx;.*pop r[a-z1-589]{1,3}; ret" /usr/bin/grep
```

*Note: each gadget's mnemonic is separated by *`"; "`*, so consider that when
constructing any regex patterns.*

### Changing Gadget Length Constraints

By default, `inspector-gadget` will find gadgets containing between 2 and 10
instructions. If you'd like to change these bounds, use the `--min-insns` and
`--max-insns` flags:

```bash
inspector-gadget --min-insns 4 --max-insns 6 /usr/bin/grep
```

### Changing Gadget Ending Instructions

By default, `inspector-gadget` will only search for gadgets ending with
whatever instruction are used for a function return for the given architecture.
If you'd like to also allow terminating indirect jumps or terminating indirect
calls, use the `--allow-terminating-call` or `--allow-terminating-jmp` flags:

```bash
inspector-gadget --allow-terminating-call /usr/bin/grep
```

*Note: this works great for architectures that have obvious distinctions
between instructions that are used for jmp/call/ret, but is less effective or
non-functional for RISC architectures that re-use the same instructions for
control flow. I've manually implemented heuristics for return instructions for
each architecture, but if call/jmp instructions aren't specifically tagged by
Capstone for your target architecture, I haven't gone back through and done
separate ones myself.*

### Manually-Specifying Architecture and Endianness

By default, `inspector-gadget` will parse the object file passed as input in
order to determine the correct architecture and endianness to use during
disassembly. If you'd like to specifying these values manually, use the
`--arch` and `--endianness` flags:

```bash
inspector-gadget --arch x86_64 --endianness little /usr/bin/grep
```

If `--arch` or `--endianness` flags are passed, the manually-specified values
will be used instead of the values parsed from the object file.

### Using Raw Binary Data as Input

If you'd like to use raw data as input, use the `--raw-binary` flag:

```bash
inspector-gadget --arch x86_64 --raw-binary /tmp/grep_text_dump.bin
```

*Note: when using* `--raw-binary`*, the binary's architecture and endianness
must be specified manually. Endianness will default to little-endian if the*
`--endianness` *flag is not passed, as it is significantly more common.*
`--arch` *must always be passed when using* `--raw-binary`.

## Implementation Details

`inspector-gadget` is built on the
[Capstone](https://www.capstone-engine.org) disassembly framework, and
supports gadget-finding for every available Capstone disassembly
architecture. The disassembly and gadget-finding process is heavily
multithreaded using a work queue of pre-calculated search start addresses
and the [rayon](https://docs.rs/rayon) data-parallelism library.

After using Capstone to find valid gadgets, `inspector-gadget` uses a
custom tree-based data structure to de-duplicate any gadgets that can be
found at multiple addresses within the binary.

Up until this point, the mnemonic strings for the gadgets' instructions
haven't been accessed or stored anywhere, so `inspector-gadget` then uses
Capstone to disassemble all of the unique gadgets that have been found and
generate their final mnemonic strings.

Due to the short length of the  gadgets and the significantly smaller
number of operations required when compared to the original search, this
second disassembly pass both saves a significant amount of memory usage
and is significantly faster than if the mnemonic strings had been stored
during the initial pass.

`inspector-gadget` also implements object file parsing for the PE/COFF,
ELF, and Mach-O file formats, as well as support for raw input blobs.

## Further Documentation
Documentation is available on [docs.rs](https://docs.rs/crate/inspector-gadget).

Functions and structures are all commented using Rust's doc comments, so
`rust doc` should generate pretty good documentation.

## Performance

On my test box, it takes less than 10 seconds to find every gadget in an
Android arm64 build of `libmonochrome.so`, the dylib used by Chrome and the
Android system webview:

```bash
time target/release/inspector-gadget test_bins/libmonochrome_64.so > /dev/null
[...]
real    0m9.758s
```

The next-best option was [Ropper](https://github.com/sashs/Ropper), which took
about 35 minutes and didn't bother de-duplicating or sorting the gadgets that
it found.

A Windows x86_64 build of `xul.dll`, the Firefox dylib, took about a minute and
a half to process:
```bash
time target/release/inspector-gadget test_bins/xul.dll > /dev/null
[...]
real    1m25.907s
```

I gave up waiting on an actual number from Ropper after about 3 hours, but
anecdotally it used to be a "run it overnight" sort of problem.

When targeting smaller binaries, results are near-instant:
```bash
time target/release/inspector-gadget test_bins/apple-mfi-fastcharge.ko
[...]
real    0m0.113s
```

*TODO(garnt): collect better data and make some graphs.*

# License
`inspector-gadget` is licensed under [GPLv3](LICENSE).