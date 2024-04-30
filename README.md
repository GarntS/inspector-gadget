# inspector-gadget

A cli-based, multi-architecture gadget-finding tool, designed for fast
operation, even with large binaries like browser engines and OS kernels.

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

# Implementation Details

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

# License
`inspector-gadget` is licensed under [GPLv3](LICENSE).