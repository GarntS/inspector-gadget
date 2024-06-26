/*  file:   main.rs
    author: garnt
    date:   04/15/2024
    desc:   Entrypoint for inspector-gadget.
*/

//! A cli-based, multi-architecture gadget-finding tool, designed for fast
//! operation, even with large binaries like browser engines and OS kernels.
//!
//! # Usage
//!
//! The minimal invocation of `inspector-gadget` is very simple:
//! ```bash
//! inspector-gadget /usr/bin/grep
//! ```
//! `inspector-gadget`'s default behavior is to:
//! 1. Parse the input binary, which is assumed to be an object file.
//! 2. Find every gadget in sections and segments marked as executable, by
//! default finding only gadgets ending with a return instruction.
//! 3. De-duplicate the gadgets.
//! 4. Print to `stdout` the gadget mnemonic and the list of start addresses
//! for each unique gadget that was found.
//!
//! For more info, see [README.md](https://github.com/garnts/inspector-gadget).
//!

mod arch;
mod cli_args;
mod disasm_tools;
mod gadget_tree;

use crate::arch::{Arch, Endianness};
use crate::cli_args::{CLIArgs, GadgetConstraints};
use crate::disasm_tools::{is_terminating_insn, GadgetSearchInsnInfo};
use crate::gadget_tree::GadgetTree;
use capstone::Capstone;
use clap::Parser;
use indicatif::{ParallelProgressIterator, ProgressIterator};
use itertools::Itertools;
use object::{Object, ObjectSection, ObjectSegment};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use std::cell::RefCell;
use std::io::Write;
use std::sync::Mutex;
use std::{fs, io};

/// find_gadget() searches for a single gadget, starting at the beginning of
/// the search bytes, and disassembling forwards until a complete gadget is
/// found or the search finds an instruction that ends it unsuccessfully.
fn find_gadget<'a>(
    search_bytes: &'a [u8],
    addr: usize,
    cs: &Capstone,
    arch: Arch,
    constraints: GadgetConstraints,
) -> Option<(usize, Vec<&'a [u8]>)> {
    // use capstone to actually do the disassembly
    let insns = cs
        .disasm_all(search_bytes, addr as u64)
        .expect("Capstone failed disassembly!");

    // iterate over the provided instructions, looking for a gadget-terminating
    // instruction to end the sequence.
    let mut gadget_slices: Vec<&[u8]> = Vec::new();
    for insn in insns.as_ref() {
        // update gadget_len
        let start_ofs: usize = insn.address() as usize - addr;
        let end_ofs: usize = start_ofs + (insn.len() as usize);
        gadget_slices.push(&search_bytes[start_ofs..end_ofs]);

        // grab this instruction's groups
        let detail = cs.insn_detail(insn).unwrap();
        let GadgetSearchInsnInfo {
            is_terminating,
            is_valid_gadget,
        } = is_terminating_insn(insn, &detail, arch, constraints);

        // if this insn is terminating and the gadget is still valid, stop
        // searching and return it if its length is ok.
        if is_terminating && is_valid_gadget {
            // if we have too few insns, this gadget is invalid
            if gadget_slices.len() < constraints.min_insns {
                return None;
            }
            // if we have too many insns, this gadget is invalid
            if gadget_slices.len() > constraints.max_insns {
                return None;
            }

            // if we got here, the gadget is valid
            return Some((addr, gadget_slices));

        // otherwise, if the insn is terminating or the gadget is invalid, stop
        // searching and return none.
        } else if is_terminating || !is_valid_gadget {
            return None;
        }
    }

    // if we got here, we didn't find a gadget, so return None
    None
}

/// get_gadget_mnemonic() returns an owned string representing the concatenated
/// mnemonics of the provided gadget's bytes.
fn get_gadget_mnemonic(
    gadget_bytes: &[u8],
    gadget_addr: usize,
    arch: Arch,
    endianness: Endianness,
) -> Result<String, String> {
    // init capstone and use it to do the disassembly
    let cs: Capstone = disasm_tools::init_capstone(arch, endianness, false).unwrap();
    let insns = cs
        .disasm_all(gadget_bytes, gadget_addr as u64)
        .expect("Capstone failed disassembly!");

    // iterate over the provided instructions, looking for a gadget-terminating
    // instruction to end the sequence.
    match insns
        .iter()
        .map(|insn| {
            // grab an owned copy of the operand's mnemonic
            let mut mnemonic: String = insn.mnemonic().unwrap().to_owned();
            // append the operand string if it exists
            if let Some(op_str) = insn.op_str() {
                mnemonic += " ";
                mnemonic += op_str;
            }
            mnemonic
        })
        .reduce(|acc, str| format!("{acc}; {str}"))
    {
        Some(mnemonic_string) => Ok(mnemonic_string),
        None => Err(format!(
            "Failed to get mnemonic for gadget at addr: {:x}",
            gadget_addr
        )),
    }
}

/// The entrypoint.
fn main() -> Result<(), String> {
    // parse cli args and gadget constraints
    let cli_args = CLIArgs::parse();
    let gadget_constraints = GadgetConstraints::from_cli_args(&cli_args);

    // compile regex and put it in a Mutex
    let regex_mtx: Mutex<Regex> = match &cli_args.regex_str {
        Some(reg_str) => Mutex::new(Regex::new(&reg_str).expect("Failed to compile regex!")),
        None => Mutex::new(Regex::new(r"^$").expect("Failed to compile regex!")),
    };

    // figure out if an out_file was specified and if it exists
    let mut use_out_file: bool = false;
    if let Some(out_file_path) = &cli_args.out_file {
        // if the out_file is a directory, refuse to overwrite it
        if out_file_path.is_dir() {
            return Err(format!(
                "Refusing to overwrite {}, which is a directory. Exiting...",
                out_file_path.to_str().unwrap()
            ));
        }

        // if the out_file already exists, make sure --overwrite was passed
        if out_file_path.exists() && !cli_args.overwrite {
            return Err(
                "Refusing to overwrite out_file without --overwrite! Exiting...".to_owned(),
            );
        }

        // if we got here, we're good to use the file
        use_out_file = true;
    }

    // the variables we need for gadget-finding
    let bin_data: Vec<u8>;
    let bin_arch: Arch;
    let bin_endianness: Endianness;
    let mut search_regions: Vec<(usize, usize, Option<std::string::String>, &[u8])>;

    // if raw binary, don't parse the binary
    if cli_args.raw_binary {
        bin_data = fs::read(cli_args.bin_path).unwrap();
        bin_arch = cli_args
            .arch
            .expect("arch should always be set for raw bins");
        bin_endianness = cli_args.endianness;
        search_regions = Vec::new();
        search_regions.push((0x0, bin_data.len(), None, bin_data.as_slice()));

    // otherwise, assume it's a "standard" object file
    } else {
        // read the binary file into memory, then parse it
        bin_data = fs::read(cli_args.bin_path).unwrap();
        let bin_file = object::File::parse(&*bin_data).unwrap();

        // grab the binary file's architecture and address size
        bin_arch = Arch::from_obj_arch(bin_file.architecture());
        bin_endianness = Endianness::from_obj_endianness(bin_file.endianness());
        eprintln!("arch: {:?} - endianness: {:?}", bin_arch, bin_endianness);

        // generate a list of 3-tuples of all the executable segments/sections in
        // the provided binary
        search_regions = bin_file
            .segments()
            .filter(|segment| match segment.flags() {
                object::SegmentFlags::Coff { characteristics } => {
                    (characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE) > 0
                }
                object::SegmentFlags::Elf { p_flags, .. } => (p_flags & object::elf::PF_X) > 0,
                object::SegmentFlags::MachO { initprot, .. } => {
                    (initprot & object::macho::VM_PROT_EXECUTE) > 0
                }
                _ => false,
            })
            .map(|exec_segment| {
                (
                    exec_segment.address() as usize,
                    exec_segment.size() as usize,
                    match exec_segment.name().unwrap() {
                        Some(x) => Some(x.to_owned()),
                        None => None,
                    },
                    exec_segment.data().unwrap().as_ref(),
                )
            })
            // iterate sections as well and chain the resulting iterators
            .chain(
                bin_file
                    .sections()
                    .filter(|section| match section.flags() {
                        object::SectionFlags::Coff { characteristics } => {
                            (characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE) > 0
                        }
                        object::SectionFlags::Elf { sh_flags, .. } => {
                            (sh_flags & (object::elf::SHF_EXECINSTR as u64)) > 0
                        }
                        // we can ignore mach-o, as it can't have executable sections that
                        // aren't also segments.
                        _ => false,
                    })
                    .map(|exec_section| {
                        (
                            exec_section.address() as usize,
                            exec_section.size() as usize,
                            Some(exec_section.name().unwrap().to_owned()),
                            exec_section.data().unwrap().as_ref(),
                        )
                    }),
            )
            // remove nonsense regions that are the full length of the file
            .filter(|region| region.1 < bin_data.len())
            // some regions appear as sections and segments, so deduplicate them by
            // keying on their load addresses
            .unique_by(|region| region.0)
            .sorted()
            .collect();
    }

    // filter out any search regions that overlap with others to avoid
    // searching twice
    let mut region_iter = search_regions.iter();
    let mut prev_reg: (usize, usize) = (0, 0);
    let mut bad_reg_addrs: Vec<usize> = Vec::new();
    while let Some(cur_region) = region_iter.next() {
        // if the previous region overlaps this one, mark it for removel
        if prev_reg.1 > cur_region.0 + cur_region.1 {
            eprintln!(
                "Region starting @0x{:x} overlaps subsequent region! Ignoring...",
                prev_reg.0
            );
            bad_reg_addrs.push(prev_reg.0);
        }
        // update prev_reg
        prev_reg = (cur_region.0, cur_region.0 + cur_region.1)
    }

    // remove any regions that need to be deleted
    search_regions = search_regions
        .into_iter()
        .filter(|region| !bad_reg_addrs.iter().contains(&region.0))
        .collect();

    if !Capstone::supports_arch(bin_arch.to_cs_arch()) {
        // TODO(garnt): remove if riscv supports_arch() bug gets fixed
        // there's a bug with Capstone::supports_arch() where it returns false
        // even if the underlying capstone library is compiled with riscv
        // support. For the time being, if the arch is RISCV, don't raise the
        // error.
        if bin_arch.to_cs_arch() != capstone::Arch::RISCV {
            return Err("Underlying capstone library doesn't support arch!".to_owned());
        }
    }

    // grab the max instruction length, in bytes, for the correct arch
    let max_insn_len_bytes: usize = match bin_arch {
        // arm/aarch64/ppc/mips/risc-v are all fixed 4-byte instructions
        Arch::Arm
        | Arch::Arm64
        | Arch::PowerPc
        | Arch::PowerPc64
        | Arch::Mips
        | Arch::Mips64
        | Arch::Riscv32
        | Arch::Riscv64
        | Arch::Sparc64 => 4,
        // s390x/sysz has 4/6/8-byte instructions
        Arch::SysZ => 8,
        // x86/x86_64 has some long-ass instructions
        Arch::X86 | Arch::X86_64 => 15,
    };

    // instantiate a new gadget tree for deduplication
    let mut gadget_tree: GadgetTree = GadgetTree::new();

    // generate a list of every valid instruction start address for a given
    // segment
    for (region_addr, region_len, region_name, region_data) in search_regions {
        // setup progress bar style
        let mut bar_str: String = match &region_name {
            Some(name) => format!("Finding all gadgets in {}: ", name),
            None => "Finding all gadgets in unnamed region: ".to_owned(),
        };
        bar_str += "{bar} [{pos}/{len} ({percent}%)] ({elapsed})";
        let search_style = indicatif::ProgressStyle::with_template(&bar_str).unwrap();

        // make sure the byte slice we grabbed actually has contents. ntoskrnl
        // has a segment that has a length but no data, so we have to check.
        if region_data.len() == 0 {
            continue;
        }

        // find all valid gadget start addresses within the segment, then
        // actually do the gadget search.
        let gadget_starts =
            disasm_tools::valid_gadget_start_addrs(bin_arch, region_addr, region_len);

        // create a variable stored in TLS to store a reference to a
        // thread-unique Capstone object. Instantiate it with a placeholder
        // that can be constructed statically.
        thread_local!(static THREAD_LOCAL_CS: RefCell<Capstone> = RefCell::new(
            Capstone::new_raw(capstone::Arch::ARM,
                capstone::Mode::Arm,
                std::iter::empty(),
                None).unwrap()
        ));

        // broadcast to each thread in the global rayon thread pool, telling
        // them to replace their thread-unique Capstone objects with one that
        // has the correct parameters.
        rayon::broadcast(|_| {
            THREAD_LOCAL_CS
                .set(disasm_tools::init_capstone(bin_arch, bin_endianness, true).unwrap())
        });

        let mut single_gadgets: Vec<(usize, Vec<&[u8]>)> = gadget_starts
            // iterate over the start addresses, parallelizing with rayon
            .par_iter()
            // render the status bar we've prepared, updating as we go
            .progress_with_style(search_style)
            // turn start addresses into offsets into the segment, then map
            // each start offset to an end offset.
            .map(|start_addr| {
                (
                    start_addr - region_addr,
                    region_data
                        .len()
                        .min(start_addr + (max_insn_len_bytes * cli_args.max_insns) - region_addr),
                )
            })
            // actually disassemble and attempt to find a gadget
            .map(|ofs_range| {
                THREAD_LOCAL_CS.with_borrow(|cs_ref| {
                    find_gadget(
                        &region_data[ofs_range.0..ofs_range.1],
                        ofs_range.0 + region_addr,
                        cs_ref,
                        bin_arch,
                        gadget_constraints,
                    )
                })
            })
            // filter out None results
            .flatten()
            .collect();

        // keep track of how many gadgets we found for sanity-checking later
        let single_gadgets_len: usize = single_gadgets.len();

        // print the number of gadgets
        if let Some(name) = &region_name {
            eprintln!("{} gadgets in {}", single_gadgets.len(), name);
        } else {
            eprintln!("{} gadgets in unnamed region", single_gadgets.len());
        }

        // add the new gadgets to the tree so we can deduplicate them
        let prev_tree_size: usize = gadget_tree.size();
        let tree_style = indicatif::ProgressStyle::with_template(
            "Constructing dedup tree: {bar} [{pos}/{len} ({percent}%)] ({elapsed})",
        )
        .unwrap();
        for gadget in single_gadgets.iter_mut().progress_with_style(tree_style) {
            gadget_tree.insert(&mut gadget.1, gadget.0);
        }
        assert_eq!(single_gadgets_len, gadget_tree.size() - prev_tree_size);
    }

    // walk the tree to get a list of unique gadgets and their start addrs
    let gadgets = gadget_tree.walk_gadgets();
    let n_walked: usize = gadgets.iter().map(|pair| pair.1.len()).sum();
    assert_eq!(n_walked, gadget_tree.size());

    // print the number of unique gadgets
    eprintln!("{} unique gadgets found.", gadgets.len());

    // setup progress bar style for mnemonic-finding
    let mnemonic_bar_style = indicatif::ProgressStyle::with_template(
        "Fetching gadget mnemonics: {bar} [{pos}/{len} ({percent}%)] ({elapsed})",
    )
    .unwrap();

    // generate mnemonic strings for gadgets
    let mnemonics: Vec<(String, &[usize])> = gadgets
        // iterate over the start addresses, parallelizing with rayon
        .par_iter()
        // render the status bar we've prepared, updating as we go
        .progress_with_style(mnemonic_bar_style)
        // actually disassemble and attempt to find a gadget
        .map(|pair| {
            (
                get_gadget_mnemonic(pair.0.as_ref(), pair.1[0], bin_arch, bin_endianness).unwrap(),
                pair.1,
            )
        })
        // filter mnemonics using regex
        .filter(|pair| {
            // only bother with the regex if the regex object exists
            if (&cli_args.regex_str).is_some() {
                let regex_obj = regex_mtx.lock().unwrap();
                return regex_obj.is_match(&pair.0);
            // if there's no regex object, just yield everything
            } else {
                return true;
            }
        })
        .collect();

    // if we used a regex, print the number of gadgets remaining after
    // applying it.
    if (&cli_args.regex_str).is_some() {
        eprintln!("{} unique gadgets after filtering", mnemonics.len());
    }

    // TODO(garnt): add flag to find function names per-gadget using symbols

    // if we should write to the out_file, do that, otherwise, write to stdout
    let out_dest: Box<dyn std::io::Write> = if use_out_file {
        Box::new(fs::File::create(cli_args.out_file.unwrap()).unwrap())
    } else {
        Box::new(std::io::stdout())
    };
    let mut out_writer = io::BufWriter::new(out_dest);

    // actually write all the gadgets to the file
    for mnemonic in mnemonics.iter() {
        out_writer
            .write(format!("{:02x?}: {}\n", mnemonic.1, mnemonic.0).as_bytes())
            .unwrap();
    }

    // Return something to satiate the compiler
    Ok(())
}
