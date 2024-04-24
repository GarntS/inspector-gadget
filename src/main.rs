/*  file:       main.rs
    author:     garnt
    date:       04/15/2024
    desc:       Entrypoint for inspector_gadget.
 */

mod capstone_tools;
mod cli_args;
mod gadget_tree;
mod ig_error;

use capstone::Capstone;
use clap::Parser;
use cli_args::{CLIArgs, GadgetConstraints};
use gadget_tree::GadgetTree;
use ig_error::IGError;
use indicatif::{ParallelProgressIterator, ProgressIterator};
use object::{Object, ObjectSegment};
use rayon::iter::{ParallelIterator, IntoParallelRefIterator};
use regex::Regex;
use std::sync::{Arc, Mutex};
use capstone_tools::{is_terminating_insn, GadgetSearchInsnInfo};

// is_valid_gadget_len() returns true if a gadget length is valid given the
// passed GadgetConstraints object.
fn is_valid_gadget_len(n_insns: usize, constraints: GadgetConstraints) -> bool {
    // if we have too few insns, this length is invalid
    if n_insns < constraints.min_insns {
        return false
    }
    // if we have too many insns, this length is invalid
    if n_insns > constraints.max_insns {
        return false;
    }

    // if we got here, the length is valid
    true
}

// find_gadget() finds a single gadget and returns the string representation
// of its mnemonics if one is found.
fn find_gadget(search_bytes: &[u8], addr: usize, arch: object::Architecture, endianness: object::Endianness, constraints: GadgetConstraints) -> Option<(usize, Vec<&[u8]>)> {
    // init capstone and use it to do the disassembly
    let cs: Capstone = capstone_tools::init_capstone(arch, endianness, true).unwrap();
    let cs_arch = capstone_tools::object_arch_to_cs_arch(arch).unwrap();
    let insns = cs.disasm_all(search_bytes, addr as u64)
                .expect("Capstone failed disassembly!");

    // iterate over the provided instructions, looking for a gadget-terminating
    // instruction to end the sequence.
    let mut found_valid_gadget: bool = false;
    let mut gadget_slices: Vec<&[u8]> = Vec::new();
    for insn in insns.as_ref() {
        // update gadget_len
        let start_ofs: usize = insn.address() as usize - addr;
        let end_ofs: usize = start_ofs + (insn.len() as usize);
        gadget_slices.push(&search_bytes[start_ofs..end_ofs]);

        // grab this instruction's groups
        let detail = cs.insn_detail(insn).unwrap();
        let GadgetSearchInsnInfo {is_terminating, is_valid_gadget} = is_terminating_insn(insn, &detail, cs_arch, constraints);
    
        // if this insn is terminating and the gadget is still valid, stop
        // searching and return it if its length is ok.
        if is_terminating && is_valid_gadget {
            found_valid_gadget = is_valid_gadget_len(gadget_slices.len(), constraints);
            break;
        // otherwise, if the insn is terminating or the gadget is invalid, stop
        // searching and return none.
        } else if is_terminating || !is_valid_gadget {
            break;
        }
    }

    // TODO(garnt): reconsider memory leak
    // explicitly drop the capstone disassembler and instructions objects
    std::mem::drop(insns);
    std::mem::drop(cs);

    // if we found a gadget
    if found_valid_gadget {
        return Some((addr, gadget_slices));
    }

    // if we didn't find a gadget, return None
    None
}

// get_gadget_mnemonic() returns an owned string representing the concatenated
// mnemonics of the provided gadget bytes
fn get_gadget_mnemonic(gadget_bytes: &[u8], gadget_addr: usize, arch: object::Architecture, endianness: object::Endianness) -> String {
    // init capstone and use it to do the disassembly
    let cs: Capstone = capstone_tools::init_capstone(arch, endianness, false).unwrap();
    let insns = cs.disasm_all(gadget_bytes, gadget_addr as u64)
                .expect("Capstone failed disassembly!");
    
    // iterate over the provided instructions, looking for a gadget-terminating
    // instruction to end the sequence.
    insns
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
        .unwrap_or_default()
}

// main() is the entrypoint.
fn main() -> Result<(), IGError> {
    // parse cli args and gadget constraints
    let cli_args = CLIArgs::parse();
    let gadget_constraints = GadgetConstraints::from_cli_args(&cli_args);

    // compile regex and put it in a Mutex
    let regex_mtx: Mutex<Regex> = match &cli_args.regex_str {
        Some(reg_str) =>Mutex::new(Regex::new(&reg_str).expect("Failed to compile regex!")),
        None => Mutex::new(Regex::new(r"^$").expect("Failed to compile regex!")),
    };

    // read the binary file into memory, then parse it
    let bin_data = std::fs::read(cli_args.bin_path).unwrap();
    let bin_file = object::File::parse(&*bin_data).unwrap();

    // grab the binary file's architecture and address size
    let bin_arch = bin_file.architecture();
    let bin_endianness = bin_file.endianness();
    println!("arch: {:?} - endianness: {:?}", bin_arch, bin_endianness);
    if !Capstone::supports_arch(capstone_tools::object_arch_to_cs_arch(bin_arch).unwrap()) {
        // TODO(garnt): remove if riscv supports_arch() bug gets fixed
        // there's a bug with Capstone::supports_arch() where it returns false
        // even if the underlying capstone library is compiled with riscv
        // support. For the time being, if the arch is RISCV, don't raise the
        // error.
        if capstone_tools::object_arch_to_cs_arch(bin_arch).unwrap() != capstone::Arch::RISCV {
            return Err(IGError::new("Underlying capstone library doesn't support arch!"))
        }
    }

    // grab the max instruction length, in bytes, for the correct arch
    let max_insn_len_bytes: usize = match capstone_tools::object_arch_to_cs_arch(bin_arch) {
        // arm/aarch64/ppc/mips/risc-v are all fixed 4-byte instructions
        Some(capstone::Arch::ARM)
        | Some(capstone::Arch::ARM64)
        | Some(capstone::Arch::PPC)
        | Some(capstone::Arch::MIPS)
        | Some(capstone::Arch::RISCV)
        | Some(capstone::Arch::SPARC) => Some(4),
        // s390x/sysz has 4/6/8-byte instructions
        Some(capstone::Arch::SYSZ) => Some(8),
        // x86/x86_64 has some long-ass instructions
        Some(capstone::Arch::X86) => Some(15),
        // default to None
        _ => None
    }.expect("Unexpected value for bin_arch!");

    // generate a list of every valid instruction start address for a given
    // segment
    for segment in bin_file.segments() {
        // check if this section will be marked executable. if not, ignore it.
        if ! match segment.flags() {
            object::SegmentFlags::Coff { characteristics } => {
                (characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE) > 0
            },
            object::SegmentFlags::Elf { p_flags, .. } => {
                (p_flags & object::elf::PF_X) > 0
            },
            object::SegmentFlags::MachO { initprot, .. } => {
                (initprot & object::macho::VM_PROT_EXECUTE) > 0
            },
            _ => false
        } {
            continue;
        }

        // setup progress bar style
        let seg_name = segment.name().unwrap();
        let mut bar_str: String = match seg_name {
            Some(name) => format!("Finding all gadgets in segment {}: ", name),
            None => "Finding all gadgets in segment: ".to_owned(),
        };
        bar_str += "{bar} [{pos}/{len} ({percent}%)] ({elapsed})";
        let search_style = indicatif::ProgressStyle::with_template(&bar_str).unwrap();

        // grab a copy of the segment contents we can slice up
        let seg_bytes: Arc<[u8]> = segment.data().unwrap().into();

        // make sure the byte slice we grabbed actually has contents. ntoskrnl
        // has a segment that has a length but no data, so we have to check.
        if seg_bytes.len() == 0 {
            continue;
        }

        // find all valid gadget start addresses within the segment, then
        // actually do the gadget search.
        let gadget_starts = capstone_tools::valid_gadget_start_addrs(&segment, bin_arch);
        let mut single_gadgets: Vec<(usize, Vec<&[u8]>)> = gadget_starts
            // iterate over the start addresses, parallelizing with rayon
            .par_iter()
            // render the status bar we've prepared, updating as we go
            .progress_with_style(search_style)
            // turn start addresses into offsets into the segment, then map
            // each start offset to an end offset.
            .map(|start_addr| (start_addr - (segment.address() as usize), seg_bytes.len().min(start_addr + (max_insn_len_bytes * cli_args.max_insns) - (segment.address() as usize))))
            // actually disassemble and attempt to find a gadget
            .map(|ofs_range| find_gadget(
                &seg_bytes[ofs_range.0..ofs_range.1],
                ofs_range.0 + segment.address() as usize,
                bin_arch,
                bin_endianness,
                gadget_constraints
            ))
            // filter out None results
            .flatten()
            .collect();

        // keep track of how many gadgets we found for sanity-checking later
        let single_gadgets_len: usize = single_gadgets.len();
        
        // print the number of gadgets
        if let Some(name) = seg_name {
            println!("{} gadgets in {}", single_gadgets.len(), name);
        } else {
            println!("{} gadgets in segment", single_gadgets.len());
        }

        // populate a tree from the gadgets so we can deduplicate them
        let tree_style = indicatif::ProgressStyle::with_template("Constructing dedup tree: {bar} [{pos}/{len} ({percent}%)] ({elapsed})").unwrap();
        let mut gadget_tree: GadgetTree = GadgetTree::new();
        for gadget in single_gadgets.iter_mut().progress_with_style(tree_style) {
            gadget_tree.insert(&mut gadget.1, gadget.0);
        }
        assert_eq!(single_gadgets_len, gadget_tree.size());

        // walk the tree to get a list of unique gadgets and their start addrs
        let gadgets = gadget_tree.walk_gadgets();
        let n_walked: usize = gadgets.iter().map(|pair| pair.1.len()).sum();
        assert_eq!(single_gadgets_len, n_walked);

        // print the number of unique gadgets
        if let Some(name) = seg_name {
            println!("{} unique gadgets in {}", gadgets.len(), name);
        } else {
            println!("{} unique gadgets in segment", gadgets.len());
        }

        // setup progress bar style for mnemonic-finding
        let mnemonic_bar_style = indicatif::ProgressStyle::with_template("Fetching gadget mnemonics: {bar} [{pos}/{len} ({percent}%)] ({elapsed})").unwrap();

        // generate mnemonic strings for gadgets
        let mnemonics: Vec<(String, &[usize])> = gadgets
            // iterate over the start addresses, parallelizing with rayon
            .par_iter()
            // render the status bar we've prepared, updating as we go
            .progress_with_style(mnemonic_bar_style)
            // actually disassemble and attempt to find a gadget
            .map(|pair| {
                (get_gadget_mnemonic(pair.0.as_ref(), pair.1[0], bin_arch, bin_endianness), pair.1)
            })
            // filter mnemonics using regex
            .filter(|pair| {
                // only bother with the regex if the regex object exists
                if (&cli_args.regex_str).is_some() {
                    let regex_obj = regex_mtx.lock().unwrap();
                    return regex_obj.is_match(&pair.0)
                // if there's no regex object, just yield everything
                } else {
                    return true;
                }
            })
            .collect();

        // if we used a regex, print the number of gadgets remaining after
        // applying it.
        if (&cli_args.regex_str).is_some() {
            if let Some(name) = seg_name {
                println!("{} unique gadgets in {} after filtering", mnemonics.len(), name);
            } else {
                println!("{} unique gadgets in segment after filtering", mnemonics.len());
            }
        }

        // TODO(garnt): print em all
        // print the first 10 mnemonics
        for mnemonic in mnemonics.iter().take(10) {
            println!("{:02x?}: {}", mnemonic.1, mnemonic.0);
        }
    }

    // Return something to satiate the compiler
    Ok(())
}