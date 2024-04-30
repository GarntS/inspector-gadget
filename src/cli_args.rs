/*  file:   cli_args.rs
    author: garnt
    date:   04/15/2024
    desc:   CLIArgs struct, GadgetConstraints struct, and their methods/trait
            impls.
*/

//! cli_args contains structures used to contain flags and information
//! parsed from command line flags.

use crate::arch::{Arch, Endianness};
use clap::Parser;
use std::path::PathBuf;

/// CLIArgs contain the [`clap`]-parsed command line arguments for
/// inspector-gadget.
#[derive(Parser, Debug, PartialEq)]
#[command(version, about, long_about = None)]
#[clap(rename_all = "kebab_case")]
pub struct CLIArgs {
    /// Path to the binary file to search for gadgets in.
    pub bin_path: PathBuf,

    /// Path to the file which found gadgets should be written to.
    #[arg(short, long, group = "outfile")]
    pub out_file: Option<PathBuf>,

    /// True if the out_file should be written to even if it already
    /// exists. (If the out_file is a directory, it will never be
    /// overwritten.)
    #[arg(long, requires = "outfile", default_value_t = false)]
    pub overwrite: bool,

    /// String containing an optional regex used to filter gadgets by applying
    /// the regex to each gadget's concatenated mnemonics.
    #[arg(short, long)]
    pub regex_str: Option<String>,

    /// True if the input binary should be treated as a raw blob.
    #[arg(long, requires = "manualarch", default_value_t = false)]
    pub raw_binary: bool,

    /// Override for input binary's arch. Required if the `--raw-binary` flag
    /// is set.
    #[arg(long, value_enum, group = "manualarch")]
    pub arch: Option<Arch>,

    /// Override for input binary's endianness. Required if the `--raw-binary`
    /// flag is set.
    #[arg(long, default_value_t = Endianness::Little)]
    pub endianness: Endianness,

    //
    // Below are fields that can be serialized into a GadgetConstraints struct.
    //
    /// Minimum number of instructions required to be contained within a gadget
    /// in order to consider a gadget valid.
    #[arg(long, default_value_t = 2)]
    pub min_insns: usize,

    /// Maximum number of instructions required to be contained within a gadget
    /// in order to consider a gadget valid.
    #[arg(long, default_value_t = 10)]
    pub max_insns: usize,

    /// True if ret instructions are allowed to terminate gadgets.
    #[arg(long, default_value_t = true)]
    pub allow_terminating_ret: bool,

    /// True if indirect call instructions are allowed to terminate gadgets.
    #[arg(long, default_value_t = false)]
    pub allow_terminating_call: bool,

    /// True if indirect jump/non-call branch instructions are allowed to
    /// terminate gadgets.
    #[arg(long, default_value_t = false)]
    pub allow_terminating_jmp: bool,
}

/// GadgetConstraints contains only the gadget-finding constraints stored
/// within [`CLIArgs`].
#[derive(Clone, Copy, Debug)]
pub struct GadgetConstraints {
    /// See [`CLIArgs::min_insns`].
    pub min_insns: usize,
    /// See [`CLIArgs::max_insns`].
    pub max_insns: usize,
    /// See [`CLIArgs::allow_terminating_ret`].
    pub allow_terminating_ret: bool,
    /// See [`CLIArgs::allow_terminating_call`].
    pub allow_terminating_call: bool,
    /// See [`CLIArgs::allow_terminating_jmp`].
    pub allow_terminating_jmp: bool,
}

// GadgetConstraints method impls
impl GadgetConstraints {
    /// Constructs a new [`GadgetConstraints`] from the relevant fields of the
    /// passed [`CLIArgs`].
    pub fn from_cli_args(args: &CLIArgs) -> Self {
        // construct the new GadgetConstraints struct
        let constraints = GadgetConstraints {
            min_insns: args.min_insns,
            max_insns: args.max_insns,
            allow_terminating_ret: args.allow_terminating_ret,
            allow_terminating_call: args.allow_terminating_call,
            allow_terminating_jmp: args.allow_terminating_jmp,
        };

        // struct must be valid
        assert!(constraints.is_valid().is_ok());

        // return constraints
        constraints
    }

    /// Returns true if this [`GadgetConstraints`] can result in valid gadgets.
    pub fn is_valid(&self) -> Result<(), String> {
        // if either n_insns bound is zero, it's invalid
        if self.min_insns == 0 || self.max_insns == 0 {
            return Err("n_insns bounds cannot be 0!".to_owned());
        }

        // if either min_insns is greater than max_insns, it's invalid
        if self.min_insns > self.max_insns {
            return Err("max_insns must be greater than min_insns!".to_owned());
        }

        // if no terminating instructions are specified, it's invalid
        if !self.allow_terminating_ret
            && !self.allow_terminating_call
            && !self.allow_terminating_jmp
        {
            return Err("at least one terminating instruction must be allowed!".to_owned());
        }

        // default is valid
        Ok(())
    }
}
