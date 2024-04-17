/*  file:       cli_args.rs
    author:     garnt
    date:       04/15/2024
    desc:       inspector_gadget::CLIArgs struct and associated functions.
 */

use clap::Parser;

use crate::ig_error::IGError;

// Struct to contain the clap-parsed arguments.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct CLIArgs {
    // path to the binary file to search in
    #[arg(short, long)]
    pub bin_path: String,

    // string containing regex to filter with
    #[arg(short, long)]
    pub regex_str: Option<String>,

    //
    // Below are fields that can be serialized into a GadgetConstraints struct.
    //

    // minimum number of instructions to consider a gadget
    #[arg(long, default_value_t = 3)]
    pub min_insns: usize,

    // maximum number of instructions to consider a gadget
    #[arg(short, long, default_value_t = 10)]
    pub max_insns: usize,

    // if ret instructions are allowed to terminate gadgets
    #[arg(long, default_value_t = true)]
    pub allow_terminating_ret: bool,

    // if indirect call instructions are allowed to terminate gadgets
    #[arg(long, default_value_t = false)]
    pub allow_terminating_call: bool,

    // if non-call indirect jmp instructions are allowed to terminate gadgets
    #[arg(long, default_value_t = false)]
    pub allow_terminating_jmp: bool,
}

// Struct containing only the gadget-finding constraints contained within
// CLIArgs.
#[derive(Clone, Copy, Debug)]
pub struct GadgetConstraints {
    pub min_insns: usize,
    pub max_insns: usize,
    pub allow_terminating_ret: bool,
    pub allow_terminating_call: bool,
    pub allow_terminating_jmp: bool,
}

// GadgetConstraints method impls
impl GadgetConstraints {
    // from_cli_args() constructs a new GadgetConstraints object from the
    // relevant fields of the passed CLIArgs object. 
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

    // is_valid() returns true if the provided GadgetConstraints can result in
    // valid gadgets.
    pub fn is_valid(&self) -> Result<(), IGError> {
        // if either n_insns bound is zero, it's invalid
        if self.min_insns == 0 || self.max_insns == 0 {
            return Err(IGError::new("n_insns bounds cannot be 0!"));
        }

        // if either min_insns is greater than max_insns, it's invalid
        if self.min_insns > self.max_insns {
            return Err(IGError::new("max_insns must be greater than min_insns!"));
        }

        // if no terminating instructions are specified, it's invalid
        if !self.allow_terminating_ret && !self.allow_terminating_call && !self.allow_terminating_jmp {
            return Err(IGError::new("at least one terminating instruction must be allowed!"));
        }

        // default is valid
        Ok(())
    }
}