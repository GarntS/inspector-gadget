/*  file:       cli_args.rs
    author:     garnt
    date:       04/15/2024
    desc:       inspector_gadget::CLIArgs struct and associated functions.
 */

use clap::Parser;

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

    // maximum number of instructions to consider a gadget
    #[arg(short, long, default_value_t = 10)]
    pub max_insns: usize,
}