/*  file:       arch.rs
    author:     garnt
    date:       04/24/2024
    desc:       Types and convenience functions used for storing architecture
                information and converting to other formats.
 */

use std::fmt;

// Arch refers to a specific architecture
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Arch {
    Arm,
    Arm64,
    X86,
    X86_64,
    Mips,
    Mips64,
    PowerPc,
    PowerPc64,
    Riscv32,
    Riscv64,
    Sparc64,
    SysZ,
}

// Arch method impls
impl Arch {

}

// impl std::fmt::Display for Arch
impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Arch:: Arm => write!(f, "arm"),
            Arch:: Arm64 => write!(f, "arm64"),
            Arch:: X86 => write!(f, "x86"),
            Arch:: X86_64 => write!(f, "x86_64"),
            Arch:: Mips => write!(f, "mips"),
            Arch:: Mips64 => write!(f, "mips64"),
            Arch:: PowerPc => write!(f, "powerpc"),
            Arch:: PowerPc64 => write!(f, "powerpc64"),
            Arch:: Riscv32 => write!(f, "riscv32"),
            Arch:: Riscv64 => write!(f, "riscv64"),
            Arch:: Sparc64 => write!(f, "sparc64"),
            Arch:: SysZ => write!(f, "systemz"),
        }
    }
}

// impl clap::ValueEnum for Arch
impl clap::ValueEnum for Arch {
    // returns a slice referencing every possible enum value, in order
    fn value_variants<'a>() -> &'a [Self] {
        &[Arch::Arm,
            Arch::Arm64,
            Arch::X86,
            Arch::X86_64,
            Arch::Mips,
            Arch::Mips64,
            Arch::PowerPc,
            Arch::PowerPc64,
            Arch::Riscv32,
            Arch::Riscv64,
            Arch::Sparc64,
            Arch::SysZ
        ]
    }

    // returns a clap::builder::PossibleValue for a provided Arch ref
    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        
    }

    fn from_str(input: &str, ignore_case: bool) -> Result<Self, String> {

        
    }
}

// object_arch_to_cs_arch() returns the corresponding capstone::arch enum value
// for the provided object::Architecture enum value.
pub fn object_arch_to_cs_arch(arch: object::Architecture) -> Option<capstone::Arch> {
    match arch {
        // aarch64
        object::Architecture::Aarch64 | object::Architecture::Aarch64_Ilp32 => Some(capstone::Arch::ARM64),
        // arm32
        object::Architecture::Arm => Some(capstone::Arch::ARM),
        // x86/x86_64
        object::Architecture::I386 | object::Architecture::X86_64 | object::Architecture::X86_64_X32 => Some(capstone::Arch::X86),
        // ppc
        object::Architecture::PowerPc | object::Architecture::PowerPc64 => Some(capstone::Arch::PPC),
        // mips
        object::Architecture::Mips | object::Architecture::Mips64 => Some(capstone::Arch::MIPS),
        // risc-v
        object::Architecture::Riscv32 | object::Architecture::Riscv64 => Some(capstone::Arch::RISCV),
        // sparc
        object::Architecture::Sparc64 => Some(capstone::Arch::SPARC),
        // s390x/sysz
        object::Architecture::S390x => Some(capstone::Arch::SYSZ),
        // default to None
        _ => None
    }
}
