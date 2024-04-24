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
    // from_obj_arch() returns the corresponding Arch for a given
    // object::Architecture
    pub fn from_obj_arch(arch: object::Architecture) -> Self {
        match arch {
            object::Architecture::Aarch64 | object::Architecture::Aarch64_Ilp32 => Arch::Arm64,
            object::Architecture::Arm => Arch::Arm,
            object::Architecture::I386 => Arch::X86,
            object::Architecture::X86_64 | object::Architecture::X86_64_X32 => Arch::X86_64,
            object::Architecture::PowerPc => Arch::PowerPc,
            object::Architecture::PowerPc64 => Arch::PowerPc64,
            object::Architecture::Mips => Arch::Mips,
            object::Architecture::Mips64 => Arch::Mips64,
            object::Architecture::Riscv32 => Arch::Riscv32,
            object::Architecture::Riscv64 => Arch::Riscv64,
            object::Architecture::Sparc64 => Arch::Sparc64,
            object::Architecture::S390x => Arch::SysZ,
            // we should always handle every case here
            _ => unreachable!("Unexpected arch in from_obj_arch()!"),
        }
    }

    // to_obj_arch() returns the corresponding object::Architecture for this
    // Arch
    pub fn to_obj_arch(&self) -> object::Architecture {
        match self {
            Arch::Arm64 => object::Architecture::Aarch64,
            Arch::Arm => object::Architecture::Arm,
            Arch::X86 => object::Architecture::I386,
            Arch::X86_64 => object::Architecture::X86_64,
            Arch::PowerPc => object::Architecture::PowerPc,
            Arch::PowerPc64 => object::Architecture::PowerPc64,
            Arch::Mips => object::Architecture::Mips,
            Arch::Mips64 => object::Architecture::Mips64,
            Arch::Riscv32 => object::Architecture::Riscv32,
            Arch::Riscv64 => object::Architecture::Riscv64,
            Arch::Sparc64 => object::Architecture::Sparc64,
            Arch::SysZ => object::Architecture::S390x,
        }
    }

    // to_cs_arch() returns the corresponding object::Architecture for this Arch
    pub fn to_cs_arch(&self) -> capstone::Arch {
        match self {
            Arch::Arm64 => capstone::Arch::ARM64,
            Arch::Arm => capstone::Arch::ARM,
            Arch::X86 | Arch::X86_64 => capstone::Arch::X86,
            Arch::PowerPc | Arch::PowerPc64 => capstone::Arch::PPC,
            Arch::Mips | Arch::Mips64 => capstone::Arch::MIPS,
            Arch::Riscv32 | Arch::Riscv64 => capstone::Arch::RISCV,
            Arch::Sparc64 => capstone::Arch::SPARC,
            Arch::SysZ => capstone::Arch::SYSZ,
        }
    }
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
    // value_variants() returns a slice referencing every possible enum value,
    // in order
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

    // to_possible_value() returns a clap::builder::PossibleValue for a provided
    // Arch ref
    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            Arch:: Arm => Some(clap::builder::PossibleValue::new("arm/arm32")),
            Arch:: Arm64 => Some(clap::builder::PossibleValue::new("arm64/aarch64")),
            Arch:: X86 => Some(clap::builder::PossibleValue::new("x86/i386/i686/ia32")),
            Arch:: X86_64 => Some(clap::builder::PossibleValue::new("x86_64/x64/ia64")),
            Arch:: Mips => Some(clap::builder::PossibleValue::new("mips/mips32")),
            Arch:: Mips64 => Some(clap::builder::PossibleValue::new("mips64")),
            Arch:: PowerPc => Some(clap::builder::PossibleValue::new("powerpc32/ppc32/powerpc/ppc")),
            Arch:: PowerPc64 => Some(clap::builder::PossibleValue::new("powerpc64/ppc64")),
            Arch:: Riscv32 => Some(clap::builder::PossibleValue::new("riscv32/rv32/riscv")),
            Arch:: Riscv64 => Some(clap::builder::PossibleValue::new("riscv64/rv64")),
            Arch:: Sparc64 => Some(clap::builder::PossibleValue::new("sparc64/sparc")),
            Arch:: SysZ => Some(clap::builder::PossibleValue::new("sysz/s390x/systemz"))
        }
        
    }

    // from_str() returns an Arch matching a provided str input or an error
    fn from_str(input: &str, _ic: bool) -> Result<Self, String> {
        match input.to_lowercase().as_str() {
            "arm" | "arm32" => Ok(Arch::Arm),
            "arm64" | "aarch64" => Ok(Arch::Arm64),
            "i386" | "i686" | "ia32" | "ia-32" |"x86" => Ok(Arch::X86),
            "x64" | "ia64" | "ia-64" | "x86_64" => Ok(Arch::X86_64),
            "mips" | "mips32" => Ok(Arch::Mips),
            "mips64" => Ok(Arch::Mips64),
            "ppc32" | "powerpc32" | "ppc" | "powerpc" => Ok(Arch::PowerPc),
            "ppc64" | "powerpc64" => Ok(Arch::PowerPc64),
            "riscv32" | "rv32" | "riscv" => Ok(Arch::Riscv32),
            "riscv64" | "rv64" => Ok(Arch::Riscv64),
            "sparc" | "sparc64" => Ok(Arch::Sparc64),
            "sysz" | "s390x" | "systemz" => Ok(Arch::SysZ),
            _ => Err("Unknown arch str!".to_owned())
        }
    }
}
