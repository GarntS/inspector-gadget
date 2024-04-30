/*  file:   arch.rs
    author: garnt
    date:   04/24/2024
    desc:   Types and convenience functions used for storing architecture
            information and converting to other formats.
*/

//! arch contains enum implementations for architecture and endianness used
//! during disassembly, as well as convenience functions to convert to/from the
//! corresponding architecture and endianness enums used by other crates.

use std::fmt;

/// Endianness refers to a machine code endianness used during disassembly.
#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
pub enum Endianness {
    /// Big-Endian byte ordering (MSB-first).
    Big,
    /// Little-Endian byte ordering (LSB-first).
    Little,
}

/// Arch refers to a specific machine code architecture used during disassembly.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Arch {
    /// 32-bit ARM variants.
    Arm,
    /// 64-bit ARM variants.
    Arm64,
    /// 32-bit x86 variants, including i386, i686, IA-32, etc.
    X86,
    /// 64-bit x86_64 variants, including x32 and IA-64.
    X86_64,
    /// 32-bit MIPS variants.
    Mips,
    /// 64-bit MIPS variants.
    Mips64,
    /// 32-bit PowerPc variants.
    PowerPc,
    /// 64-bit PowerPc variants.
    PowerPc64,
    /// 32-bit register-sized RISC-V variants.
    Riscv32,
    /// 64-bit register-sized RISC-V variants.
    Riscv64,
    /// 64-bit SPARC variants.
    Sparc64,
    /// SystemZ variants, including s390x, etc.
    SysZ,
}

// Endianness method impls
impl Endianness {
    /// Returns the corresponding Endianness for a given [`capstone::Endian`].
    #[allow(dead_code)]
    pub fn from_cs_endian(endian: capstone::Endian) -> Self {
        match endian {
            capstone::Endian::Big => Endianness::Big,
            capstone::Endian::Little => Endianness::Little,
        }
    }

    /// Returns the corresponding Endianness for a given [`object::Endianness`].
    pub fn from_obj_endianness(endianness: object::Endianness) -> Self {
        match endianness {
            object::Endianness::Big => Endianness::Big,
            object::Endianness::Little => Endianness::Little,
        }
    }

    /// Returns the corresponding [`capstone::Endian`] for this Endianness.
    pub fn to_cs_endian(&self) -> capstone::Endian {
        match self {
            Endianness::Big => capstone::Endian::Big,
            Endianness::Little => capstone::Endian::Little,
        }
    }

    /// Returns the corresponding [`object::Endianness`] for this Endianness.
    #[allow(dead_code)]
    pub fn to_obj_endianness(&self) -> object::Endianness {
        match self {
            Endianness::Big => object::Endianness::Big,
            Endianness::Little => object::Endianness::Little,
        }
    }
}

// impl std::fmt::Display for Endianness
impl fmt::Display for Endianness {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Endianness::Big => write!(f, "big"),
            Endianness::Little => write!(f, "little"),
        }
    }
}

// Arch method impls
impl Arch {
    /// Returns the corresponding Arch for a given [`object::Architecture`].
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

    /// Returns the corresponding [`object::Architecture`] for this Arch.
    #[allow(dead_code)]
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

    /// Returns the corresponding [`capstone::Arch`] for this Arch.
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
            Arch::Arm => write!(f, "arm"),
            Arch::Arm64 => write!(f, "arm64"),
            Arch::X86 => write!(f, "x86"),
            Arch::X86_64 => write!(f, "x86_64"),
            Arch::Mips => write!(f, "mips"),
            Arch::Mips64 => write!(f, "mips64"),
            Arch::PowerPc => write!(f, "powerpc"),
            Arch::PowerPc64 => write!(f, "powerpc64"),
            Arch::Riscv32 => write!(f, "riscv32"),
            Arch::Riscv64 => write!(f, "riscv64"),
            Arch::Sparc64 => write!(f, "sparc64"),
            Arch::SysZ => write!(f, "systemz"),
        }
    }
}

// impl clap::ValueEnum for Arch
impl clap::ValueEnum for Arch {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Arch::Arm,
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
            Arch::SysZ,
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            Arch::Arm => Some(clap::builder::PossibleValue::new("arm")),
            Arch::Arm64 => Some(clap::builder::PossibleValue::new("arm64")),
            Arch::X86 => Some(clap::builder::PossibleValue::new("x86")),
            Arch::X86_64 => Some(clap::builder::PossibleValue::new("x86_64")),
            Arch::Mips => Some(clap::builder::PossibleValue::new("mips")),
            Arch::Mips64 => Some(clap::builder::PossibleValue::new("mips64")),
            Arch::PowerPc => Some(clap::builder::PossibleValue::new("powerpc")),
            Arch::PowerPc64 => Some(clap::builder::PossibleValue::new("powerpc64")),
            Arch::Riscv32 => Some(clap::builder::PossibleValue::new("riscv")),
            Arch::Riscv64 => Some(clap::builder::PossibleValue::new("riscv64")),
            Arch::Sparc64 => Some(clap::builder::PossibleValue::new("sparc64")),
            Arch::SysZ => Some(clap::builder::PossibleValue::new("sysz")),
        }
    }
}
