/*  file:       capstone_tools.rs
    author:     garnt
    date:       04/17/2024
    desc:       Some functions used for interacting with capstone.
 */

use capstone::{Capstone, InsnGroupId, InsnGroupType, InsnId};
use capstone::arch::{self, BuildsCapstone, BuildsCapstoneEndian, BuildsCapstoneExtraMode, BuildsCapstoneSyntax};
use capstone::arch::ppc::PpcInsn;
use crate::cli_args::GadgetConstraints;
use crate::IGError;
use object::ObjectSegment;

// constant-valued Capstone group IDS
pub const JMP_GRP_ID: InsnGroupId = InsnGroupId(InsnGroupType::CS_GRP_JUMP as u8);
pub const CALL_GRP_ID: InsnGroupId = InsnGroupId(InsnGroupType::CS_GRP_CALL as u8);
pub const RET_GRP_ID: InsnGroupId = InsnGroupId(InsnGroupType::CS_GRP_RET as u8);
pub const REL_BR_GRP_ID: InsnGroupId = InsnGroupId(InsnGroupType::CS_GRP_BRANCH_RELATIVE as u8);

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

// init_capstone() constructs a Capstone object for the correct arch
pub fn init_capstone(arch: object::Architecture, endianness: object::Endianness, enable_detail: bool) -> Result<Capstone, IGError> {
    // translate object::Endianness to capstone::Endian
    let obj_end: capstone::Endian = match endianness {
        object::Endianness::Big => capstone::Endian::Big,
        object::Endianness::Little => capstone::Endian::Little,
    };

    match arch {
        object::Architecture::Aarch64 => Ok(Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .endian(obj_end)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for arm64!")),
        object::Architecture::Arm => Ok(Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .endian(obj_end)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for arm!")),
        object::Architecture::Mips64 => Ok(Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips64)
            .endian(obj_end)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for mips64!")),
        object::Architecture::Mips => Ok(Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips32)
            .endian(obj_end)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for mips!")),
        object::Architecture::Riscv64 => Ok(Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .extra_mode(std::iter::once(arch::riscv::ArchExtraMode::RiscVC))
            .endian(obj_end)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for riscv64!")),
        object::Architecture::Riscv32 => Ok(Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV32)
            .extra_mode(std::iter::once(arch::riscv::ArchExtraMode::RiscVC))
            .endian(obj_end)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for riscv32!")),
        object::Architecture::PowerPc64 => Ok(Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode64)
            .endian(obj_end)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for powerpc64!")),
        object::Architecture::PowerPc => Ok(Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode32)
            .endian(capstone::Endian::Big)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for powerpc32!")),
        object::Architecture::X86_64 | object::Architecture::X86_64_X32 => Ok(Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for x86(_64)!")),
        object::Architecture::I386 => Ok(Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for x86(_64)!")),
        object::Architecture::Sparc64 => Ok(Capstone::new()
            .sparc()
            .mode(arch::sparc::ArchMode::Default)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for sparc!")),
        object::Architecture::S390x => Ok(Capstone::new()
            .sysz()
            .mode(arch::sysz::ArchMode::Default)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for s390x/sysz!")),
        _ => Err(IGError::new("Unexpected architecture!"))
    }
}

// valid_gadget_start_addrs() returns an owned vec<usize> of all the valid
// start addresses for a gadget within the given segment.
pub fn valid_gadget_start_addrs(segment: &object::Segment, arch: object::Architecture) -> Vec<usize> {
    // grab segment start and end addrs
    let segment_start_addr: usize = segment.address() as usize;
    let segment_end_addr: usize = segment_start_addr + segment.size() as usize;

    // figure out the valid instruction alignment for this arch
    let instr_alignment: usize = match arch {
        // arm/aarch64/ppc/mips are 4-byte aligned
        object::Architecture::Arm
        | object::Architecture::Aarch64
        | object::Architecture::Aarch64_Ilp32
        | object::Architecture::PowerPc
        | object::Architecture::PowerPc64
        | object::Architecture::Mips
        | object::Architecture::Mips64
        | object::Architecture::Sparc64 => 4,
        // risc-v can have 2-byte instructions and 2-byte alignment when it's
        // using the c extension, which we assume is is supported because all
        // risc-v SoC's that I can find in production support it.
        // s390x/sysz instructions can mysteriously be half-word aligned
        // despite having instruction sizes of 4-, 6-, and 8-bytes.
        object::Architecture::S390x
        | object::Architecture::Riscv32
        | object::Architecture::Riscv64 => 2,
        // x86/x86_64 aren't aligned
        object::Architecture::I386
        | object::Architecture::X86_64_X32
        | object::Architecture::X86_64 => 1,
        // default to None
        _ => unreachable!("Unexpected architecture!")
    };

    // iterate over the valid start addresses and return a vec containing them
    (segment_start_addr..(segment_end_addr + 1))
        .step_by(instr_alignment)
        .collect()
}

// GadgetSearchInsnInfo contains information about whether the current
// instruction would terminate a gadget search, and if the resulting gadget
// remains valid.
#[derive(Clone, Copy, Debug)]
pub struct GadgetSearchInsnInfo {
    // true if this instruction should terminate the search
    pub is_terminating: bool,
    // true if the gadget is a valid gadget if this instruction is added to it
    pub is_valid_gadget: bool,
}

// constant-valued Capstone PPC InsnId's
const PPC_BLR_ID: InsnId = InsnId(PpcInsn::PPC_INS_BLR as u32);

// is_terminating_insn_ppc() does the is_terminating_insn() evaluation for
// the passed ppc instruction.
fn is_terminating_insn_ppc(insn: &capstone::Insn, detail: &capstone::InsnDetail, constraints: &GadgetConstraints) -> GadgetSearchInsnInfo {
    // relative branches are always direct jumps and therefore not allowed
    if detail.groups().contains(&REL_BR_GRP_ID) {
        return GadgetSearchInsnInfo {
            is_terminating: true,
            is_valid_gadget: false
        };
    }

    // check to see if this instruction is a ret
    if constraints.allow_terminating_ret && insn.id() == PPC_BLR_ID {
        return GadgetSearchInsnInfo {
            is_terminating: true,
            is_valid_gadget: true,
        };
    }

    // check if this instruction is a call
    if detail.groups().contains(&CALL_GRP_ID) {
        // if a register wasn't read, it's a direct call, which can't exist
        // in the middle of a gadget
        if detail.regs_read().len() == 0 {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: false
            };
        // if a register was read, and terminating calls are allowed,
        // terminate the gadget
        } else if constraints.allow_terminating_call {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: true
            };
        }
    }

    // check if this instruction is a jump
    if detail.groups().contains(&JMP_GRP_ID) {
        // if a register wasn't read, we need to check if this instruction
        // is a direct jump, which can't exist in the middle of a gadget
        if detail.regs_read().len() == 0 {
            // if a register wasn't read and there's no immediate, which
            // would be stored in the op_str, it's a direct jump
            if insn.op_str().is_none() {
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: false
                };
            }
        // if a register was read, and terminating jumps are allowed,
        // terminate the gadget
        } else if constraints.allow_terminating_jmp {
            // if the gadget length is valid, the gadget is valid
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: true
            };
        }
    }

    // for any non-terminating instructions, signal to continue the search
    GadgetSearchInsnInfo {
        is_terminating: false,
        is_valid_gadget: true,
    }
}

// is_terminating_insn_riscv() does the is_terminating_insn() evaluation for
// the passed riscv instruction.
fn is_terminating_insn_riscv(insn: &capstone::Insn, detail: &capstone::InsnDetail, constraints: &GadgetConstraints) -> GadgetSearchInsnInfo {
    // TODO(garnt): remove
    //println!("bytes: {:x?}(len {})", insn.bytes(), insn.bytes().len());

    // relative branches are always direct jumps and therefore not allowed
    if detail.groups().contains(&REL_BR_GRP_ID) {
        return GadgetSearchInsnInfo {
            is_terminating: true,
            is_valid_gadget: false
        };
    }

    // ret on riscv is a special case of JALR: JALR x0, x1, 0
    // that instruction assembles to different opcodes based on whether the
    // compiler chose the compressed version of the gadget or the normal one,
    // so check for both
    if constraints.allow_terminating_ret {
        if insn.bytes() == b"\x82\x80" || insn.bytes() == b"\x67\x80\x00\x00" {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: true,
            };
        }
    }

    // check if this instruction is a call
    if detail.groups().contains(&CALL_GRP_ID) {
        // if a register wasn't read, it's a direct call, which can't exist
        // in the middle of a gadget
        if detail.regs_read().len() == 0 {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: false
            };
        // if a register was read, and terminating calls are allowed,
        // terminate the gadget
        } else if constraints.allow_terminating_call {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: true
            };
        }
    }

    // check if this instruction is a jump
    if detail.groups().contains(&JMP_GRP_ID) {
        // if a register wasn't read, we need to check if this instruction
        // is a direct jump, which can't exist in the middle of a gadget
        if detail.regs_read().len() == 0 {
            // if a register wasn't read and there's no immediate, which
            // would be stored in the op_str, it's a direct jump
            if insn.op_str().is_none() {
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: false
                };
            }
        // if a register was read, and terminating jumps are allowed,
        // terminate the gadget
        } else if constraints.allow_terminating_jmp {
            // if the gadget length is valid, the gadget is valid
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: true
            };
        }
    }

    // for any non-terminating instructions, signal to continue the search
    GadgetSearchInsnInfo {
        is_terminating: false,
        is_valid_gadget: true,
    }
}

// constant-valued Capstone SYSZ InsnId's
const SYSZ_BAL_ID: InsnId = InsnId(capstone_sys::sysz_insn::SYSZ_INS_BAL as u32);
const SYSZ_BAS_ID: InsnId = InsnId(capstone_sys::sysz_insn::SYSZ_INS_BAS as u32);
const SYSZ_BRASL_ID: InsnId = InsnId(capstone_sys::sysz_insn::SYSZ_INS_BRASL as u32);
const SYSZ_BRAS_ID: InsnId = InsnId(capstone_sys::sysz_insn::SYSZ_INS_BRAS as u32);

// is_terminating_insn_sysz() does the is_terminating_insn() evaluation for
// the passed sysz instruction.
fn is_terminating_insn_sysz(insn: &capstone::Insn, detail: &capstone::InsnDetail, constraints: &GadgetConstraints) -> GadgetSearchInsnInfo {
    // return addrs in the sysz calling convention are stored in r14, so ret is:
    // br r14. check for that opcode
    if constraints.allow_terminating_ret && insn.bytes() == b"\x07\xfe" {
        return GadgetSearchInsnInfo {
            is_terminating: true,
            is_valid_gadget: true,
        };
    }

    // otherwise, match the instruction id
    match insn.id() {
        // relative branches
        SYSZ_BAL_ID
        | SYSZ_BAS_ID => {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: false
            };
        },
        // function calls
        SYSZ_BRASL_ID
        | SYSZ_BRAS_ID => {
            // if a register wasn't read, it's a direct call, which can't exist
            // in the middle of a gadget
            if detail.regs_read().len() == 0 {
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: false
                };
            // if a register was read, and terminating calls are allowed,
            // terminate the gadget
            } else if constraints.allow_terminating_call {
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: true
                };
            }
        },
        _ => {}
    }

    // for any non-terminating instructions, signal to continue the search
    GadgetSearchInsnInfo {
        is_terminating: false,
        is_valid_gadget: true,
    }
}

// is_terminating_insn() evaluates whether a given instruction terminates the
// current gadget being searched for, and if the gadget is a valid gadget after
// the current instruction is included in it.
pub fn is_terminating_insn(insn: &capstone::Insn, detail: &capstone::InsnDetail, arch: capstone::Arch, constraints: GadgetConstraints) -> GadgetSearchInsnInfo {
    // some architectures' capstone disassemblers don't tag gadget-terminating
    // instructions with the architecture-generic capstone instruction groups
    // in quite the way we're expecting, especially if those architectures
    // don't have dedicated ret instructions, so we implement this function
    // differently for those architectures.
    match arch {
        // PPC, RISCV, and S390x don't play nicely.
        capstone::Arch::PPC => is_terminating_insn_ppc(insn, detail, &constraints),
        capstone::Arch::RISCV => is_terminating_insn_riscv(insn, detail, &constraints),
        capstone::Arch::SYSZ => is_terminating_insn_sysz(insn, detail, &constraints),
        // This is the default case for architectures that play nicely.
        _ => {
            // relative branches are always direct jumps and therefore not allowed
            if detail.groups().contains(&REL_BR_GRP_ID) {
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: false
                };
            }

            // if terminating rets are allowed, check if this instruction is a ret
            // and terminates the gadget
            if constraints.allow_terminating_ret && detail.groups().contains(&RET_GRP_ID) {
                // if the gadget length is valid, the gadget is valid
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: true
                };
            }

            // check if this instruction is a call
            if detail.groups().contains(&CALL_GRP_ID) {
                // if a register wasn't read, it's a direct call, which can't exist
                // in the middle of a gadget
                if detail.regs_read().len() == 0 {
                    return GadgetSearchInsnInfo {
                        is_terminating: true,
                        is_valid_gadget: false
                    };
                // if a register was read, and terminating calls are allowed,
                // terminate the gadget
                } else if constraints.allow_terminating_call {
                    return GadgetSearchInsnInfo {
                        is_terminating: true,
                        is_valid_gadget: true
                    };
                }
            }

            // check if this instruction is a jump
            if detail.groups().contains(&JMP_GRP_ID) {
                // if a register wasn't read, we need to check if this instruction
                // is a direct jump, which can't exist in the middle of a gadget
                if detail.regs_read().len() == 0 {
                    // if a register wasn't read and there's no immediate, which
                    // would be stored in the op_str, it's a direct jump
                    if insn.op_str().is_none() {
                        return GadgetSearchInsnInfo {
                            is_terminating: true,
                            is_valid_gadget: false
                        };
                    }
                // if a register was read, and terminating jumps are allowed,
                // terminate the gadget
                } else if constraints.allow_terminating_jmp {
                    // if the gadget length is valid, the gadget is valid
                    return GadgetSearchInsnInfo {
                        is_terminating: true,
                        is_valid_gadget: true
                    };
                }
            }

            // for any non-terminating instructions, we should continue the
            // search
            GadgetSearchInsnInfo {
                is_terminating: false,
                is_valid_gadget: true,
            }
        }
    }
}