/*  file:   disasm_tools.rs
    author: garnt
    date:   04/17/2024
    desc:   Some functions used for interacting with capstone during
            disassembly and gadget-finding.
*/

//! disasm_tools contains some functions used during the gadget-finding process
//! that specifically pertain to disassembly and instruction evaluation. These
//! functions have been separated into a new module to reduce the amount of
//! code in main.rs and increase readability.

use crate::arch::{Arch, Endianness};
use crate::cli_args::GadgetConstraints;
use capstone::arch::arm::{ArmInsn, ArmOperandType};
use capstone::arch::ppc::PpcInsn;
use capstone::arch::{
    BuildsCapstone, BuildsCapstoneEndian, BuildsCapstoneExtraMode, BuildsCapstoneSyntax,
    DetailsArchInsn,
};
use capstone::{Capstone, InsnGroupId, InsnGroupType, InsnId};
use capstone_sys::{cs_close, cs_op_count};

// constant-valued Capstone group ids for is_terminating_insn() and its
// architecture-specific variants.
/// Constant-valued Capstone InsnGroupID for jump instructions.
const JMP_GRP_ID: InsnGroupId = InsnGroupId(InsnGroupType::CS_GRP_JUMP as u8);
/// Constant-valued Capstone InsnGroupID for call instructions.
const CALL_GRP_ID: InsnGroupId = InsnGroupId(InsnGroupType::CS_GRP_CALL as u8);
/// Constant-valued Capstone InsnGroupID for return instructions.
const RET_GRP_ID: InsnGroupId = InsnGroupId(InsnGroupType::CS_GRP_RET as u8);
/// Constant-valued Capstone InsnGroupID for relative branch instructions.
const REL_BR_GRP_ID: InsnGroupId = InsnGroupId(InsnGroupType::CS_GRP_BRANCH_RELATIVE as u8);

// constant-valued Capstone ARM InsnId's for is_terminating_insn_arm()
/// Constant-valued Capstone InsnID for the ARM BX instruction.
const ARM_BX_ID: InsnId = InsnId(ArmInsn::ARM_INS_BX as u32);
/// Constant-valued Capstone InsnID for the ARM BLX instruction.
const ARM_BLX_ID: InsnId = InsnId(ArmInsn::ARM_INS_BLX as u32);
/// Constant-valued Capstone InsnID for the ARM POP instruction.
const ARM_POP_ID: InsnId = InsnId(ArmInsn::ARM_INS_POP as u32);
/// Constant-valued Capstone RegID for the ARM PC register.
const ARM_PC_OPTYPE: ArmOperandType = ArmOperandType::Reg(capstone::RegId(
    capstone::arch::arm::ArmReg::ARM_REG_PC as u16,
));
/// Constant-valued Capstone RegID for the ARM LR register.
const ARM_LR_OPTYPE: ArmOperandType = ArmOperandType::Reg(capstone::RegId(
    capstone::arch::arm::ArmReg::ARM_REG_LR as u16,
));

// constant-valued Capstone PPC InsnId's for is_terminating_insn_ppc()
/// Constant-valued Capstone InsnID for the PowerPC BLR instruction.
const PPC_BLR_ID: InsnId = InsnId(PpcInsn::PPC_INS_BLR as u32);

// constant-valued Capstone SYSZ InsnId's for is_terminating_insn_sysz().
/// Constant-valued Capstone InsnID for the SystemZ BAL instruction.
const SYSZ_BAL_ID: InsnId = InsnId(capstone_sys::sysz_insn::SYSZ_INS_BAL as u32);
/// Constant-valued Capstone InsnID for the SystemZ BAS instruction.
const SYSZ_BAS_ID: InsnId = InsnId(capstone_sys::sysz_insn::SYSZ_INS_BAS as u32);
/// Constant-valued Capstone InsnID for the SystemZ BRASL instruction.
const SYSZ_BRASL_ID: InsnId = InsnId(capstone_sys::sysz_insn::SYSZ_INS_BRASL as u32);
/// Constant-valued Capstone InsnID for the SystemZ BRAS instruction.
const SYSZ_BRAS_ID: InsnId = InsnId(capstone_sys::sysz_insn::SYSZ_INS_BRAS as u32);

/// Constructs a Capstone object with the provided [`Arch`], [`Endianness`],
/// and detail values, with sane defaults for arch-specific settings.
pub fn init_capstone(
    arch: Arch,
    endianness: Endianness,
    enable_detail: bool,
) -> Result<Capstone, String> {
    match arch {
        Arch::Arm64 => Ok(Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .endian(endianness.to_cs_endian())
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for arm64!")),
        Arch::Arm => Ok(Capstone::new()
            .arm()
            .mode(capstone::arch::arm::ArchMode::Arm)
            .endian(endianness.to_cs_endian())
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for arm!")),
        Arch::Mips64 => Ok(Capstone::new()
            .mips()
            .mode(capstone::arch::mips::ArchMode::Mips64)
            .endian(endianness.to_cs_endian())
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for mips64!")),
        Arch::Mips => Ok(Capstone::new()
            .mips()
            .mode(capstone::arch::mips::ArchMode::Mips32)
            .endian(endianness.to_cs_endian())
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for mips!")),
        Arch::Riscv64 => Ok(Capstone::new()
            .riscv()
            .mode(capstone::arch::riscv::ArchMode::RiscV64)
            .extra_mode(std::iter::once(
                capstone::arch::riscv::ArchExtraMode::RiscVC,
            ))
            .endian(endianness.to_cs_endian())
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for riscv64!")),
        Arch::Riscv32 => Ok(Capstone::new()
            .riscv()
            .mode(capstone::arch::riscv::ArchMode::RiscV32)
            .extra_mode(std::iter::once(
                capstone::arch::riscv::ArchExtraMode::RiscVC,
            ))
            .endian(endianness.to_cs_endian())
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for riscv32!")),
        Arch::PowerPc64 => Ok(Capstone::new()
            .ppc()
            .mode(capstone::arch::ppc::ArchMode::Mode64)
            .endian(endianness.to_cs_endian())
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for powerpc64!")),
        Arch::PowerPc => Ok(Capstone::new()
            .ppc()
            .mode(capstone::arch::ppc::ArchMode::Mode32)
            .endian(capstone::Endian::Big)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for powerpc32!")),
        Arch::X86_64 => Ok(Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for x86_64!")),
        Arch::X86 => Ok(Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode32)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for x86!")),
        Arch::Sparc64 => Ok(Capstone::new()
            .sparc()
            .mode(capstone::arch::sparc::ArchMode::Default)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for sparc!")),
        Arch::SysZ => Ok(Capstone::new()
            .sysz()
            .mode(capstone::arch::sysz::ArchMode::Default)
            .detail(enable_detail)
            .build()
            .expect("Failed to create Capstone object for s390x/sysz!")),
    }
}

/// Returns an owned [`Vec<usize>`] of all the valid start addresses for a
/// gadget with the given [`Arch`] within the memory region defined by the
/// provided start address and size.
pub fn valid_gadget_start_addrs(
    arch: Arch,
    region_start_addr: usize,
    region_len: usize,
) -> Vec<usize> {
    // figure out the valid instruction alignment for this arch
    let instr_alignment: usize = match arch {
        // arm/aarch64/ppc/mips are 4-byte aligned
        Arch::Arm
        | Arch::Arm64
        | Arch::PowerPc
        | Arch::PowerPc64
        | Arch::Mips
        | Arch::Mips64
        | Arch::Sparc64 => 4,
        // risc-v can have 2-byte instructions and 2-byte alignment when it's
        // using the c extension, which we assume is is supported because all
        // risc-v SoC's that I can find in production support it.
        // s390x/sysz instructions can mysteriously be half-word aligned
        // despite having instruction sizes of 4-, 6-, and 8-bytes.
        Arch::SysZ | Arch::Riscv32 | Arch::Riscv64 => 2,
        // x86/x86_64 aren't aligned
        Arch::X86 | Arch::X86_64 => 1,
    };

    // iterate over the valid start addresses and return a vec containing them
    (region_start_addr..(region_start_addr + region_len + 1))
        .step_by(instr_alignment)
        .collect()
}

/// Returns true if any of the operands for this instruction are registers.
fn has_register_operand(insn: &capstone::Insn, detail: &capstone::InsnDetail, arch: Arch) -> bool {
    match arch {
        Arch::Arm64 => detail.arch_detail().arm64().unwrap().operands().any(|op| {
            std::mem::discriminant(&op.op_type)
                == std::mem::discriminant(&capstone::arch::arm64::Arm64OperandType::Reg(
                    capstone::RegId(0),
                ))
        }),
        Arch::Arm => detail.arch_detail().arm().unwrap().operands().any(|op| {
            std::mem::discriminant(&op.op_type)
                == std::mem::discriminant(&capstone::arch::arm::ArmOperandType::Reg(
                    capstone::RegId(0),
                ))
        }),
        Arch::Mips64 | Arch::Mips => detail.arch_detail().mips().unwrap().operands().any(|op| {
            std::mem::discriminant(&op)
                == std::mem::discriminant(&capstone::arch::mips::MipsOperand::Reg(capstone::RegId(
                    0,
                )))
        }),
        Arch::Riscv64 | Arch::Riscv32 => {
            detail.arch_detail().riscv().unwrap().operands().any(|op| {
                std::mem::discriminant(&op)
                    == std::mem::discriminant(&capstone::arch::riscv::RiscVOperand::Reg(
                        capstone::RegId(0),
                    ))
            })
        }
        Arch::PowerPc64 | Arch::PowerPc => {
            detail.arch_detail().ppc().unwrap().operands().any(|op| {
                std::mem::discriminant(&op)
                    == std::mem::discriminant(&capstone::arch::ppc::PpcOperand::Reg(
                        capstone::RegId(0),
                    ))
            })
        }
        Arch::X86_64 | Arch::X86 => detail.arch_detail().x86().unwrap().operands().any(|op| {
            std::mem::discriminant(&op.op_type)
                == std::mem::discriminant(&capstone::arch::x86::X86OperandType::Reg(
                    capstone::RegId(0),
                ))
        }),
        Arch::Sparc64 => detail.arch_detail().sparc().unwrap().operands().any(|op| {
            std::mem::discriminant(&op)
                == std::mem::discriminant(&capstone::arch::sparc::SparcOperand::Reg(
                    capstone::RegId(0),
                ))
        }),
        Arch::SysZ => {
            // for some unknown reason, this api isn't provided for sysz, so we
            // have to implement it manually using the capstone_sys crate
            // TODO(garnt): use the capstone crate for this if sysz is ever
            // fixed

            // call capstone_sys::cs_open() to get a capstone instance
            let mut sys_cs_handle: Box<capstone_sys::csh> = Box::new(0);
            let sys_arch: capstone_sys::cs_arch = capstone::Arch::SYSZ.into();
            let sys_mode: capstone_sys::cs_mode =
                Into::<capstone::Mode>::into(capstone::arch::sysz::ArchMode::Default).into();
            let open_err =
                unsafe { capstone_sys::cs_open(sys_arch, sys_mode, sys_cs_handle.as_mut()) };
            assert_eq!(open_err, capstone_sys::cs_err::CS_ERR_OK);

            // use capstone_sys to manually disassemble this one instruction
            let mut sys_insns: *mut capstone_sys::cs_insn = core::ptr::null_mut();
            let disasm_count = unsafe {
                capstone_sys::cs_disasm(
                    *sys_cs_handle.as_ref(),
                    insn.bytes().as_ptr(),
                    insn.bytes().len(),
                    0,
                    1,
                    &mut sys_insns,
                )
            };
            assert_eq!(disasm_count, 1);

            // actually iterate through the operands
            let reg_op_count = unsafe {
                cs_op_count(
                    *sys_cs_handle.as_ref(),
                    sys_insns,
                    capstone_sys::sysz_op_type::SYSZ_OP_REG as u32,
                )
            };

            // manually destruct the capstone object to prevent leaking it
            let close_err = unsafe { cs_close(sys_cs_handle.as_mut()) };
            assert_eq!(close_err, capstone_sys::cs_err::CS_ERR_OK);

            // manually free the disassembled instruction buffer
            unsafe {
                capstone_sys::cs_free(
                    std::mem::replace(&mut sys_insns, std::ptr::null_mut()),
                    disasm_count,
                );
            };

            // true if any operands were registers
            reg_op_count > 0
        }
    }
}

/// GadgetSearchInsnInfo contains information about whether the current
/// instruction would terminate a gadget search, and if the resulting gadget
/// remains valid.
#[derive(Clone, Copy, Debug)]
pub struct GadgetSearchInsnInfo {
    /// True if this instruction should terminate the search.
    pub is_terminating: bool,
    /// True if the gadget is a valid gadget if this instruction is added to it.
    pub is_valid_gadget: bool,
}

/// Performs the [`is_terminating_insn()`] evaluation for the passed 32-bit ARM
/// instruction, returning a [`GadgetSearchInsnInfo`] representing its findings.
fn is_terminating_insn_arm(
    insn: &capstone::Insn,
    detail: &capstone::InsnDetail,
    constraints: &GadgetConstraints,
) -> GadgetSearchInsnInfo {
    // relative branches are always direct jumps and therefore not allowed
    if detail.groups().contains(&REL_BR_GRP_ID) {
        return GadgetSearchInsnInfo {
            is_terminating: true,
            is_valid_gadget: false,
        };
    }

    // check to see if this instruction is a ret. ARM function returns seem to
    // come in the following flavors:
    // pop {pc[, ...]} (technically STMDB SP!,{pc[, ...]} but capstone is nice)
    // b{l}x lr
    if constraints.allow_terminating_ret {
        match insn.id() {
            ARM_BX_ID | ARM_BLX_ID => {
                // if we read from the register lr, it's a ret
                if detail
                    .arch_detail()
                    .arm()
                    .unwrap()
                    .operands()
                    .any(|op| op.op_type == ARM_LR_OPTYPE)
                {
                    return GadgetSearchInsnInfo {
                        is_terminating: true,
                        is_valid_gadget: true,
                    };
                }
            }
            ARM_POP_ID => {
                // if we write to the register PC, it's a ret
                if detail
                    .arch_detail()
                    .arm()
                    .unwrap()
                    .operands()
                    .any(|op| op.op_type == ARM_PC_OPTYPE)
                {
                    return GadgetSearchInsnInfo {
                        is_terminating: true,
                        is_valid_gadget: true,
                    };
                }
            }
            _ => {}
        }
    }

    // check if this instruction is a call
    if detail.groups().contains(&CALL_GRP_ID) {
        // if a register wasn't read, it's a direct call, which can't exist
        // in the middle of a gadget
        if has_register_operand(insn, detail, Arch::Arm) {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: false,
            };
        // if a register was read, and terminating calls are allowed,
        // terminate the gadget
        } else if constraints.allow_terminating_call {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: true,
            };
        }
    }

    // check if this instruction is a jump
    if detail.groups().contains(&JMP_GRP_ID) {
        // if a register wasn't read, we need to check if this instruction
        // is a direct jump, which can't exist in the middle of a gadget
        if has_register_operand(insn, detail, Arch::Arm) {
            // if a register wasn't read and there's no immediate, which
            // would be stored in the op_str, it's a direct jump
            if insn.op_str().is_none() {
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: false,
                };
            }
        // if a register was read, and terminating jumps are allowed,
        // terminate the gadget
        } else if constraints.allow_terminating_jmp {
            // if the gadget length is valid, the gadget is valid
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: true,
            };
        }
    }

    // for any non-terminating instructions, signal to continue the search
    GadgetSearchInsnInfo {
        is_terminating: false,
        is_valid_gadget: true,
    }
}

/// Performs the [`is_terminating_insn()`] evaluation for the passed (32 or
/// 64-bit) PowerPC instruction, returning a [`GadgetSearchInsnInfo`]
/// representing its findings.
fn is_terminating_insn_ppc(
    insn: &capstone::Insn,
    detail: &capstone::InsnDetail,
    constraints: &GadgetConstraints,
) -> GadgetSearchInsnInfo {
    // relative branches are always direct jumps and therefore not allowed
    if detail.groups().contains(&REL_BR_GRP_ID) {
        return GadgetSearchInsnInfo {
            is_terminating: true,
            is_valid_gadget: false,
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
        if has_register_operand(insn, detail, Arch::PowerPc) {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: false,
            };
        // if a register was read, and terminating calls are allowed,
        // terminate the gadget
        } else if constraints.allow_terminating_call {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: true,
            };
        }
    }

    // check if this instruction is a jump
    if detail.groups().contains(&JMP_GRP_ID) {
        // if a register wasn't read, we need to check if this instruction
        // is a direct jump, which can't exist in the middle of a gadget
        if has_register_operand(insn, detail, Arch::PowerPc) {
            // if a register wasn't read and there's no immediate, which
            // would be stored in the op_str, it's a direct jump
            if insn.op_str().is_none() {
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: false,
                };
            }
        // if a register was read, and terminating jumps are allowed,
        // terminate the gadget
        } else if constraints.allow_terminating_jmp {
            // if the gadget length is valid, the gadget is valid
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: true,
            };
        }
    }

    // for any non-terminating instructions, signal to continue the search
    GadgetSearchInsnInfo {
        is_terminating: false,
        is_valid_gadget: true,
    }
}

/// Performs the [`is_terminating_insn()`] evaluation for the passed (32 or
/// 64-bit) RISC-V instruction, returning a [`GadgetSearchInsnInfo`]
/// representing its findings.
fn is_terminating_insn_riscv(
    insn: &capstone::Insn,
    detail: &capstone::InsnDetail,
    constraints: &GadgetConstraints,
) -> GadgetSearchInsnInfo {
    // relative branches are always direct jumps and therefore not allowed
    if detail.groups().contains(&REL_BR_GRP_ID) {
        return GadgetSearchInsnInfo {
            is_terminating: true,
            is_valid_gadget: false,
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
        if has_register_operand(insn, detail, Arch::Riscv32) {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: false,
            };
        // if a register was read, and terminating calls are allowed,
        // terminate the gadget
        } else if constraints.allow_terminating_call {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: true,
            };
        }
    }

    // check if this instruction is a jump
    if detail.groups().contains(&JMP_GRP_ID) {
        // if a register wasn't read, we need to check if this instruction
        // is a direct jump, which can't exist in the middle of a gadget
        if has_register_operand(insn, detail, Arch::Riscv32) {
            // if a register wasn't read and there's no immediate, which
            // would be stored in the op_str, it's a direct jump
            if insn.op_str().is_none() {
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: false,
                };
            }
        // if a register was read, and terminating jumps are allowed,
        // terminate the gadget
        } else if constraints.allow_terminating_jmp {
            // if the gadget length is valid, the gadget is valid
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: true,
            };
        }
    }

    // for any non-terminating instructions, signal to continue the search
    GadgetSearchInsnInfo {
        is_terminating: false,
        is_valid_gadget: true,
    }
}

/// Performs the [`is_terminating_insn()`] evaluation for the passed SystemZ
/// instruction, returning a [`GadgetSearchInsnInfo`] representing its findings.
fn is_terminating_insn_sysz(
    insn: &capstone::Insn,
    detail: &capstone::InsnDetail,
    constraints: &GadgetConstraints,
) -> GadgetSearchInsnInfo {
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
        SYSZ_BAL_ID | SYSZ_BAS_ID => {
            return GadgetSearchInsnInfo {
                is_terminating: true,
                is_valid_gadget: false,
            };
        }
        // function calls
        SYSZ_BRASL_ID | SYSZ_BRAS_ID => {
            // if a register wasn't read, it's a direct call, which can't exist
            // in the middle of a gadget
            if !has_register_operand(insn, detail, Arch::SysZ) {
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: false,
                };
            // if a register was read, and terminating calls are allowed,
            // terminate the gadget
            } else if constraints.allow_terminating_call {
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: true,
                };
            }
        }
        _ => {}
    }

    // for any non-terminating instructions, signal to continue the search
    GadgetSearchInsnInfo {
        is_terminating: false,
        is_valid_gadget: true,
    }
}

/// Evaluates whether a given instruction would terminate a gadget search, and
/// additionally if the gadget being searched for would remain a valid gadget
/// after appending the instruction.
pub fn is_terminating_insn(
    insn: &capstone::Insn,
    detail: &capstone::InsnDetail,
    arch: Arch,
    constraints: GadgetConstraints,
) -> GadgetSearchInsnInfo {
    // some architectures' capstone disassemblers don't tag gadget-terminating
    // instructions with the architecture-generic capstone instruction groups
    // in quite the way we're expecting, especially if those architectures
    // don't have dedicated ret instructions, so we implement this function
    // differently for those architectures.
    match arch {
        // ARM, PPC, RISCV, and S390x don't play nicely.
        Arch::Arm => is_terminating_insn_arm(insn, detail, &constraints),
        Arch::PowerPc | Arch::PowerPc64 => is_terminating_insn_ppc(insn, detail, &constraints),
        Arch::Riscv32 | Arch::Riscv64 => is_terminating_insn_riscv(insn, detail, &constraints),
        Arch::SysZ => is_terminating_insn_sysz(insn, detail, &constraints),
        // This is the default case for architectures that play nicely.
        _ => {
            // relative branches are always direct jumps and therefore not allowed
            if detail.groups().contains(&REL_BR_GRP_ID) {
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: false,
                };
            }

            // if terminating rets are allowed, check if this instruction is a ret
            // and terminates the gadget
            if constraints.allow_terminating_ret && detail.groups().contains(&RET_GRP_ID) {
                // if the gadget length is valid, the gadget is valid
                return GadgetSearchInsnInfo {
                    is_terminating: true,
                    is_valid_gadget: true,
                };
            }

            // check if this instruction is a call
            if detail.groups().contains(&CALL_GRP_ID) {
                // if a register wasn't read, it's a direct call, which can't exist
                // in the middle of a gadget
                if has_register_operand(insn, detail, arch) {
                    return GadgetSearchInsnInfo {
                        is_terminating: true,
                        is_valid_gadget: false,
                    };
                // if a register was read, and terminating calls are allowed,
                // terminate the gadget
                } else if constraints.allow_terminating_call {
                    return GadgetSearchInsnInfo {
                        is_terminating: true,
                        is_valid_gadget: true,
                    };
                }
            }

            // check if this instruction is a jump
            if detail.groups().contains(&JMP_GRP_ID) {
                // if a register wasn't read, we need to check if this instruction
                // is a direct jump, which can't exist in the middle of a gadget
                if has_register_operand(insn, detail, arch) {
                    // if a register wasn't read and there's no immediate, which
                    // would be stored in the op_str, it's a direct jump
                    if insn.op_str().is_none() {
                        return GadgetSearchInsnInfo {
                            is_terminating: true,
                            is_valid_gadget: false,
                        };
                    }
                // if a register was read, and terminating jumps are allowed,
                // terminate the gadget
                } else if constraints.allow_terminating_jmp {
                    // if the gadget length is valid, the gadget is valid
                    return GadgetSearchInsnInfo {
                        is_terminating: true,
                        is_valid_gadget: true,
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
