use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    Branch,
    MemoryAddress,
    JumpTarget,
    ControlTransfer,
    Libcall,
    Check,
    Syscall,
    Incomplete,
    IncompleteOrAddress,
    Unclassified,
}

impl Class {
    pub const ALL: [Class; 10] = [
        Class::Branch,
        Class::MemoryAddress,
        Class::JumpTarget,
        Class::ControlTransfer,
        Class::Libcall,
        Class::Check,
        Class::Syscall,
        Class::Incomplete,
        Class::IncompleteOrAddress,
        Class::Unclassified,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Class::Branch => "branch",
            Class::MemoryAddress => "memory-address",
            Class::JumpTarget => "jump-target",
            Class::ControlTransfer => "control-transfer",
            Class::Libcall => "libcall",
            Class::Check => "check",
            Class::Syscall => "syscall",
            Class::Incomplete => "incomplete",
            Class::IncompleteOrAddress => "incomplete-or-address",
            Class::Unclassified => "unclassified",
        }
    }

    /// A longer explanation, for the classes whose name doesn't say it all.
    pub fn explanation(self) -> Option<&'static str> {
        match self {
            Class::ControlTransfer => Some("Either the address of the jump or the loaded target was secret."),
            Class::Libcall => Some("A runtime function called from here depended on the secret."),
            Class::Check => Some("A secret reached something that must stay public."),
            Class::Syscall => Some("A secret was passed to a system call."),
            Class::Incomplete => Some("A SIMD shift used a secret count. That's constant-time, but Valgrind loses track of the secret here, so anything after it is unchecked."),
            Class::IncompleteOrAddress => Some("A SIMD shift loaded its count from memory, and either the address or the count was secret. A secret address would be a leak, and a secret count means anything after it is unchecked."),
            Class::Unclassified => Some("Valgrind reported something unexpected."),
            _ => None,
        }
    }

    /// Whether this class means the rest of the run couldn't be checked.
    pub fn is_incomplete(self) -> bool {
        matches!(self, Class::Incomplete | Class::IncompleteOrAddress)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Finding(Class),
    /// A wasm bounds check hit a guard page.
    /// Not a leak if a trap followed.
    GuardPage,
}

/// The rules apply in order and the first match wins, because the categories overlap: a `div` can have a memory operand, and so can an indirect jump.
pub fn classify(kind: &str, _what: &str, in_host: bool, instruction: Option<&Instruction>) -> Disposition {
    use Disposition::*;
    match kind {
        "ClientCheck" => return Finding(Class::Check),
        "SyscallParam" => return Finding(Class::Syscall),
        "InvalidRead" | "InvalidWrite" => return GuardPage,
        "UninitCondition" | "UninitValue" if in_host => return Finding(Class::Libcall),
        _ => {}
    }
    let Some(instruction) = instruction else {
        return Finding(Class::Unclassified);
    };
    let has_memory_operand = (0..instruction.op_count()).any(|i| instruction.op_kind(i) == OpKind::Memory);
    let indirect = matches!(instruction.flow_control(), FlowControl::IndirectBranch | FlowControl::IndirectCall);
    match kind {
        "UninitCondition" => {
            let repeats = instruction.has_rep_prefix() || instruction.has_repe_prefix() || instruction.has_repne_prefix();
            if instruction.flow_control() == FlowControl::ConditionalBranch || repeats {
                Finding(Class::Branch)
            } else {
                Finding(Class::Unclassified)
            }
        }
        "UninitValue" if indirect && has_memory_operand => Finding(Class::ControlTransfer),
        "UninitValue" if indirect => Finding(Class::JumpTarget),
        "UninitValue" if is_simd_shift_by_scalar(instruction) => {
            Finding(if has_memory_operand { Class::IncompleteOrAddress } else { Class::Incomplete })
        }
        "UninitValue" if has_memory_operand => Finding(Class::MemoryAddress),
        _ => Finding(Class::Unclassified),
    }
}

fn is_simd_shift_by_scalar(instruction: &Instruction) -> bool {
    use Mnemonic::*;
    let shift = matches!(
        instruction.mnemonic(),
        Psllw | Pslld | Psllq | Psrlw | Psrld | Psrlq | Psraw | Psrad | Vpsllw | Vpslld | Vpsllq | Vpsrlw | Vpsrld | Vpsrlq | Vpsraw | Vpsrad
    );
    shift && !matches!(
        instruction.op_kind(instruction.op_count() - 1),
        OpKind::Immediate8 | OpKind::Immediate8_2nd
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bytes: &[u8]) -> Instruction {
        let instruction = Decoder::new(64, bytes, DecoderOptions::NONE).decode();
        assert!(!instruction.is_invalid(), "{bytes:02x?}");
        instruction
    }

    #[test]
    fn rules_apply_in_order() {
        let je = decode(&[0x74, 0x05]);
        let rep_movsb = decode(&[0xf3, 0xa4]);
        let jmp_reg = decode(&[0xff, 0xe0]);
        let call_reg = decode(&[0xff, 0xd0]);
        let jmp_mem = decode(&[0xff, 0x24, 0xc5, 0, 0, 0, 0]);
        let call_mem = decode(&[0xff, 0x14, 0xc5, 0, 0, 0, 0]);
        let load = decode(&[0x8b, 0x04, 0x07]);
        let div_mem = decode(&[0xf7, 0x30]);
        let pslld_reg = decode(&[0x66, 0x0f, 0xf2, 0xc1]);
        let pslld_mem = decode(&[0x66, 0x0f, 0xf2, 0x00]);
        let vpslld_reg = decode(&[0xc5, 0xf1, 0xf2, 0xc2]);
        let pslld_imm = decode(&[0x66, 0x0f, 0x72, 0xf0, 0x03]);
        let add = decode(&[0x01, 0xc8]);

        use Class::*;
        use Disposition::*;
        for (kind, what, in_host, instruction, expected) in [
            ("ClientCheck", "", true, None, Finding(Check)),
            ("SyscallParam", "", true, None, Finding(Syscall)),
            ("InvalidRead", "", false, Some(&load), GuardPage),
            ("InvalidWrite", "", false, Some(&load), GuardPage),
            ("UninitCondition", "", true, None, Finding(Libcall)),
            ("UninitValue", "", true, Some(&load), Finding(Libcall)),
            ("UninitCondition", "", false, Some(&je), Finding(Branch)),
            ("UninitCondition", "", false, Some(&rep_movsb), Finding(Branch)),
            ("UninitValue", "", false, Some(&jmp_reg), Finding(JumpTarget)),
            ("UninitValue", "", false, Some(&call_reg), Finding(JumpTarget)),
            ("UninitValue", "", false, Some(&jmp_mem), Finding(ControlTransfer)),
            ("UninitValue", "", false, Some(&call_mem), Finding(ControlTransfer)),
            ("UninitValue", "", false, Some(&pslld_reg), Finding(Incomplete)),
            ("UninitValue", "", false, Some(&vpslld_reg), Finding(Incomplete)),
            ("UninitValue", "", false, Some(&pslld_mem), Finding(IncompleteOrAddress)),
            ("UninitValue", "", false, Some(&load), Finding(MemoryAddress)),
            ("UninitValue", "", false, Some(&div_mem), Finding(MemoryAddress)),
            ("UninitValue", "", false, Some(&add), Finding(Unclassified)),
            ("UninitValue", "", false, Some(&pslld_imm), Finding(Unclassified)),
            ("UninitCondition", "", false, Some(&add), Finding(Unclassified)),
            ("UninitValue", "", false, None, Finding(Unclassified)),
            ("Overlap", "", false, Some(&load), Finding(Unclassified)),
        ] {
            assert_eq!(classify(kind, what, in_host, instruction), expected, "{kind} {what}");
        }
    }
}
