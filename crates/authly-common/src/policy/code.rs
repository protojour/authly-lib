//! Code definitions for the Authly policy engine.

use int_enum::IntEnum;
use serde::{Deserialize, Serialize};

/// The value/outcome of a policy engine evaluation.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash, Debug)]
pub enum PolicyValue {
    /// Represents denied access.
    Deny,
    /// Represents allowed access.
    Allow,
}

impl PolicyValue {
    /// Whether self is [Self::Deny],
    pub fn is_deny(self) -> bool {
        matches!(self, Self::Deny)
    }

    /// Whether self is [Self::Allow],
    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }
}

impl From<bool> for PolicyValue {
    fn from(value: bool) -> Self {
        match value {
            false => Self::Deny,
            true => Self::Allow,
        }
    }
}

/// typed opcode representation for policy engine instructions.
#[derive(PartialEq, Eq, Debug)]
#[allow(missing_docs)]
pub enum OpCode {
    LoadSubjectId(u128),
    LoadSubjectAttrs,
    LoadResourceId(u128),
    LoadResourceAttrs,
    LoadConstId(u128),
    IsEq,
    SupersetOf,
    IdSetContains,
    And,
    Or,
    Not,
    Return,
}

/// bytecode representation for policy engine instructions.
#[repr(u8)]
#[derive(IntEnum, Debug)]
#[allow(missing_docs)]
pub enum Bytecode {
    LoadSubjectId = 0,
    LoadSubjectAttrs = 1,
    LoadResourceId = 2,
    LoadResourceAttrs = 3,
    LoadConstId = 4,
    IsEq = 5,
    SupersetOf = 6,
    IdSetContains = 7,
    And = 8,
    Or = 9,
    Not = 10,
    Return = 11,
}

/// Convert slice of opcodes to bytecode.
pub fn to_bytecode(opcodes: &[OpCode]) -> Vec<u8> {
    let mut out = Vec::with_capacity(opcodes.len());

    for opcode in opcodes {
        match opcode {
            OpCode::LoadSubjectId(eid) => {
                out.push(Bytecode::LoadSubjectId as u8);
                out.extend(unsigned_varint::encode::u128(*eid, &mut Default::default()));
            }
            OpCode::LoadSubjectAttrs => {
                out.push(Bytecode::LoadSubjectAttrs as u8);
            }
            OpCode::LoadResourceId(eid) => {
                out.push(Bytecode::LoadResourceId as u8);
                out.extend(unsigned_varint::encode::u128(*eid, &mut Default::default()));
            }
            OpCode::LoadResourceAttrs => {
                out.push(Bytecode::LoadResourceAttrs as u8);
            }
            OpCode::LoadConstId(id) => {
                out.push(Bytecode::LoadConstId as u8);
                out.extend(unsigned_varint::encode::u128(*id, &mut Default::default()));
            }
            OpCode::IsEq => {
                out.push(Bytecode::IsEq as u8);
            }
            OpCode::SupersetOf => {
                out.push(Bytecode::SupersetOf as u8);
            }
            OpCode::IdSetContains => {
                out.push(Bytecode::IdSetContains as u8);
            }
            OpCode::And => {
                out.push(Bytecode::And as u8);
            }
            OpCode::Or => {
                out.push(Bytecode::Or as u8);
            }
            OpCode::Not => {
                out.push(Bytecode::Not as u8);
            }
            OpCode::Return => {
                out.push(Bytecode::Return as u8);
            }
        }
    }

    out
}
