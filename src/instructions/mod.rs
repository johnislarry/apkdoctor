use std::{
    fmt::{self, Display, Formatter},
    io,
};

mod op_to_str;

use crate::encode::{self, encode_u8};
use crate::{
    decode::{decode_i8, decode_u16, decode_u8},
    encode::encode_u16,
};

pub trait TInstruction {
    /// Decodes an instruction from the stream `r`.  The opcode for this
    /// instruction is passed as `op`, and the implementation is responsible for
    /// consuming the remainder of the instruction.
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead;

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write;

    fn display(&self) -> String;
}

macro_rules! impl_traits_for_instruction_struct_types {
    () => {};
    ($opvariant:ident) => {
        impl From<$opvariant> for Instruction {
            fn from(op: $opvariant) -> Self {
                Self::$opvariant(op)
            }
        }

        impl Display for $opvariant {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "{}", self.display())
            }
        }
    };
    ($opvariant:ident , $($rest:tt)*) => {
        impl_traits_for_instruction_struct_types!($opvariant);
        impl_traits_for_instruction_struct_types!($($rest)*);
    };
}

impl_traits_for_instruction_struct_types!(Ins10x, Ins12x, Ins11n, Ins10t, Ins20t);

enum Instruction {
    Ins10x(Ins10x),
    Ins12x(Ins12x),
    Ins11n(Ins11n),
    Ins11x(Ins11x),
    Ins10t(Ins10t),
    Ins20t(Ins20t),
}

impl Display for Instruction {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        macro_rules! impl_display_for_opcode_inner {
            () => {};
            ($opvariant:ident) => {
                {
                    if let Instruction::$opvariant(op) = self {
                        return write!(f, "{}", op.to_string());
                    }
                }
            };
            ($opvariant:ident , $($rest:tt)*) => {
                impl_display_for_opcode_inner!($opvariant);
                impl_display_for_opcode_inner!($($rest)*);
            };
        }
        impl_display_for_opcode_inner!(Ins10x, Ins12x, Ins11n, Ins10t, Ins20t);
        unreachable!("Error in Display trait for Opcode");
    }
}

struct Ins10x {
    op: u8,
}

impl TInstruction for Ins10x {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let rest = decode_u8(r);
        assert!(rest == 0x00);
        return Self { op };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, 0x00);
    }

    fn display(&self) -> String {
        op_to_str::op_to_str(self.op).to_string()
    }
}

struct Ins12x {
    op: u8,
    a: u8,
    b: u8,
}

impl TInstruction for Ins12x {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let regs = decode_u8(r);
        let a = regs & 0x0f;
        let b = regs >> 4;
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.b << 4 | self.a);
    }

    fn display(&self) -> String {
        format!("{} v{}, v{}", op_to_str::op_to_str(self.op), self.a, self.b)
    }
}

struct Ins11n {
    op: u8,
    a: u8,
    b: i8,
}

impl TInstruction for Ins11n {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let data = decode_u8(r);
        let a = data & 0x0f;
        let b = data as i8 >> 4;
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, ((self.b as u8) << 4) | self.a);
    }

    fn display(&self) -> String {
        format!("{} v{}, {}", op_to_str::op_to_str(self.op), self.a, self.b)
    }
}

struct Ins11x {
    op: u8,
    a: u8,
}

impl TInstruction for Ins11x {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        Self { op, a }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
    }

    fn display(&self) -> String {
        format!("{} v{}", op_to_str::op_to_str(self.op), self.a)
    }
}
struct Ins10t {
    op: u8,
    a: i8,
}

impl TInstruction for Ins10t {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_i8(r);
        Self { op, a }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a as u8);
    }

    fn display(&self) -> String {
        format!("{} {}", op_to_str::op_to_str(self.op), self.a)
    }
}

struct Ins20t {
    op: u8,
    a: i16,
}

impl TInstruction for Ins20t {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let rest = decode_u8(r);
        assert!(rest == 0x00);
        let a = decode_u16(r) as i16;
        Self { op, a }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, 0x00);
        encode_u16(w, self.a as u16);
    }

    fn display(&self) -> String {
        format!("{} {}", op_to_str::op_to_str(self.op), self.a)
    }
}

struct Ins20bc {
    op: u8,
    a: i8,
    b: u16,
}

impl TInstruction for Ins20bc {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_i8(r);
        let b = decode_u16(r);
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a as u8);
        encode_u16(w, self.b);
    }

    fn display(&self) -> String {
        format!(
            "{} {}, kind@{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.b
        )
    }
}

fn decode_insn<R>(r: &mut R) -> Instruction
where
    R: io::BufRead,
{
    match decode_u8(r) {
        op @ 0x00 => {
            let b = decode_u8(r);
            match b {
                op @ 0x00 => {
                    return Ins10x { op }.into();
                }
                0x01 => {
                    // packed switch
                    todo!();
                }
                0x02 => {
                    // etc
                    todo!();
                }
                0x03 => {
                    // etc
                    todo!();
                }
                _ => panic!("bad nop high bits"),
            }
        }
        op @ 0x01 => Ins12x::deserialize(r, op).into(),
    }
}

pub fn decode_insns<R>(r: &mut R, insns_size: usize) -> Vec<Instruction>
where
    R: io::BufRead,
{
    let mut insns = vec![];
    for _ in 0..insns_size {
        insns.push(decode_insn(r));
    }
    return insns;
}
