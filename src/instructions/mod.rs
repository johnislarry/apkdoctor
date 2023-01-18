use std::{
    fmt::{self, Display, Formatter},
    io,
};

mod op_to_str;

use crate::{
    decode::{decode_i8, decode_u16, decode_u8},
    encode::{encode_u16, encode_u64},
};
use crate::{
    decode::{decode_u32, decode_u64},
    encode::{encode_u32, encode_u8},
};

macro_rules! call_macro_with_structs {
    ($macroname:ident) => {
        $macroname! {
            Ins10x,
            Ins12x,
            Ins11n,
            Ins11x,
            Ins10t,
            Ins20t,
            Ins20bc,
            Ins22x,
            Ins21t,
            Ins21s,
            Ins21h,
            Ins21c,
            Ins23x,
            Ins22b,
            Ins22t,
            Ins22s,
            Ins22c,
            Ins22cs,
            Ins30t,
            Ins32x,
            Ins31i,
            Ins31t,
            Ins31c,
            Ins35c,
            Ins35ms,
            Ins35mi,
            Ins3rc,
            Ins3rms,
            Ins3rmi,
            Ins45cc,
            Ins4rcc,
            Ins51l,
            PackedSwitchPayload,
            SparseSwitchPayload,
            FillArrayDataPayload,
        }
    };
}

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

    /// Human readable mnuemonic for this instruction.
    fn display(&self) -> String;

    /// Size of instruction in bytes.
    fn size(&self) -> usize;
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

call_macro_with_structs!(impl_traits_for_instruction_struct_types);

macro_rules! build_instruction_enum {
    (@as_item $i:item) => { $i };
    ($($i:ident),* $(,)*) => {
        build_instruction_enum! {
            @as_item
            #[derive(Debug, PartialEq, Eq)]
            pub enum Instruction {
                $($i($i),)*
            }
        }
    };
}

call_macro_with_structs!(build_instruction_enum);

impl Display for Instruction {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        macro_rules! impl_display_for_opcode_inner {
            (@as_expr $e:expr) => {
                $e
            };
            ($($i:ident),* $(,)*) => {
                impl_display_for_opcode_inner! {
                    @as_expr
                    match self {
                        $(Instruction::$i(op) => write!(f, "{}", op.to_string()),)*
                    }
                }
            };
        }
        return call_macro_with_structs!(impl_display_for_opcode_inner);
    }
}

impl Instruction {
    pub(crate) fn size(&self) -> usize {
        macro_rules! impl_instruction_inner {
            (@as_expr $e:expr) => { $e };
            ($($i:ident),* $(,)*) => {
                impl_instruction_inner! {
                    @as_expr
                    match self {
                        $(Instruction::$i(op) => op.size(),)*
                    }
                }
            };
        }
        return call_macro_with_structs!(impl_instruction_inner);
    }

    pub(crate) fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        macro_rules! impl_serialize {
            (@as_expr $e:expr) => { $e };
            ($($i:ident),* $(,)*) => {
                impl_serialize! {
                    @as_expr
                    match self {
                        $(Instruction::$i(op) => op.serialize(w),)*
                    }
                }
            };
        }
        call_macro_with_structs!(impl_serialize);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins10x {
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

    fn size(&self) -> usize {
        2
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins12x {
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

    fn size(&self) -> usize {
        2
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins11n {
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
        format!("{} v{}, #{}", op_to_str::op_to_str(self.op), self.a, self.b)
    }

    fn size(&self) -> usize {
        2
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins11x {
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

    fn size(&self) -> usize {
        2
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Ins10t {
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

    fn size(&self) -> usize {
        2
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins20t {
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

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins20bc {
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

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins22x {
    op: u8,
    a: u8,
    b: u16,
}

impl TInstruction for Ins22x {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u16(r);
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u16(w, self.b);
    }

    fn display(&self) -> String {
        format!("{} v{}, v{}", op_to_str::op_to_str(self.op), self.a, self.b)
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins21t {
    op: u8,
    a: u8,
    b: i16,
}

impl TInstruction for Ins21t {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u16(r) as i16;
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u16(w, self.b as u16);
    }

    fn display(&self) -> String {
        format!("{} v{}, {}", op_to_str::op_to_str(self.op), self.a, self.b)
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins21s {
    op: u8,
    a: u8,
    b: i16,
}

impl TInstruction for Ins21s {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u16(r) as i16;
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u16(w, self.b as u16);
    }

    fn display(&self) -> String {
        format!("{} v{}, {}", op_to_str::op_to_str(self.op), self.a, self.b)
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins21h {
    op: u8,
    a: u8,
    b: i16,
}

impl TInstruction for Ins21h {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u16(r) as i16;
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u16(w, self.b as u16);
    }

    fn display(&self) -> String {
        format!("{} v{}, #{}", op_to_str::op_to_str(self.op), self.a, self.b)
    }

    fn size(&self) -> usize {
        4
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Ins21c {
    op: u8,
    a: u8,
    b: u16,
}

impl TInstruction for Ins21c {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u16(r);
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u16(w, self.b);
    }

    fn display(&self) -> String {
        format!(
            "{} v{}, kind@{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.b
        )
    }

    fn size(&self) -> usize {
        4
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Ins23x {
    op: u8,
    a: u8,
    b: u8,
    c: u8,
}

impl TInstruction for Ins23x {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u8(r);
        let c = decode_u8(r);
        Self { op, a, b, c }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u8(w, self.b);
        encode_u8(w, self.c);
    }

    fn display(&self) -> String {
        format!(
            "{} v{}, v{}, v{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.b,
            self.c
        )
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins22b {
    op: u8,
    a: u8,
    b: u8,
    c: u8,
}

impl TInstruction for Ins22b {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u8(r);
        let c = decode_u8(r);
        Self { op, a, b, c }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u8(w, self.b);
        encode_u8(w, self.c);
    }

    fn display(&self) -> String {
        format!(
            "{} v{}, v{}, #{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.b,
            self.c
        )
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins22t {
    op: u8,
    a: u8,
    b: u8,
    c: i16,
}

impl TInstruction for Ins22t {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let ba = decode_u8(r);
        let c = decode_u16(r) as i16;
        Self {
            op,
            a: ba & 0xf,
            b: ba >> 4,
            c,
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.b << 4 | self.a);
        encode_u16(w, self.c as u16);
    }

    fn display(&self) -> String {
        format!(
            "{} v{}, v{}, {}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.b,
            self.c
        )
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins22s {
    op: u8,
    a: u8,
    b: u8,
    c: i16,
}

impl TInstruction for Ins22s {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let ba = decode_u8(r);
        let c = decode_u16(r) as i16;
        Self {
            op,
            a: ba & 0xf,
            b: ba >> 4,
            c,
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.b << 4 | self.a);
        encode_u16(w, self.c as u16);
    }

    fn display(&self) -> String {
        format!(
            "{} v{}, v{}, #{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.b,
            self.c
        )
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins22c {
    op: u8,
    a: u8,
    b: u8,
    c: u16,
}

impl TInstruction for Ins22c {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let ba = decode_u8(r);
        let c = decode_u16(r);
        Self {
            op,
            a: ba & 0xf,
            b: ba >> 4,
            c,
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.b << 4 | self.a);
        encode_u16(w, self.c);
    }

    fn display(&self) -> String {
        format!(
            "{} v{}, v{}, kind@{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.b,
            self.c
        )
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins22cs {
    op: u8,
    a: u8,
    b: u8,
    c: u16,
}

impl TInstruction for Ins22cs {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let ba = decode_u8(r);
        let c = decode_u16(r);
        Self {
            op,
            a: ba & 0xf,
            b: ba >> 4,
            c,
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.b << 4 | self.a);
        encode_u16(w, self.c);
    }

    fn display(&self) -> String {
        format!(
            "{} v{}, v{}, fieldoff@{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.b,
            self.c
        )
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins30t {
    op: u8,
    a: i32,
}

impl TInstruction for Ins30t {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let null = decode_u8(r);
        assert!(null == 0);

        let a = decode_u32(r) as i32;
        Self { op, a }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, 0);
        encode_u32(w, self.a as u32);
    }

    fn display(&self) -> String {
        format!("{} {}", op_to_str::op_to_str(self.op), self.a,)
    }

    fn size(&self) -> usize {
        6
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins32x {
    op: u8,
    a: u16,
    b: u16,
}

impl TInstruction for Ins32x {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let null = decode_u8(r);
        assert!(null == 0);

        let a = decode_u16(r);
        let b = decode_u16(r);
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, 0);
        encode_u16(w, self.a);
        encode_u16(w, self.b);
    }

    fn display(&self) -> String {
        format!("{} v{}, v{}", op_to_str::op_to_str(self.op), self.a, self.b)
    }

    fn size(&self) -> usize {
        6
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins31i {
    op: u8,
    a: u8,
    b: i32,
}

impl TInstruction for Ins31i {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u32(r) as i32;
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u32(w, self.b as u32);
    }

    fn display(&self) -> String {
        format!("{} v{}, #{}", op_to_str::op_to_str(self.op), self.a, self.b)
    }

    fn size(&self) -> usize {
        6
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins31t {
    op: u8,
    a: u8,
    b: i32,
}

impl TInstruction for Ins31t {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u32(r) as i32;
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u32(w, self.b as u32);
    }

    fn display(&self) -> String {
        format!("{} v{}, {}", op_to_str::op_to_str(self.op), self.a, self.b)
    }

    fn size(&self) -> usize {
        6
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins31c {
    op: u8,
    a: u8,
    b: u32,
}

impl TInstruction for Ins31c {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u32(r);
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u32(w, self.b);
    }

    fn display(&self) -> String {
        format!(
            "{} v{}, string@{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.b
        )
    }

    fn size(&self) -> usize {
        6
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins35c {
    op: u8,
    a: u8,
    b: u16,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
    g: u8,
}

impl TInstruction for Ins35c {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let ag = decode_u8(r);
        let b = decode_u16(r);
        let dc = decode_u8(r);
        let fe = decode_u8(r);
        Self {
            op,
            a: ag >> 4,
            b,
            c: dc & 0xf,
            d: dc >> 4,
            e: fe & 0xf,
            f: fe >> 4,
            g: ag & 0xf,
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a << 4 | self.g);
        encode_u16(w, self.b);
        encode_u8(w, self.d << 4 | self.c);
        encode_u8(w, self.f << 4 | self.e);
    }

    fn display(&self) -> String {
        format!(
            "{} {} v{}, v{}, v{}, v{}, v{}, kind@{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.c,
            self.d,
            self.e,
            self.f,
            self.g,
            self.b,
        )
    }

    fn size(&self) -> usize {
        6
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Ins35ms {
    op: u8,
    a: u8,
    b: u16,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
    g: u8,
}

impl TInstruction for Ins35ms {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let ag = decode_u8(r);
        let b = decode_u16(r);
        let dc = decode_u8(r);
        let fe = decode_u8(r);
        Self {
            op,
            a: ag >> 4,
            b,
            c: dc & 0xf,
            d: dc >> 4,
            e: fe & 0xf,
            f: fe >> 4,
            g: ag & 0xf,
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a << 4 | self.g);
        encode_u16(w, self.b);
        encode_u8(w, self.d << 4 | self.c);
        encode_u8(w, self.f << 4 | self.e);
    }

    fn display(&self) -> String {
        format!(
            "{} {} v{}, v{}, v{}, v{}, v{}, vtaboff@{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.c,
            self.d,
            self.e,
            self.f,
            self.g,
            self.b,
        )
    }

    fn size(&self) -> usize {
        6
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Ins35mi {
    op: u8,
    a: u8,
    b: u16,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
    g: u8,
}

impl TInstruction for Ins35mi {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let ag = decode_u8(r);
        let b = decode_u16(r);
        let dc = decode_u8(r);
        let fe = decode_u8(r);
        Self {
            op,
            a: ag >> 4,
            b,
            c: dc & 0xf,
            d: dc >> 4,
            e: fe & 0xf,
            f: fe >> 4,
            g: ag & 0xf,
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a << 4 | self.g);
        encode_u16(w, self.b);
        encode_u8(w, self.d << 4 | self.c);
        encode_u8(w, self.f << 4 | self.e);
    }

    fn display(&self) -> String {
        format!(
            "{} {} v{}, v{}, v{}, v{}, v{}, inline@{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.c,
            self.d,
            self.e,
            self.f,
            self.g,
            self.b,
        )
    }

    fn size(&self) -> usize {
        6
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins3rc {
    op: u8,
    a: u8,
    b: u16,
    c: u16,
}

impl TInstruction for Ins3rc {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u16(r);
        let c = decode_u16(r);
        Self { op, a, b, c }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u16(w, self.b);
        encode_u16(w, self.c);
    }

    fn display(&self) -> String {
        format!(
            "{} {{v{} .. v{}}}, kind@{}",
            op_to_str::op_to_str(self.op),
            self.c,
            self.c + self.a as u16 - 1,
            self.b
        )
    }

    fn size(&self) -> usize {
        6
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins3rms {
    op: u8,
    a: u8,
    b: u16,
    c: u16,
}

impl TInstruction for Ins3rms {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u16(r);
        let c = decode_u16(r);
        Self { op, a, b, c }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u16(w, self.b);
        encode_u16(w, self.c);
    }

    fn display(&self) -> String {
        format!(
            "{} {{v{} .. v{}}}, vtaboff@{}",
            op_to_str::op_to_str(self.op),
            self.c,
            self.c + self.a as u16 - 1,
            self.b
        )
    }

    fn size(&self) -> usize {
        6
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins3rmi {
    op: u8,
    a: u8,
    b: u16,
    c: u16,
}

impl TInstruction for Ins3rmi {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u16(r);
        let c = decode_u16(r);
        Self { op, a, b, c }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u16(w, self.b);
        encode_u16(w, self.c);
    }

    fn display(&self) -> String {
        format!(
            "{} {{v{} .. v{}}}, inline@{}",
            op_to_str::op_to_str(self.op),
            self.c,
            self.c + self.a as u16 - 1,
            self.b
        )
    }

    fn size(&self) -> usize {
        6
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins45cc {
    op: u8,
    a: u8,
    b: u16,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
    g: u8,
    h: u16,
}

impl TInstruction for Ins45cc {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let ag = decode_u8(r);
        let b = decode_u16(r);
        let dc = decode_u8(r);
        let fe = decode_u8(r);
        let h = decode_u16(r);
        Self {
            op,
            a: ag >> 4,
            b,
            c: dc & 0xf,
            d: dc >> 4,
            e: fe & 0xf,
            f: fe >> 4,
            g: ag & 0xf,
            h,
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a << 4 | self.g);
        encode_u16(w, self.b);
        encode_u8(w, self.d << 4 | self.c);
        encode_u8(w, self.f << 4 | self.e);
        encode_u16(w, self.h);
    }

    fn display(&self) -> String {
        format!(
            "{} {} v{}, v{}, v{}, v{}, v{}, meth@{}, proto@{}",
            op_to_str::op_to_str(self.op),
            self.a,
            self.c,
            self.d,
            self.e,
            self.f,
            self.g,
            self.b,
            self.h,
        )
    }

    fn size(&self) -> usize {
        8
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins4rcc {
    op: u8,
    a: u8,
    b: u16,
    c: u16,
    h: u16,
}

impl TInstruction for Ins4rcc {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u16(r);
        let c = decode_u16(r);
        let h = decode_u16(r);
        Self { op, a, b, c, h }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u16(w, self.b);
        encode_u16(w, self.c);
        encode_u16(w, self.h);
    }

    fn display(&self) -> String {
        format!(
            "{} {{v{} .. v{}}}, meth@{}, proto@{}",
            op_to_str::op_to_str(self.op),
            self.c,
            self.c + self.a as u16 - 1,
            self.b,
            self.h,
        )
    }

    fn size(&self) -> usize {
        8
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ins51l {
    op: u8,
    a: u8,
    b: i64,
}

impl TInstruction for Ins51l {
    fn deserialize<R>(r: &mut R, op: u8) -> Self
    where
        R: io::BufRead,
    {
        let a = decode_u8(r);
        let b = decode_u64(r) as i64;
        Self { op, a, b }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.op);
        encode_u8(w, self.a);
        encode_u64(w, self.b as u64);
    }

    fn display(&self) -> String {
        format!("{} v{}, #{}", op_to_str::op_to_str(self.op), self.a, self.b)
    }

    fn size(&self) -> usize {
        10
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PackedSwitchPayload {
    size: u16,
    first_key: i32,
    targets: Vec<i32>,
}

impl TInstruction for PackedSwitchPayload {
    fn deserialize<R>(r: &mut R, _op: u8) -> Self
    where
        R: io::BufRead,
    {
        let size = decode_u16(r);
        let first_key = decode_u32(r) as i32;
        let targets = (0..size).map(|_| decode_u32(r) as i32).collect();
        Self {
            size,
            first_key,
            targets,
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, 0x00);
        encode_u8(w, 0x01);
        encode_u16(w, self.size);
        encode_u32(w, self.first_key as u32);
        for target in self.targets.iter() {
            encode_u32(w, *target as u32);
        }
    }

    fn display(&self) -> String {
        format!(
            "packed-switch-payload {}",
            self.targets
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<String>>()
                .join(" ")
        )
    }

    fn size(&self) -> usize {
        self.size as usize * 4 + 8
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SparseSwitchPayload {
    size: u16,
    keys: Vec<i32>,
    targets: Vec<i32>,
}

impl TInstruction for SparseSwitchPayload {
    fn deserialize<R>(r: &mut R, _op: u8) -> Self
    where
        R: io::BufRead,
    {
        let size = decode_u16(r);
        let keys = (0..size).map(|_| decode_u32(r) as i32).collect();
        let targets = (0..size).map(|_| decode_u32(r) as i32).collect();
        Self {
            size,
            keys,
            targets,
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, 0x00);
        encode_u8(w, 0x02);
        encode_u16(w, self.size);
        for key in self.keys.iter() {
            encode_u32(w, *key as u32);
        }
        for target in self.targets.iter() {
            encode_u32(w, *target as u32);
        }
    }

    fn display(&self) -> String {
        format!(
            "sparse-switch-payload {}",
            self.keys
                .iter()
                .zip(self.targets.iter())
                .map(|(k, t)| format!("{} -> {}", k.to_string(), t.to_string()))
                .collect::<Vec<String>>()
                .join(" ")
        )
    }

    fn size(&self) -> usize {
        self.size as usize * 8 + 4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct FillArrayDataPayload {
    element_width: u16,
    size: u32,
    data: Vec<u8>,
}

impl TInstruction for FillArrayDataPayload {
    fn deserialize<R>(r: &mut R, _op: u8) -> Self
    where
        R: io::BufRead,
    {
        let element_width = decode_u16(r);
        let size = decode_u32(r);
        let data = (0..(element_width as usize * size as usize))
            .map(|_| decode_u8(r))
            .collect::<Vec<u8>>();
        if data.len() % 2 == 1 {
            // Burn off byte to align to 16-bit code units.
            decode_u8(r);
        }
        Self {
            element_width,
            size,
            data,
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, 0x00);
        encode_u8(w, 0x03);
        encode_u16(w, self.element_width);
        encode_u32(w, self.size);
        for byte in self.data.iter() {
            encode_u8(w, *byte);
        }
        if self.data.len() % 2 == 1 {
            // Write one byte of padding if needed to align to 16-bit code unit boundary.
            encode_u8(w, 0x00);
        }
    }

    fn display(&self) -> String {
        format!(
            "fill-array-data-payload width: {} size: {} bytes: {}",
            self.element_width,
            self.size,
            self.data
                .iter()
                .map(|b| format!("0x{:X}", b))
                .collect::<Vec<String>>()
                .join(" ")
        )
    }

    fn size(&self) -> usize {
        let size = (self.size as usize * self.element_width as usize) + 8;
        if size % 2 == 1 {
            // Pad to nearest 16-bit code unit.
            return size + 1;
        }
        return size;
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
                0x00 => Ins10x { op: 0x00 }.into(),
                0x01 => PackedSwitchPayload::deserialize(r, op).into(),
                0x02 => SparseSwitchPayload::deserialize(r, op).into(),
                0x03 => FillArrayDataPayload::deserialize(r, op).into(),
                _ => panic!("bad nop high bits"),
            }
        }
        op @ 0x01 => Ins12x::deserialize(r, op).into(),
        op @ 0x02 => Ins22x::deserialize(r, op).into(),
        op @ 0x03 => Ins32x::deserialize(r, op).into(),
        op @ 0x04 => Ins12x::deserialize(r, op).into(),
        op @ 0x05 => Ins22x::deserialize(r, op).into(),
        op @ 0x06 => Ins32x::deserialize(r, op).into(),
        op @ 0x07 => Ins12x::deserialize(r, op).into(),
        op @ 0x08 => Ins22x::deserialize(r, op).into(),
        op @ 0x09 => Ins32x::deserialize(r, op).into(),
        op @ 0x0a => Ins11x::deserialize(r, op).into(),
        op @ 0x0b => Ins11x::deserialize(r, op).into(),
        op @ 0x0c => Ins11x::deserialize(r, op).into(),
        op @ 0x0d => Ins11x::deserialize(r, op).into(),
        op @ 0x0e => Ins10x::deserialize(r, op).into(),
        op @ 0x0f => Ins11x::deserialize(r, op).into(),
        op @ 0x10 => Ins11x::deserialize(r, op).into(),
        op @ 0x11 => Ins11x::deserialize(r, op).into(),
        op @ 0x12 => Ins11n::deserialize(r, op).into(),
        op @ 0x13 => Ins21s::deserialize(r, op).into(),
        op @ 0x14 => Ins31i::deserialize(r, op).into(),
        op @ 0x15 => Ins21h::deserialize(r, op).into(),
        op @ 0x16 => Ins21s::deserialize(r, op).into(),
        op @ 0x17 => Ins31i::deserialize(r, op).into(),
        op @ 0x18 => Ins51l::deserialize(r, op).into(),
        op @ 0x19 => Ins21h::deserialize(r, op).into(),
        op @ 0x1a => Ins21c::deserialize(r, op).into(),
        op @ 0x1b => Ins31c::deserialize(r, op).into(),
        op @ 0x1c => Ins21c::deserialize(r, op).into(),
        op @ 0x1d => Ins11x::deserialize(r, op).into(),
        op @ 0x1e => Ins11x::deserialize(r, op).into(),
        op @ 0x1f => Ins21c::deserialize(r, op).into(),
        op @ 0x20 => Ins22c::deserialize(r, op).into(),
        op @ 0x21 => Ins12x::deserialize(r, op).into(),
        op @ 0x22 => Ins21c::deserialize(r, op).into(),
        op @ 0x23 => Ins22c::deserialize(r, op).into(),
        op @ 0x24 => Ins35c::deserialize(r, op).into(),
        op @ 0x25 => Ins3rc::deserialize(r, op).into(),
        op @ 0x26 => Ins31t::deserialize(r, op).into(),
        op @ 0x27 => Ins11x::deserialize(r, op).into(),
        op @ 0x28 => Ins10t::deserialize(r, op).into(),
        op @ 0x29 => Ins20t::deserialize(r, op).into(),
        op @ 0x2a => Ins30t::deserialize(r, op).into(),
        op @ 0x2b => Ins31t::deserialize(r, op).into(),
        op @ 0x2c => Ins31t::deserialize(r, op).into(),
        op @ 0x2d..=0x31 => Ins23x::deserialize(r, op).into(),
        op @ 0x32..=0x37 => Ins22t::deserialize(r, op).into(),
        op @ 0x38..=0x3d => Ins21t::deserialize(r, op).into(),
        op @ 0x3e..=0x43 => Ins10x::deserialize(r, op).into(),
        op @ 0x44..=0x51 => Ins23x::deserialize(r, op).into(),
        op @ 0x52..=0x5f => Ins22c::deserialize(r, op).into(),
        op @ 0x60..=0x6d => Ins21c::deserialize(r, op).into(),
        op @ 0x6e..=0x72 => Ins35c::deserialize(r, op).into(),
        op @ 0x73 => Ins10x::deserialize(r, op).into(),
        op @ 0x74..=0x78 => Ins3rc::deserialize(r, op).into(),
        op @ 0x79..=0x7a => Ins10x::deserialize(r, op).into(),
        op @ 0x7b..=0x8f => Ins12x::deserialize(r, op).into(),
        op @ 0x90..=0xaf => Ins23x::deserialize(r, op).into(),
        op @ 0xb0..=0xcf => Ins12x::deserialize(r, op).into(),
        op @ 0xd0..=0xd7 => Ins22s::deserialize(r, op).into(),
        op @ 0xd8..=0xe2 => Ins22b::deserialize(r, op).into(),
        op @ 0xe3..=0xf9 => Ins10x::deserialize(r, op).into(),
        op @ 0xfa => Ins45cc::deserialize(r, op).into(),
        op @ 0xfb => Ins4rcc::deserialize(r, op).into(),
        op @ 0xfc => Ins35c::deserialize(r, op).into(),
        op @ 0xfd => Ins3rc::deserialize(r, op).into(),
        op @ 0xfe => Ins21c::deserialize(r, op).into(),
        op @ 0xff => Ins21c::deserialize(r, op).into(),
    }
}

pub fn decode_insns<R>(r: &mut R, mut insns_size: usize) -> Vec<Instruction>
where
    R: io::BufRead,
{
    let mut insns = vec![];
    while insns_size > 0 {
        let insn = decode_insn(r);
        insns_size -= insn.size() / 2;
        insns.push(insn);
    }
    return insns;
}
