use std::{fmt::Debug, io, vec};

use crate::{
    decode::{
        decode_i8, decode_nbytes_as_f32, decode_nbytes_as_f64, decode_nbytes_signed,
        decode_nbytes_unsigned, decode_sleb128, decode_u16, decode_u32, decode_u8, decode_uleb128,
        decode_uleb128p1,
    },
    encode::{
        encode_nbytes, encode_nbytes_for_double, encode_nbytes_for_float, encode_sleb128,
        encode_u16, encode_u32, encode_u8, encode_uleb128, encode_uleb128p1, size_sleb128,
        size_uleb128, size_uleb128p1,
    },
    encoded_value_utils::{
        get_required_bytes_for_f32, get_required_bytes_for_f64, get_required_bytes_signed,
        get_required_bytes_unsigned,
    },
    sleb128, uleb128, uleb128p1,
};

pub trait DexStruct {
    /// Padding requirement from DEX spec.
    const ALIGNMENT: u64;

    /// Decodes from binary format into rust struct.
    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead;

    /// Encodes struct to binary format.
    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write;

    /// Size of the struct when encoded.
    fn size(&self) -> usize;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Header {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

impl DexStruct for Header {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)
            .expect("Could not read magic number");
        let checksum = decode_u32(r);
        let mut signature = [0u8; 20];
        r.read_exact(&mut signature)
            .expect("Could not read signature");
        let file_size = decode_u32(r);
        let header_size = decode_u32(r);
        let endian_tag = decode_u32(r);
        let link_size = decode_u32(r);
        let link_off = decode_u32(r);
        let map_off = decode_u32(r);
        let string_ids_size = decode_u32(r);
        let string_ids_off = decode_u32(r);
        let type_ids_size = decode_u32(r);
        let type_ids_off = decode_u32(r);
        let proto_ids_size = decode_u32(r);
        let proto_ids_off = decode_u32(r);
        let field_ids_size = decode_u32(r);
        let field_ids_off = decode_u32(r);
        let method_ids_size = decode_u32(r);
        let method_ids_off = decode_u32(r);
        let class_defs_size = decode_u32(r);
        let class_defs_off = decode_u32(r);
        let data_size = decode_u32(r);
        let data_off = decode_u32(r);

        return Self {
            magic,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        w.write(&self.magic).expect("Could not write magic.");
        encode_u32(w, self.checksum);
        w.write(&self.signature)
            .expect("Could not write signature.");
        encode_u32(w, self.file_size);
        encode_u32(w, self.header_size);
        encode_u32(w, self.endian_tag);
        encode_u32(w, self.link_size);
        encode_u32(w, self.link_off);
        encode_u32(w, self.map_off);
        encode_u32(w, self.string_ids_size);
        encode_u32(w, self.string_ids_off);
        encode_u32(w, self.type_ids_size);
        encode_u32(w, self.type_ids_off);
        encode_u32(w, self.proto_ids_size);
        encode_u32(w, self.proto_ids_off);
        encode_u32(w, self.field_ids_size);
        encode_u32(w, self.field_ids_off);
        encode_u32(w, self.method_ids_size);
        encode_u32(w, self.method_ids_off);
        encode_u32(w, self.class_defs_size);
        encode_u32(w, self.class_defs_off);
        encode_u32(w, self.data_size);
        encode_u32(w, self.data_off);
    }

    fn size(&self) -> usize {
        self.header_size as usize
    }
}

#[derive(Debug, PartialEq)]
pub struct StringIdItem {
    pub string_data_off: u32,
}
impl DexStruct for StringIdItem {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let string_data_off = decode_u32(r);
        return Self { string_data_off };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.string_data_off);
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq)]
pub struct StringDataItem {
    pub utf16_size: uleb128,
    pub data: Vec<u8>,
}

impl DexStruct for StringDataItem {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let size = decode_uleb128(r);
        let mut buf = vec![];
        r.read_until(0, &mut buf)
            .expect("Could not deserialize string data");

        // https://android.googlesource.com/platform/libcore/+/9edf43dfcc35c761d97eb9156ac4254152ddbc55/dex/src/main/java/com/android/dex/Mutf8.java
        // let x = mutf8::decode(&buf).unwrap().to_string();

        return Self {
            utf16_size: size,
            data: buf,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_uleb128(w, self.utf16_size);
        w.write(&self.data).expect("failed to write string data");
    }

    fn size(&self) -> usize {
        size_uleb128(self.utf16_size) + self.data.len()
    }
}

#[derive(Debug, PartialEq)]
pub struct TypeIdItem {
    pub descriptor_idx: u32,
}

impl DexStruct for TypeIdItem {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let descriptor_idx = decode_u32(r);
        return Self { descriptor_idx };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.descriptor_idx);
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq)]
pub struct ProtoIdItem {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
}

impl DexStruct for ProtoIdItem {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let shorty_idx = decode_u32(r);
        let return_type_idx = decode_u32(r);
        let parameters_off = decode_u32(r);
        return Self {
            shorty_idx,
            return_type_idx,
            parameters_off,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.shorty_idx);
        encode_u32(w, self.return_type_idx);
        encode_u32(w, self.parameters_off);
    }

    fn size(&self) -> usize {
        12
    }
}

#[derive(Debug, PartialEq)]
pub struct FieldIdItem {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

impl DexStruct for FieldIdItem {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let class_idx = decode_u16(r);
        let type_idx = decode_u16(r);
        let name_idx = decode_u32(r);
        return Self {
            class_idx,
            type_idx,
            name_idx,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u16(w, self.class_idx);
        encode_u16(w, self.type_idx);
        encode_u32(w, self.name_idx);
    }

    fn size(&self) -> usize {
        8
    }
}

#[derive(Debug, PartialEq)]
pub struct MethodIdItem {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

impl DexStruct for MethodIdItem {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let class_idx = decode_u16(r);
        let proto_idx = decode_u16(r);
        let name_idx = decode_u32(r);
        return Self {
            class_idx,
            proto_idx,
            name_idx,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u16(w, self.class_idx);
        encode_u16(w, self.proto_idx);
        encode_u32(w, self.name_idx);
    }

    fn size(&self) -> usize {
        8
    }
}

#[derive(Debug, PartialEq)]
pub struct ClassDefItem {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

impl DexStruct for ClassDefItem {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let class_idx = decode_u32(r);
        let access_flags = decode_u32(r);
        let superclass_idx = decode_u32(r);
        let interfaces_off = decode_u32(r);
        let source_file_idx = decode_u32(r);
        let annotations_off = decode_u32(r);
        let class_data_off = decode_u32(r);
        let static_values_off = decode_u32(r);
        return Self {
            class_idx,
            access_flags,
            superclass_idx,
            interfaces_off,
            source_file_idx,
            annotations_off,
            class_data_off,
            static_values_off,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.class_idx);
        encode_u32(w, self.access_flags);
        encode_u32(w, self.superclass_idx);
        encode_u32(w, self.interfaces_off);
        encode_u32(w, self.source_file_idx);
        encode_u32(w, self.annotations_off);
        encode_u32(w, self.class_data_off);
        encode_u32(w, self.static_values_off);
    }

    fn size(&self) -> usize {
        32
    }
}

#[derive(Debug, PartialEq)]
pub struct CallSiteIdItem {
    pub call_site_off: u32,
}

impl DexStruct for CallSiteIdItem {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let call_site_off = decode_u32(r);
        return Self { call_site_off };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.call_site_off);
    }

    fn size(&self) -> usize {
        4
    }
}

pub type CallSiteItem = EncodedArrayItem;

#[derive(Debug, PartialEq)]
pub struct EncodedArrayItem {
    pub value: EncodedArray,
}

impl DexStruct for EncodedArrayItem {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let value = EncodedArray::deserialize(r);
        return Self { value };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        self.value.serialize(w);
    }

    fn size(&self) -> usize {
        self.value.size()
    }
}

#[derive(Debug, PartialEq)]
pub struct EncodedArray {
    pub values: Vec<EncodedValue>,
}

impl DexStruct for EncodedArray {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let size = decode_uleb128(r);
        let mut values = vec![];
        for _ in 0..size {
            values.push(EncodedValue::deserialize(r));
        }
        return Self { values };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_uleb128(w, self.values.len() as u32);
        for val in self.values.iter() {
            val.serialize(w);
        }
    }

    fn size(&self) -> usize {
        size_uleb128(self.values.len() as u32) + self.values.iter().map(|v| v.size()).sum::<usize>()
    }
}

#[derive(Debug, PartialEq)]
pub enum EncodedValue {
    ValueByte(i8),
    ValueShort(i16),
    ValueChar(u16),
    ValueInt(i32),
    ValueLong(i64),
    ValueFloat(f32),
    ValueDouble(f64),
    ValueMethodType(u32),
    ValueMethodHandle(u32),
    ValueString(u32),
    ValueType(u32),
    ValueField(u32),
    ValueMethod(u32),
    ValueEnum(u32),
    ValueArray(EncodedArray),
    ValueAnnotation(EncodedAnnotation),
    ValueNull,
    ValueBoolean(bool),
}

impl EncodedValue {
    fn serialize_value_signed<W>(&self, w: &mut W, v: i64)
    where
        W: io::Write,
    {
        let rb = get_required_bytes_signed(v);
        let val = ((rb - 1) << 5) | self.get_type_code();
        encode_u8(w, val);
        encode_nbytes(w, rb, v as u64);
    }

    fn serialize_value_unsigned<W>(&self, w: &mut W, v: u64)
    where
        W: io::Write,
    {
        let rb = get_required_bytes_unsigned(v);
        let val = ((rb - 1) << 5) | self.get_type_code();
        encode_u8(w, val);
        encode_nbytes(w, rb, v as u64);
    }

    fn get_type_code(&self) -> u8 {
        match self {
            EncodedValue::ValueByte(_) => 0x00,
            EncodedValue::ValueShort(_) => 0x02,
            EncodedValue::ValueChar(_) => 0x03,
            EncodedValue::ValueInt(_) => 0x04,
            EncodedValue::ValueLong(_) => 0x06,
            EncodedValue::ValueFloat(_) => 0x10,
            EncodedValue::ValueDouble(_) => 0x11,
            EncodedValue::ValueMethodType(_) => 0x15,
            EncodedValue::ValueMethodHandle(_) => 0x16,
            EncodedValue::ValueString(_) => 0x17,
            EncodedValue::ValueType(_) => 0x18,
            EncodedValue::ValueField(_) => 0x19,
            EncodedValue::ValueMethod(_) => 0x1a,
            EncodedValue::ValueEnum(_) => 0x1b,
            EncodedValue::ValueArray(_) => 0x1c,
            EncodedValue::ValueAnnotation(_) => 0x1d,
            EncodedValue::ValueNull => 0x1e,
            EncodedValue::ValueBoolean(_) => 0x1f,
        }
    }
}

impl DexStruct for EncodedValue {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let value_byte = decode_u8(r);
        // TODO: just shift by 5 no need to & everything
        let value_arg = (((value_byte & 0b11100000) >> 5) & 0b00000111) as usize;
        let value_type = value_byte & 0b00011111;
        match value_type {
            0x00 => {
                assert_eq!(value_arg, 0);
                EncodedValue::ValueByte(decode_i8(r))
            }
            0x02 => EncodedValue::ValueShort(decode_nbytes_signed(r, value_arg + 1) as i16),
            0x03 => EncodedValue::ValueChar(decode_nbytes_unsigned(r, value_arg + 1) as u16),
            0x04 => EncodedValue::ValueInt(decode_nbytes_signed(r, value_arg + 1) as i32),
            0x06 => EncodedValue::ValueLong(decode_nbytes_signed(r, value_arg + 1) as i64),
            0x10 => EncodedValue::ValueFloat(decode_nbytes_as_f32(r, value_arg + 1)),
            0x11 => EncodedValue::ValueDouble(decode_nbytes_as_f64(r, value_arg + 1)),
            0x15 => EncodedValue::ValueMethodType(decode_nbytes_unsigned(r, value_arg + 1) as u32),
            0x16 => {
                EncodedValue::ValueMethodHandle(decode_nbytes_unsigned(r, value_arg + 1) as u32)
            }
            0x17 => EncodedValue::ValueString(decode_nbytes_unsigned(r, value_arg + 1) as u32),
            0x18 => EncodedValue::ValueType(decode_nbytes_unsigned(r, value_arg + 1) as u32),
            0x19 => EncodedValue::ValueField(decode_nbytes_unsigned(r, value_arg + 1) as u32),
            0x1a => EncodedValue::ValueMethod(decode_nbytes_unsigned(r, value_arg + 1) as u32),
            0x1b => EncodedValue::ValueEnum(decode_nbytes_unsigned(r, value_arg + 1) as u32),
            0x1c => {
                assert_eq!(value_arg, 0);
                EncodedValue::ValueArray(EncodedArray::deserialize(r))
            }
            0x1d => {
                assert_eq!(value_arg, 0);
                EncodedValue::ValueAnnotation(EncodedAnnotation::deserialize(r))
            }
            0x1e => {
                assert_eq!(value_arg, 0);
                EncodedValue::ValueNull
            }
            0x1f => EncodedValue::ValueBoolean(value_arg != 0),
            _ => panic!("unexpected value type {}", value_type),
        }
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        match self {
            EncodedValue::ValueByte(v) => {
                self.serialize_value_signed(w, *v as i64);
            }
            EncodedValue::ValueShort(v) => {
                self.serialize_value_signed(w, *v as i64);
            }
            EncodedValue::ValueChar(v) => {
                self.serialize_value_unsigned(w, *v as u64);
            }
            EncodedValue::ValueInt(v) => {
                self.serialize_value_signed(w, *v as i64);
            }
            EncodedValue::ValueLong(v) => {
                self.serialize_value_signed(w, *v as i64);
            }
            EncodedValue::ValueFloat(v) => {
                let rb = get_required_bytes_for_f32(*v);
                let val = ((rb - 1) << 5) | self.get_type_code();
                encode_u8(w, val);
                encode_nbytes_for_float(w, rb, v.to_bits());
            }
            EncodedValue::ValueDouble(v) => {
                let rb = get_required_bytes_for_f64(*v);
                let val = ((rb - 1) << 5) | self.get_type_code();
                encode_u8(w, val);
                encode_nbytes_for_double(w, rb, v.to_bits());
            }
            EncodedValue::ValueMethodType(v) => {
                self.serialize_value_unsigned(w, *v as u64);
            }
            EncodedValue::ValueMethodHandle(v) => {
                self.serialize_value_unsigned(w, *v as u64);
            }
            EncodedValue::ValueString(v) => {
                self.serialize_value_unsigned(w, *v as u64);
            }
            EncodedValue::ValueType(v) => {
                self.serialize_value_unsigned(w, *v as u64);
            }
            EncodedValue::ValueField(v) => {
                self.serialize_value_unsigned(w, *v as u64);
            }
            EncodedValue::ValueMethod(v) => {
                self.serialize_value_unsigned(w, *v as u64);
            }
            EncodedValue::ValueEnum(v) => {
                self.serialize_value_unsigned(w, *v as u64);
            }
            EncodedValue::ValueArray(v) => {
                encode_u8(w, self.get_type_code());
                v.serialize(w);
            }
            EncodedValue::ValueAnnotation(v) => {
                encode_u8(w, self.get_type_code());
                v.serialize(w);
            }
            EncodedValue::ValueNull => {
                encode_u8(w, self.get_type_code());
            }
            EncodedValue::ValueBoolean(v) => {
                if *v {
                    encode_u8(w, (1 << 5) | self.get_type_code());
                } else {
                    encode_u8(w, self.get_type_code());
                }
            }
        }
    }

    fn size(&self) -> usize {
        match self {
            EncodedValue::ValueByte(_)
            | EncodedValue::ValueNull
            | EncodedValue::ValueBoolean(_) => 1,
            EncodedValue::ValueArray(arr) => 1 + arr.size(),
            EncodedValue::ValueAnnotation(anno) => 1 + anno.size(),
            EncodedValue::ValueShort(v) => 1 + get_required_bytes_signed(*v as i64) as usize,
            EncodedValue::ValueChar(v) => 1 + get_required_bytes_unsigned(*v as u64) as usize,
            EncodedValue::ValueInt(v) => 1 + get_required_bytes_signed(*v as i64) as usize,
            EncodedValue::ValueLong(v) => 1 + get_required_bytes_signed(*v as i64) as usize,
            EncodedValue::ValueFloat(v) => 1 + get_required_bytes_for_f32(*v) as usize,
            EncodedValue::ValueDouble(v) => 1 + get_required_bytes_for_f64(*v) as usize,
            EncodedValue::ValueMethodType(v) => 1 + get_required_bytes_unsigned(*v as u64) as usize,
            EncodedValue::ValueMethodHandle(v) => {
                1 + get_required_bytes_unsigned(*v as u64) as usize
            }
            EncodedValue::ValueString(v) => 1 + get_required_bytes_unsigned(*v as u64) as usize,
            EncodedValue::ValueType(v) => 1 + get_required_bytes_unsigned(*v as u64) as usize,
            EncodedValue::ValueField(v) => 1 + get_required_bytes_unsigned(*v as u64) as usize,
            EncodedValue::ValueMethod(v) => 1 + get_required_bytes_unsigned(*v as u64) as usize,
            EncodedValue::ValueEnum(v) => 1 + get_required_bytes_unsigned(*v as u64) as usize,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct MethodHandleItem {
    pub method_handle_type: u16,
    pub unused1: u16,
    pub field_or_method_id: u16,
    pub unused2: u16,
}

impl DexStruct for MethodHandleItem {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let method_handle_type = decode_u16(r);
        let unused1 = decode_u16(r);
        let field_or_method_id = decode_u16(r);
        let unused2 = decode_u16(r);
        return Self {
            method_handle_type,
            unused1,
            field_or_method_id,
            unused2,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u16(w, self.method_handle_type);
        encode_u16(w, self.unused1);
        encode_u16(w, self.field_or_method_id);
        encode_u16(w, self.unused2);
    }

    fn size(&self) -> usize {
        8
    }
}

#[derive(Debug, PartialEq)]
pub struct ClassDataItem {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

impl DexStruct for ClassDataItem {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let static_fields_size = decode_uleb128(r);
        let instance_fields_size = decode_uleb128(r);
        let direct_methods_size = decode_uleb128(r);
        let virtual_methods_size = decode_uleb128(r);
        let static_fields = (0..static_fields_size)
            .map(|_| EncodedField::deserialize(r))
            .collect();
        let instance_fields = (0..instance_fields_size)
            .map(|_| EncodedField::deserialize(r))
            .collect();
        let direct_methods = (0..direct_methods_size)
            .map(|_| EncodedMethod::deserialize(r))
            .collect();
        let virtual_methods = (0..virtual_methods_size)
            .map(|_| EncodedMethod::deserialize(r))
            .collect();

        return Self {
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_uleb128(w, self.static_fields.len() as u32);
        encode_uleb128(w, self.instance_fields.len() as u32);
        encode_uleb128(w, self.direct_methods.len() as u32);
        encode_uleb128(w, self.virtual_methods.len() as u32);
        for field in self.static_fields.iter() {
            field.serialize(w);
        }
        for field in self.instance_fields.iter() {
            field.serialize(w);
        }
        for method in self.direct_methods.iter() {
            method.serialize(w);
        }
        for method in self.virtual_methods.iter() {
            method.serialize(w);
        }
    }

    fn size(&self) -> usize {
        size_uleb128(self.static_fields.len() as u32)
            + size_uleb128(self.instance_fields.len() as u32)
            + size_uleb128(self.direct_methods.len() as u32)
            + size_uleb128(self.virtual_methods.len() as u32)
            + self.static_fields.iter().map(|x| x.size()).sum::<usize>()
            + self.instance_fields.iter().map(|x| x.size()).sum::<usize>()
            + self.direct_methods.iter().map(|x| x.size()).sum::<usize>()
            + self.virtual_methods.iter().map(|x| x.size()).sum::<usize>()
    }
}

#[derive(Debug, PartialEq)]
pub struct EncodedField {
    pub field_idx_off: uleb128,
    pub access_flags: uleb128,
}

impl DexStruct for EncodedField {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let field_idx_off = decode_uleb128(r);
        let access_flags = decode_uleb128(r);
        return Self {
            field_idx_off,
            access_flags,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_uleb128(w, self.field_idx_off);
        encode_uleb128(w, self.access_flags);
    }

    fn size(&self) -> usize {
        size_uleb128(self.field_idx_off) + size_uleb128(self.access_flags)
    }
}

#[derive(Debug, PartialEq)]
pub struct EncodedMethod {
    pub method_idx_off: uleb128,
    pub access_flags: uleb128,
    pub code_off: uleb128,
}

impl DexStruct for EncodedMethod {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let method_idx_off = decode_uleb128(r);
        let access_flags = decode_uleb128(r);
        let code_off = decode_uleb128(r);
        return Self {
            method_idx_off,
            access_flags,
            code_off,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_uleb128(w, self.method_idx_off);
        encode_uleb128(w, self.access_flags);
        encode_uleb128(w, self.code_off);
    }

    fn size(&self) -> usize {
        size_uleb128(self.method_idx_off)
            + size_uleb128(self.access_flags)
            + size_uleb128(self.code_off)
    }
}

#[derive(Debug, PartialEq)]
pub struct TypeList {
    pub list: Vec<TypeItem>,
}

impl DexStruct for TypeList {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let size = decode_u32(r);
        let list = (0..size).map(|_| TypeItem::deserialize(r)).collect();
        return Self { list };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.list.len() as u32);
        for type_item in self.list.iter() {
            type_item.serialize(w);
        }
    }

    fn size(&self) -> usize {
        4 + 2 * self.list.len()
    }
}

#[derive(Debug, PartialEq)]
pub struct TypeItem {
    pub type_idx: u16,
}

impl DexStruct for TypeItem {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        return Self {
            type_idx: decode_u16(r),
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u16(w, self.type_idx);
    }

    fn size(&self) -> usize {
        2
    }
}

#[derive(Debug, PartialEq)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub debug_info_off: u32,
    pub insns: Vec<u16>,
    pub tries: Vec<TryItem>,
    pub handlers: Option<EncodedCatchHandlerList>,
}

impl DexStruct for CodeItem {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let registers_size = decode_u16(r);
        let ins_size = decode_u16(r);
        let outs_size = decode_u16(r);
        let tries_size = decode_u16(r);
        let debug_info_off = decode_u32(r);
        let insns_size = decode_u32(r);
        let insns = (0..insns_size).map(|_| decode_u16(r)).collect();
        if tries_size != 0 && insns_size % 2 == 1 {
            // Burn off padding if needed.
            decode_u16(r);
        }
        let tries = (0..tries_size).map(|_| TryItem::deserialize(r)).collect();
        let mut handlers = None;
        if tries_size != 0 {
            handlers = Some(EncodedCatchHandlerList::deserialize(r));
        }
        return Self {
            registers_size,
            ins_size,
            outs_size,
            debug_info_off,
            insns,
            tries,
            handlers,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u16(w, self.registers_size);
        encode_u16(w, self.ins_size);
        encode_u16(w, self.outs_size);
        encode_u16(w, self.tries.len() as u16);
        encode_u32(w, self.debug_info_off);
        encode_u32(w, self.insns.len() as u32);
        for insn in self.insns.iter() {
            encode_u16(w, *insn);
        }
        if self.tries.len() != 0 && self.insns.len() % 2 == 1 {
            encode_u16(w, 0);
        }
        for try_item in self.tries.iter() {
            try_item.serialize(w);
        }
        for handler in self.handlers.iter() {
            handler.serialize(w);
        }
    }

    fn size(&self) -> usize {
        let padding;
        if self.tries.len() != 0 && self.insns.len() % 2 == 1 {
            padding = 2;
        } else {
            padding = 0;
        }
        16 + 2 * self.insns.len()
            + padding
            + 8 * self.tries.len()
            + self.handlers.iter().map(|h| h.size()).sum::<usize>()
    }
}

#[derive(Debug, PartialEq)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

impl DexStruct for TryItem {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let start_addr = decode_u32(r);
        let insn_count = decode_u16(r);
        let handler_off = decode_u16(r);
        return Self {
            start_addr,
            insn_count,
            handler_off,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.start_addr);
        encode_u16(w, self.insn_count);
        encode_u16(w, self.handler_off);
    }

    fn size(&self) -> usize {
        8
    }
}

#[derive(Debug, PartialEq)]
pub struct EncodedCatchHandlerList {
    pub list: Vec<EncodedCatchHandler>,
}

impl DexStruct for EncodedCatchHandlerList {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let size = decode_uleb128(r);
        let list = (0..size)
            .map(|_| EncodedCatchHandler::deserialize(r))
            .collect();
        return Self { list };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_uleb128(w, self.list.len() as uleb128);
        for handler in self.list.iter() {
            handler.serialize(w);
        }
    }

    fn size(&self) -> usize {
        size_uleb128(self.list.len() as uleb128) + self.list.iter().map(|x| x.size()).sum::<usize>()
    }
}

#[derive(Debug, PartialEq)]
pub struct EncodedCatchHandler {
    pub handlers: Vec<EncodedTypeAddressPair>,
    pub catch_all_addr: Option<uleb128>,
}

impl DexStruct for EncodedCatchHandler {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let size = decode_sleb128(r);
        let handlers = (0..size.abs())
            .map(|_| EncodedTypeAddressPair::deserialize(r))
            .collect();
        let mut catch_all_addr = None;
        if size <= 0 {
            catch_all_addr = Some(decode_uleb128(r));
        }
        return Self {
            handlers,
            catch_all_addr,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        match self.catch_all_addr {
            None => {
                encode_sleb128(w, self.handlers.len() as sleb128);
                for handler in self.handlers.iter() {
                    handler.serialize(w);
                }
            }
            Some(catch_all_addr) => {
                encode_sleb128(w, -(self.handlers.len() as sleb128));
                for handler in self.handlers.iter() {
                    handler.serialize(w);
                }
                encode_uleb128(w, catch_all_addr);
            }
        }
    }

    fn size(&self) -> usize {
        match self.catch_all_addr {
            None => {
                size_sleb128(self.handlers.len() as sleb128)
                    + self.handlers.iter().map(|x| x.size()).sum::<usize>()
            }
            Some(catch_all_addr) => {
                size_sleb128(-(self.handlers.len() as sleb128))
                    + self.handlers.iter().map(|x| x.size()).sum::<usize>()
                    + size_uleb128(catch_all_addr)
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct EncodedTypeAddressPair {
    pub type_idx: uleb128,
    pub addr: uleb128,
}

impl DexStruct for EncodedTypeAddressPair {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        let type_idx = decode_uleb128(r);
        let addr = decode_uleb128(r);
        return Self { type_idx, addr };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_uleb128(w, self.type_idx);
        encode_uleb128(w, self.addr);
    }

    fn size(&self) -> usize {
        size_uleb128(self.type_idx) + size_uleb128(self.addr)
    }
}

#[derive(Debug, PartialEq)]
pub struct DebugInfoItem {
    pub line_start: uleb128,
    pub parameter_names: Vec<uleb128p1>,
    pub bytecode: Vec<u8>,
}

impl DexStruct for DebugInfoItem {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let line_start = decode_uleb128(r);
        let parameters_size = decode_uleb128(r);
        let parameter_names = (0..parameters_size).map(|_| decode_uleb128p1(r)).collect();
        let mut bytecode = vec![];
        let end_opcode = 0x00; // DBG_END_SEQUENCE
        r.read_until(end_opcode, &mut bytecode)
            .expect("debug_info_item deserializer did not find DBG_END_SEQUENCE");
        return Self {
            line_start,
            parameter_names,
            bytecode,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_uleb128(w, self.line_start);
        encode_uleb128(w, self.parameter_names.len() as uleb128);
        for name in self.parameter_names.iter() {
            encode_uleb128p1(w, *name);
        }
        w.write(&self.bytecode).expect("failed to write dwarf");
    }

    fn size(&self) -> usize {
        size_uleb128(self.line_start)
            + size_uleb128(self.parameter_names.len() as uleb128)
            + self
                .parameter_names
                .iter()
                .map(|x| size_uleb128p1(*x))
                .sum::<usize>()
            + self.bytecode.len()
    }
}

#[derive(Debug, PartialEq)]
pub struct AnnotationsDirectoryItem {
    pub class_annotations_off: u32,
    pub field_annotations: Vec<FieldAnnotation>,
    pub method_annotations: Vec<MethodAnnotation>,
    pub parameter_annotations: Vec<ParameterAnnotation>,
}

impl DexStruct for AnnotationsDirectoryItem {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let class_annotations_off = decode_u32(r);
        let fields_size = decode_u32(r);
        let annotated_methods_size = decode_u32(r);
        let annotated_parameters_size = decode_u32(r);
        let field_annotations = (0..fields_size)
            .map(|_| FieldAnnotation::deserialize(r))
            .collect();
        let method_annotations = (0..annotated_methods_size)
            .map(|_| MethodAnnotation::deserialize(r))
            .collect();
        let parameter_annotations = (0..annotated_parameters_size)
            .map(|_| ParameterAnnotation::deserialize(r))
            .collect();

        return Self {
            class_annotations_off,
            field_annotations,
            method_annotations,
            parameter_annotations,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.class_annotations_off);
        encode_u32(w, self.field_annotations.len() as u32);
        encode_u32(w, self.method_annotations.len() as u32);
        encode_u32(w, self.parameter_annotations.len() as u32);
        for anno in self.field_annotations.iter() {
            anno.serialize(w);
        }
        for anno in self.method_annotations.iter() {
            anno.serialize(w);
        }
        for anno in self.parameter_annotations.iter() {
            anno.serialize(w);
        }
    }

    fn size(&self) -> usize {
        16 + self
            .field_annotations
            .iter()
            .map(|x| x.size())
            .sum::<usize>()
            + self
                .method_annotations
                .iter()
                .map(|x| x.size())
                .sum::<usize>()
            + self
                .parameter_annotations
                .iter()
                .map(|x| x.size())
                .sum::<usize>()
    }
}

#[derive(Debug, PartialEq)]
pub struct FieldAnnotation {
    pub field_idx: u32,
    pub annotations_off: u32,
}

impl DexStruct for FieldAnnotation {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        let field_idx = decode_u32(r);
        let annotations_off = decode_u32(r);
        return Self {
            field_idx,
            annotations_off,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.field_idx);
        encode_u32(w, self.annotations_off);
    }

    fn size(&self) -> usize {
        8
    }
}

#[derive(Debug, PartialEq)]
pub struct MethodAnnotation {
    pub method_idx: u32,
    pub annotations_off: u32,
}

impl DexStruct for MethodAnnotation {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        let method_idx = decode_u32(r);
        let annotations_off = decode_u32(r);
        return Self {
            method_idx,
            annotations_off,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.method_idx);
        encode_u32(w, self.annotations_off);
    }

    fn size(&self) -> usize {
        8
    }
}

#[derive(Debug, PartialEq)]
pub struct ParameterAnnotation {
    pub method_idx: u32,
    pub annotations_off: u32,
}

impl DexStruct for ParameterAnnotation {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        let method_idx = decode_u32(r);
        let annotations_off = decode_u32(r);
        return Self {
            method_idx,
            annotations_off,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.method_idx);
        encode_u32(w, self.annotations_off);
    }

    fn size(&self) -> usize {
        8
    }
}

#[derive(Debug, PartialEq)]
pub struct AnnotationSetRefList {
    pub list: Vec<AnnotationSetRefItem>,
}

impl DexStruct for AnnotationSetRefList {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let size = decode_u32(r);
        let list = (0..size)
            .map(|_| AnnotationSetRefItem::deserialize(r))
            .collect();
        return Self { list };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.list.len() as u32);
        for item in self.list.iter() {
            item.serialize(w);
        }
    }

    fn size(&self) -> usize {
        4 + 4 * self.list.len()
    }
}

#[derive(Debug, PartialEq)]
pub struct AnnotationSetRefItem {
    pub annotations_off: u32,
}

impl DexStruct for AnnotationSetRefItem {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let annotations_off = decode_u32(r);
        return Self { annotations_off };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.annotations_off);
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq)]
pub struct AnnotationSetItem {
    pub entries: Vec<AnnotationOffItem>,
}

impl DexStruct for AnnotationSetItem {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let size = decode_u32(r);
        let entries = (0..size)
            .map(|_| AnnotationOffItem::deserialize(r))
            .collect();
        return Self { entries };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.entries.len() as u32);
        for entry in self.entries.iter() {
            entry.serialize(w);
        }
    }

    fn size(&self) -> usize {
        4 + 4 * self.entries.len()
    }
}

#[derive(Debug, PartialEq)]
pub struct AnnotationOffItem {
    pub annotation_off: u32,
}

impl DexStruct for AnnotationOffItem {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let annotation_off = decode_u32(r);
        return Self { annotation_off };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.annotation_off);
    }

    fn size(&self) -> usize {
        4
    }
}

#[derive(Debug, PartialEq)]
pub struct AnnotationItem {
    pub visibility: u8,
    pub annotation: EncodedAnnotation,
}

impl DexStruct for AnnotationItem {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let visibility = decode_u8(r);
        let annotation = EncodedAnnotation::deserialize(r);
        return Self {
            visibility,
            annotation,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u8(w, self.visibility);
        self.annotation.serialize(w);
    }

    fn size(&self) -> usize {
        1 + self.annotation.size()
    }
}

#[derive(Debug, PartialEq)]
pub struct EncodedAnnotation {
    pub type_idx: uleb128,
    pub elements: Vec<AnnotationElement>,
}

impl DexStruct for EncodedAnnotation {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let type_idx = decode_uleb128(r);
        let size = decode_uleb128(r);
        let mut elements = vec![];
        for _ in 0..size {
            elements.push(AnnotationElement::deserialize(r));
        }
        return Self { type_idx, elements };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_uleb128(w, self.type_idx);
        encode_uleb128(w, self.elements.len() as u32);
        for element in self.elements.iter() {
            element.serialize(w);
        }
    }

    fn size(&self) -> usize {
        size_uleb128(self.type_idx)
            + size_uleb128(self.elements.len() as uleb128)
            + self.elements.iter().map(|x| x.size()).sum::<usize>()
    }
}

#[derive(Debug, PartialEq)]
pub struct AnnotationElement {
    pub name_idx: uleb128,
    pub value: EncodedValue,
}

impl DexStruct for AnnotationElement {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let name_idx = decode_uleb128(r);
        let value = EncodedValue::deserialize(r);
        return Self { name_idx, value };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_uleb128(w, self.name_idx);
        self.value.serialize(w);
    }

    fn size(&self) -> usize {
        size_uleb128(self.name_idx) + self.value.size()
    }
}

#[derive(Debug, PartialEq)]
pub struct HiddenapiClassDataItem {
    pub size: u32,
    pub offsets: Vec<u32>,
    pub flags: Vec<uleb128>,
}

impl DexStruct for HiddenapiClassDataItem {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(_r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        unimplemented!("hope this never happens lol")
    }

    fn serialize<W>(&self, _w: &mut W)
    where
        W: io::Write,
    {
        unimplemented!("hope this never happens lol")
    }

    fn size(&self) -> usize {
        unimplemented!("hope this never happens lol")
    }
}

#[derive(Debug, PartialEq)]
pub struct MapList {
    pub list: Vec<MapItem>,
}
impl MapList {
    pub fn get(&self, type_code: TypeCode) -> Option<MapItem> {
        return self
            .list
            .iter()
            .filter(|item| item.type_code == type_code)
            .map(|item| *item)
            .last();
    }
}

impl DexStruct for MapList {
    const ALIGNMENT: u64 = 4;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let size = decode_u32(r);
        let list = (0..size).map(|_| MapItem::deserialize(r)).collect();
        return Self { list };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u32(w, self.list.len() as u32);
        for map_item in self.list.iter() {
            map_item.serialize(w);
        }
    }

    fn size(&self) -> usize {
        4 + 12 * self.list.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MapItem {
    pub type_code: TypeCode,
    pub unused: u16,
    pub size: u32,
    pub offset: u32,
}

impl DexStruct for MapItem {
    const ALIGNMENT: u64 = 1;

    fn deserialize<R>(r: &mut R) -> Self
    where
        R: io::Read + io::BufRead,
    {
        let type_code = unsafe {
            let num = decode_u16(r);
            std::mem::transmute::<u16, TypeCode>(num)
        };
        let unused = decode_u16(r);
        let size = decode_u32(r);
        let offset = decode_u32(r);
        return Self {
            type_code,
            unused,
            size,
            offset,
        };
    }

    fn serialize<W>(&self, w: &mut W)
    where
        W: io::Write,
    {
        encode_u16(w, self.type_code as u16);
        encode_u16(w, self.unused);
        encode_u32(w, self.size);
        encode_u32(w, self.offset);
    }

    fn size(&self) -> usize {
        12
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(u16)]
pub enum TypeCode {
    TypeHeaderItem = 0x0000,
    TypeStringIdItem = 0x0001,
    TypeTypeIdItem = 0x0002,
    TypeProtoIdItem = 0x0003,
    TypeFieldIdItem = 0x0004,
    TypeMethodIdItem = 0x0005,
    TypeClassDefItem = 0x0006,
    TypeCallSiteIdItem = 0x0007,
    TypeMethodHandleItem = 0x0008,
    TypeMapList = 0x1000,
    TypeTypeList = 0x1001,
    TypeAnnotationSetRefList = 0x1002,
    TypeAnnotationSetItem = 0x1003,
    TypeClassDataItem = 0x2000,
    TypeCodeItem = 0x2001,
    TypeStringDataItem = 0x2002,
    TypeDebugInfoItem = 0x2003,
    TypeAnnotationItem = 0x2004,
    TypeEncodedArrayItem = 0x2005,
    TypeAnnotationsDirectoryItem = 0x2006,
    TypeHiddenapiClassDataItem = 0xF000,
}
