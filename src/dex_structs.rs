use std::{io, vec};

use crate::{
    decode::{
        decode_i8, decode_nbytes_as_f32, decode_nbytes_as_f64, decode_nbytes_signed,
        decode_nbytes_unsigned, decode_sleb128, decode_u16, decode_u32, decode_u8, decode_uleb128,
        decode_uleb128p1,
    },
    sleb128, uleb128, uleb128p1,
};

#[derive(Clone, Copy, Debug)]
#[repr(C)]
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

#[derive(Debug)]
#[repr(C)]
pub struct StringIdItem {
    pub string_data_off: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct StringDataItem {
    pub utf16_size: uleb128,
    pub data: Vec<u8>,
}

#[derive(Debug)]
#[repr(C)]
pub struct TypeIdItem {
    pub descriptor_idx: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct ProtoIdItem {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct FieldIdItem {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct MethodIdItem {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug)]
#[repr(C)]
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

#[derive(Debug)]
#[repr(C)]
pub struct CallSiteIdItem {
    pub call_site_off: u32,
}

pub type CallSiteItem = EncodedArrayItem;

#[derive(Debug)]
pub struct EncodedArrayItem {
    pub value: EncodedArray,
}

#[derive(Debug)]
pub struct EncodedArray {
    pub values: Vec<EncodedValue>,
}

impl EncodedArray {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        let size = decode_uleb128(r);
        let mut values = vec![];
        for _ in 0..size {
            values.push(EncodedValue::deserialize(r));
        }
        return Self { values };
    }
}

#[derive(Debug)]
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
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        // TODO: can this be serialized by assuming optimal packing?
        // E.g. for ValueDouble, shave off as many 0's to the right as you can.
        let value_byte = decode_u8(r);
        let value_arg = ((value_byte & 0b11100000) >> 5) as usize;
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
}

#[derive(Debug)]
#[repr(C)]
pub struct MethodHandleItem {
    pub method_handle_type: u16,
    pub unused1: u16,
    pub field_or_method_id: u16,
    pub unused2: u16,
}

#[derive(Debug)]
#[repr(C)]
pub struct ClassDataItem {
    pub static_fields_size: uleb128,
    pub instance_fields_size: uleb128,
    pub direct_methods_size: uleb128,
    pub virtual_methods_size: uleb128,
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

impl ClassDataItem {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
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
            static_fields_size,
            instance_fields_size,
            direct_methods_size,
            virtual_methods_size,
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
        };
    }
}

#[derive(Debug)]
pub struct EncodedField {
    pub field_idx_off: uleb128,
    pub access_flags: uleb128,
}

impl EncodedField {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        let field_idx_off = decode_uleb128(r);
        let access_flags = decode_uleb128(r);
        return Self {
            field_idx_off,
            access_flags,
        };
    }
}

#[derive(Debug)]
pub struct EncodedMethod {
    pub method_idx_off: uleb128,
    pub access_flags: uleb128,
    pub code_off: uleb128,
}

impl EncodedMethod {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
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
}

#[derive(Debug)]
pub struct TypeList {
    pub size: u32,
    pub list: Vec<TypeItem>,
}

impl TypeList {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        let size = decode_u32(r);
        let list = (0..size).map(|_| TypeItem::deserialize(r)).collect();
        return Self { size, list };
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct TypeItem {
    pub type_idx: u16,
}

impl TypeItem {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        return Self {
            type_idx: decode_u16(r),
        };
    }
}

#[derive(Debug)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    pub insns: Vec<u16>,
    pub tries: Vec<TryItem>,
    pub handlers: Option<EncodedCatchHandlerList>,
}

impl CodeItem {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read + io::Seek,
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
            insns_size,
            insns,
            tries,
            handlers,
        };
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

impl TryItem {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
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
}

#[derive(Debug)]
pub struct EncodedCatchHandlerList {
    pub list: Vec<EncodedCatchHandler>,
}

impl EncodedCatchHandlerList {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read + io::Seek,
    {
        let size = decode_uleb128(r);
        let list = (0..size)
            .map(|_| EncodedCatchHandler::deserialize(r))
            .collect();
        return Self { list };
    }
}

#[derive(Debug)]
pub struct EncodedCatchHandler {
    pub size: sleb128,
    pub handlers: Vec<EncodedTypeAddressPair>,
    pub catch_all_addr: Option<uleb128>,
}

impl EncodedCatchHandler {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read + io::Seek,
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
            size,
            handlers,
            catch_all_addr,
        };
    }
}

#[derive(Debug)]
pub struct EncodedTypeAddressPair {
    pub type_idx: uleb128,
    pub addr: uleb128,
}

impl EncodedTypeAddressPair {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        let type_idx = decode_uleb128(r);
        let addr = decode_uleb128(r);
        return Self { type_idx, addr };
    }
}

#[derive(Debug)]
pub struct DebugInfoItem {
    pub line_start: uleb128,
    pub parameter_names: Vec<uleb128p1>,
    pub bytecode: Vec<u8>,
}

impl DebugInfoItem {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read + io::BufRead,
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
}

#[derive(Debug)]
pub struct AnnotationsDirectoryItem {
    pub class_annotations_off: u32,
    pub fields_size: u32,
    pub annotated_methods_size: u32,
    pub annotated_parameters_size: u32,
    pub field_annotations: Vec<FieldAnnotation>,
    pub method_annotations: Vec<MethodAnnotation>,
    pub parameter_annotations: Vec<ParameterAnnotation>,
}

impl AnnotationsDirectoryItem {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
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
            fields_size,
            annotated_methods_size,
            annotated_parameters_size,
            field_annotations,
            method_annotations,
            parameter_annotations,
        };
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct FieldAnnotation {
    pub field_idx: u32,
    pub annotations_off: u32,
}

impl FieldAnnotation {
    pub fn deserialize<R>(r: &mut R) -> Self
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
}

#[derive(Debug)]
#[repr(C)]
pub struct MethodAnnotation {
    pub method_idx: u32,
    pub annotations_off: u32,
}

impl MethodAnnotation {
    pub fn deserialize<R>(r: &mut R) -> Self
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
}

#[derive(Debug)]
#[repr(C)]
pub struct ParameterAnnotation {
    pub method_idx: u32,
    pub annotations_off: u32,
}

impl ParameterAnnotation {
    pub fn deserialize<R>(r: &mut R) -> Self
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
}

#[derive(Debug)]
pub struct AnnotationSetRefList {
    pub size: u32,
    pub list: Vec<AnnotationSetRefItem>,
}

#[derive(Debug)]
#[repr(C)]
pub struct AnnotationSetRefItem {
    pub annotations_off: u32,
}

#[derive(Debug)]
pub struct AnnotationSetItem {
    pub size: u32,
    pub entries: Vec<AnnotationOffItem>,
}

#[derive(Debug)]
#[repr(C)]
pub struct AnnotationOffItem {
    pub annotation_off: u32,
}

#[derive(Debug)]
pub struct AnnotationItem {
    pub visibility: u8,
    pub annotation: EncodedAnnotation,
}

#[derive(Debug)]
pub struct EncodedAnnotation {
    pub type_idx: uleb128,
    pub elements: Vec<AnnotationElement>,
}

impl EncodedAnnotation {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        let type_idx = decode_uleb128(r);
        let size = decode_uleb128(r);
        let mut elements = vec![];
        for _ in 0..size {
            elements.push(AnnotationElement::deserialize(r));
        }
        return Self { type_idx, elements };
    }
}

#[derive(Debug)]
pub struct AnnotationElement {
    pub name_idx: uleb128,
    pub value: EncodedValue,
}

impl AnnotationElement {
    pub fn deserialize<R>(r: &mut R) -> Self
    where
        R: ?Sized + io::Read,
    {
        let name_idx = decode_uleb128(r);
        let value = EncodedValue::deserialize(r);
        return Self { name_idx, value };
    }
}

#[derive(Debug)]
pub struct HiddenapiClassDataItem {
    pub size: u32,
    pub offsets: Vec<u32>,
    pub flags: Vec<uleb128>,
}

#[derive(Debug)]
pub struct MapList {
    pub size: u32,
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

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MapItem {
    pub type_code: TypeCode,
    pub unused: u16,
    pub size: u32,
    pub offset: u32,
}

#[derive(Debug, PartialEq, Clone, Copy)]
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
    TypeTypeList = 0x1001,             // done
    TypeAnnotationSetRefList = 0x1002, // done
    TypeAnnotationSetItem = 0x1003,    // done
    TypeClassDataItem = 0x2000,        // done
    TypeCodeItem = 0x2001,
    TypeStringDataItem = 0x2002,           // done
    TypeDebugInfoItem = 0x2003,            // done
    TypeAnnotationItem = 0x2004,           // done
    TypeEncodedArrayItem = 0x2005,         // done
    TypeAnnotationsDirectoryItem = 0x2006, // done
    TypeHiddenapiClassDataItem = 0xF000,   // done
}
