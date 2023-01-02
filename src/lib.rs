use std::{
    array::TryFromSliceError,
    fs::File,
    io::{self, BufReader, Read},
    mem::{self},
};

#[allow(non_camel_case_types)]
type uleb128 = u32;
#[allow(non_camel_case_types)]
type sleb128 = u32;
#[allow(non_camel_case_types)]
type uleb128p1 = u32;

#[derive(Debug)]
pub enum DeserializeError {
    UnknownError,
    FileOpenError(io::Error),
    ArrayFromSliceMismatch(TryFromSliceError),
}

impl From<io::Error> for DeserializeError {
    fn from(err: io::Error) -> Self {
        DeserializeError::FileOpenError(err)
    }
}

impl From<TryFromSliceError> for DeserializeError {
    fn from(err: TryFromSliceError) -> Self {
        DeserializeError::ArrayFromSliceMismatch(err)
    }
}

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
#[repr(C)]
pub struct EncodedArrayItem {
    pub value: EncodedArray,
}

#[derive(Debug)]
#[repr(C)]
pub struct EncodedArray {
    pub size: uleb128,
    pub values: Vec<EncodedValue>,
}

#[derive(Debug)]
#[repr(C)]
pub struct EncodedValue {
    pub value_arg: u8,
    pub value: Vec<u8>,
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

#[derive(Debug)]
#[repr(C)]
pub struct EncodedField {
    pub field_idx_off: uleb128,
    pub access_flags: uleb128,
}

#[derive(Debug)]
#[repr(C)]
pub struct EncodedMethod {
    pub method_idx_off: uleb128,
    pub access_flags: uleb128,
    pub code_off: uleb128,
}

#[derive(Debug)]
#[repr(C)]
pub struct TypeList {
    pub size: u32,
    pub list: Vec<TypeItem>,
}

#[derive(Debug)]
#[repr(C)]
pub struct TypeItem {
    pub type_idx: u16,
}

#[derive(Debug)]
#[repr(C)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    pub insns: Vec<u16>,
    pub tries: Vec<TryItem>,
    pub handlers: Vec<EncodedCatchHandlerList>,
}

#[derive(Debug)]
#[repr(C)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

#[derive(Debug)]
#[repr(C)]
pub struct EncodedCatchHandlerList {
    pub size: uleb128,
    pub list: Vec<EncodedCatchHandler>,
}

#[derive(Debug)]
#[repr(C)]
pub struct EncodedCatchHandler {
    pub size: sleb128,
    pub handlers: Vec<EncodedTypeAddressPair>,
    pub catch_all_addr: uleb128,
}

#[derive(Debug)]
#[repr(C)]
pub struct EncodedTypeAddressPair {
    pub type_idx: uleb128,
    pub addr: uleb128,
}

#[derive(Debug)]
#[repr(C)]
pub struct DebugInfoItem {
    pub line_start: uleb128,
    pub parameters_size: uleb128,
    pub parameter_names: Vec<uleb128p1>,
    pub bytecode: Vec<u8>,
}

#[derive(Debug)]
#[repr(C)]
pub struct AnnotationsDirectoryItem {
    pub class_annotations_off: u32,
    pub fields_size: u32,
    pub annotated_methods_size: u32,
    pub annotated_parameters_size: u32,
    pub field_annotations: Vec<FieldAnnotation>,
    pub method_annotations: Vec<MethodAnnotation>,
    pub parameter_annotations: Vec<ParameterAnnotation>,
}

#[derive(Debug)]
#[repr(C)]
pub struct FieldAnnotation {
    pub field_idx: u32,
    pub annotations_off: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct MethodAnnotation {
    pub method_idx: u32,
    pub annotations_off: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct ParameterAnnotation {
    pub method_idx: u32,
    pub annotations_off: u32,
}

#[derive(Debug)]
#[repr(C)]
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
#[repr(C)]
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
#[repr(C)]
pub struct AnnotationItem {
    pub visibility: u8,
    pub annotation: EncodedAnnotation,
}

#[derive(Debug)]
#[repr(C)]
pub struct EncodedAnnotation {
    pub type_idx: uleb128,
    pub size: uleb128,
    pub elements: Vec<AnnotationElement>,
}

#[derive(Debug)]
#[repr(C)]
pub struct AnnotationElement {
    pub name_idx: uleb128,
    pub value: EncodedValue,
}

#[derive(Debug)]
#[repr(C)]
pub struct HiddenapiClassDataItem {
    pub size: u32,
    pub offsets: Vec<u32>,
    pub flags: Vec<uleb128>,
}

#[derive(Debug)]
#[repr(C)]
pub struct MapList {
    pub size: u32,
    pub list: Vec<MapItem>,
}

#[derive(Debug)]
#[repr(C)]
pub struct MapItem {
    pub type_code: TypeCode,
    pub unused: u16,
    pub size: u32,
    pub offset: u32,
}

#[derive(Debug, PartialEq)]
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

#[derive(Debug)]
#[repr(C)]
pub struct DexFile {
    pub header: Header,
    pub string_ids: Vec<StringIdItem>,
    pub type_ids: Vec<TypeIdItem>,
    pub proto_ids: Vec<ProtoIdItem>,
    pub field_ids: Vec<FieldIdItem>,
    pub method_ids: Vec<MethodIdItem>,
    pub class_defs: Vec<ClassDefItem>,
    pub call_site_ids: Vec<CallSiteIdItem>,
    pub method_handles: Vec<MethodHandleItem>,
    pub data: Vec<u8>, // TODO: Flesh this out.
    pub link_data: Vec<u8>,
}

macro_rules! transmute_dex_struct {
    ($t:ty,$b:expr,$i:expr) => {{
        let old_i: usize = $i;
        $i += mem::size_of::<$t>();
        let arr: [u8; mem::size_of::<$t>()] =
            $b[old_i..(old_i + mem::size_of::<$t>())].try_into()?;
        unsafe {
            Ok::<$t, DeserializeError>(std::mem::transmute::<[u8; mem::size_of::<$t>()], $t>(arr))
        }
    }};
}

macro_rules! transmute_dex_value {
    ($t:ty,$b:expr,$i:expr) => {{
        let arr: [u8; mem::size_of::<$t>()] =
            $b[($i as usize)..($i as usize + mem::size_of::<$t>())].try_into()?;
        unsafe {
            Ok::<$t, DeserializeError>(std::mem::transmute::<[u8; mem::size_of::<$t>()], $t>(arr))
        }
    }};
}

macro_rules! reverse_transmute_dex_struct {
    ($t:ty,$struct:expr) => {{
        unsafe { std::mem::transmute::<$t, [u8; mem::size_of::<$t>()]>($struct).to_vec() }
    }};
}

pub fn deserialize(filepath: String) -> Result<DexFile, DeserializeError> {
    let file = File::open(filepath)?;
    let reader = BufReader::new(file);

    let mut i = 0;
    let bytes: Vec<u8> = reader.bytes().collect::<Result<Vec<u8>, io::Error>>()?;
    let header = transmute_dex_struct!(Header, bytes, i)?;

    let string_ids = (0..header.string_ids_size)
        .map(|_| transmute_dex_struct!(StringIdItem, bytes, i))
        .collect::<Result<Vec<StringIdItem>, DeserializeError>>()?;

    let type_ids = (0..header.type_ids_size)
        .map(|_| transmute_dex_struct!(TypeIdItem, bytes, i))
        .collect::<Result<Vec<TypeIdItem>, DeserializeError>>()?;

    let proto_ids = (0..header.proto_ids_size)
        .map(|_| transmute_dex_struct!(ProtoIdItem, bytes, i))
        .collect::<Result<Vec<ProtoIdItem>, DeserializeError>>()?;

    let field_ids = (0..header.field_ids_size)
        .map(|_| transmute_dex_struct!(FieldIdItem, bytes, i))
        .collect::<Result<Vec<FieldIdItem>, DeserializeError>>()?;

    let method_ids = (0..header.method_ids_size)
        .map(|_| transmute_dex_struct!(MethodIdItem, bytes, i))
        .collect::<Result<Vec<MethodIdItem>, DeserializeError>>()?;

    let class_defs = (0..header.class_defs_size)
        .map(|_| transmute_dex_struct!(ClassDefItem, bytes, i))
        .collect::<Result<Vec<ClassDefItem>, DeserializeError>>()?;

    let map_list_size = transmute_dex_value!(u32, bytes, header.map_off)?;
    let mut map_list_idx = header.map_off as usize + 4;
    let map_list = MapList {
        size: map_list_size,
        list: (0..map_list_size)
            .map(|_| transmute_dex_struct!(MapItem, bytes, map_list_idx))
            .collect::<Result<Vec<MapItem>, DeserializeError>>()?,
    };

    let call_site_ids;
    if let Some(call_site_ids_map_item) = map_list
        .list
        .iter()
        .filter(|mi| mi.type_code == TypeCode::TypeCallSiteIdItem)
        .last()
    {
        call_site_ids = (0..call_site_ids_map_item.size)
            .map(|_| transmute_dex_struct!(CallSiteIdItem, bytes, i))
            .collect::<Result<Vec<CallSiteIdItem>, DeserializeError>>()?;
    } else {
        call_site_ids = vec![];
    }

    let method_handles;
    if let Some(method_handles_map_item) = map_list
        .list
        .iter()
        .filter(|mi| mi.type_code == TypeCode::TypeMethodHandleItem)
        .last()
    {
        method_handles = (0..method_handles_map_item.size)
            .map(|_| transmute_dex_struct!(MethodHandleItem, bytes, i))
            .collect::<Result<Vec<MethodHandleItem>, DeserializeError>>()?;
    } else {
        method_handles = vec![];
    }

    let data = bytes[i..(i + header.data_size as usize)].to_vec();

    let link_data =
        bytes[header.link_off as usize..(header.link_off + header.link_size) as usize].to_vec();

    return Ok(DexFile {
        header,
        string_ids,
        type_ids,
        proto_ids,
        field_ids,
        method_ids,
        class_defs,
        call_site_ids,
        method_handles,
        data,
        link_data,
    });
}

pub fn serialize(dex: DexFile) -> Vec<u8> {
    let mut serialized = vec![];
    serialized.extend(reverse_transmute_dex_struct!(Header, dex.header));

    for string_id in dex.string_ids {
        serialized.extend(reverse_transmute_dex_struct!(StringIdItem, string_id));
    }

    for type_id in dex.type_ids {
        serialized.extend(reverse_transmute_dex_struct!(TypeIdItem, type_id));
    }

    for proto_id in dex.proto_ids {
        serialized.extend(reverse_transmute_dex_struct!(ProtoIdItem, proto_id));
    }

    for field_id in dex.field_ids {
        serialized.extend(reverse_transmute_dex_struct!(FieldIdItem, field_id));
    }

    for method_id in dex.method_ids {
        serialized.extend(reverse_transmute_dex_struct!(MethodIdItem, method_id));
    }

    for class_def in dex.class_defs {
        serialized.extend(reverse_transmute_dex_struct!(ClassDefItem, class_def));
    }

    for call_site_id in dex.call_site_ids {
        serialized.extend(reverse_transmute_dex_struct!(CallSiteIdItem, call_site_id));
    }

    for method_handles in dex.method_handles {
        serialized.extend(reverse_transmute_dex_struct!(
            MethodHandleItem,
            method_handles
        ));
    }

    serialized.extend(dex.data);
    serialized.extend(dex.link_data);

    return serialized;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        if let Err(DeserializeError::FileOpenError(io_err)) = deserialize("".to_string()) {
            // "No such file or directory" error.
            assert_eq!(io_err.raw_os_error().unwrap(), 2);
        } else {
            unreachable!()
        }
    }
}
