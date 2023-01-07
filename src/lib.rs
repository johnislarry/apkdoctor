use std::{
    array::TryFromSliceError,
    fmt::Debug,
    fs::File,
    io::{self, BufRead, BufReader, Cursor, Read},
    mem::{self},
};

use decode::{decode_u16, decode_u8, decode_uleb128};
use dex_structs::{
    AnnotationItem, AnnotationOffItem, AnnotationSetItem, AnnotationSetRefItem,
    AnnotationSetRefList, AnnotationsDirectoryItem, CallSiteIdItem, ClassDataItem, ClassDefItem,
    CodeItem, DebugInfoItem, EncodedAnnotation, EncodedArray, EncodedArrayItem, FieldIdItem,
    Header, HiddenapiClassDataItem, MapItem, MapList, MethodHandleItem, MethodIdItem, ProtoIdItem,
    StringDataItem, StringIdItem, TypeCode, TypeIdItem, TypeItem, TypeList,
};

use crate::decode::decode_u32;

mod decode;
mod dex_structs;

#[allow(non_camel_case_types)]
type uleb128 = u32;
#[allow(non_camel_case_types)]
type sleb128 = i32;
#[allow(non_camel_case_types)]
type uleb128p1 = i32;

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
    pub data: Vec<u8>,
    pub type_lists: Vec<TypeList>,
    pub string_data_items: Vec<StringDataItem>,
    pub annotation_set_ref_lists: Vec<AnnotationSetRefList>,
    pub annotation_set_items: Vec<AnnotationSetItem>,
    pub annotation_items: Vec<AnnotationItem>,
    pub annotations_directory_items: Vec<AnnotationsDirectoryItem>,
    pub hiddenapi_class_data_items: Vec<HiddenapiClassDataItem>,
    pub encoded_array_items: Vec<EncodedArrayItem>,
    pub class_data_items: Vec<ClassDataItem>,
    pub debug_info_items: Vec<DebugInfoItem>,
    pub code_items: Vec<CodeItem>,
    pub link_data: Vec<u8>,
    pub map_list: MapList,
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

fn deserialize_string_data_items(
    map_item: MapItem,
    bytes: &Vec<u8>,
) -> Result<Vec<StringDataItem>, DeserializeError> {
    let MapItem { size, offset, .. } = map_item;
    // let size = map_item.size;
    // let offset = map_item.offset;
    let mut string_data_items = vec![];
    let mut cursor = Cursor::new(bytes);
    cursor.set_position(offset as u64);

    for _ in 0..size {
        let item_size = decode_uleb128(&mut cursor) as usize;
        let mut buf = vec![];
        cursor.read_until(0, &mut buf)?;

        // https://android.googlesource.com/platform/libcore/+/9edf43dfcc35c761d97eb9156ac4254152ddbc55/dex/src/main/java/com/android/dex/Mutf8.java
        // let x = mutf8::decode(&buf).unwrap().to_string();

        string_data_items.push(StringDataItem {
            utf16_size: item_size as u32,
            data: buf,
        });
    }
    return Ok(string_data_items);
}

fn deserialize_type_lists(
    map_item: MapItem,
    bytes: &Vec<u8>,
) -> Result<Vec<TypeList>, DeserializeError> {
    let MapItem { size, offset, .. } = map_item;
    let mut type_lists = vec![];
    let mut cursor = Cursor::new(bytes);
    cursor.set_position(offset as u64);

    for _ in 0..size {
        let initial_position = cursor.position();
        let list_size = decode_u32(&mut cursor);

        let mut type_items = vec![];
        for _ in 0..list_size {
            type_items.push(TypeItem {
                type_idx: decode_u16(&mut cursor),
            });
        }

        type_lists.push(TypeList {
            size: list_size,
            list: type_items,
        });

        // Ensure 4 byte alignment by burning off 2 bytes when needed.
        if (cursor.position() - initial_position) % 4 != 0 {
            assert!(decode_u16(&mut cursor) == 0);
        }
    }
    return Ok(type_lists);
}

fn deserialize_annotation_set_ref_lists(
    map_item: MapItem,
    bytes: &Vec<u8>,
) -> Result<Vec<AnnotationSetRefList>, DeserializeError> {
    let MapItem { size, offset, .. } = map_item;
    let mut annotation_set_ref_lists = vec![];
    let mut cursor = Cursor::new(bytes);
    cursor.set_position(offset as u64);

    for _ in 0..size {
        let list_size = decode_u32(&mut cursor);

        let mut items = vec![];
        for _ in 0..list_size {
            items.push(AnnotationSetRefItem {
                annotations_off: decode_u32(&mut cursor),
            });
        }

        annotation_set_ref_lists.push(AnnotationSetRefList {
            size: list_size,
            list: items,
        });
    }
    return Ok(annotation_set_ref_lists);
}

fn deserialize_annotation_set_items(
    map_item: MapItem,
    bytes: &Vec<u8>,
) -> Result<Vec<AnnotationSetItem>, DeserializeError> {
    let MapItem { size, offset, .. } = map_item;
    let mut annotation_set_items = vec![];
    let mut cursor = Cursor::new(bytes);
    cursor.set_position(offset as u64);

    for _ in 0..size {
        let set_size = decode_u32(&mut cursor);

        let mut items = vec![];
        for _ in 0..set_size {
            items.push(AnnotationOffItem {
                annotation_off: decode_u32(&mut cursor),
            });
        }

        annotation_set_items.push(AnnotationSetItem {
            size: set_size,
            entries: items,
        });
    }
    return Ok(annotation_set_items);
}

fn deserialize_annotation_items(
    map_item: MapItem,
    bytes: &Vec<u8>,
) -> Result<Vec<AnnotationItem>, DeserializeError> {
    let MapItem { size, offset, .. } = map_item;
    let mut annotation_items = vec![];
    let mut cursor = Cursor::new(bytes);
    cursor.set_position(offset as u64);

    for _ in 0..size {
        let visibility = decode_u8(&mut cursor);
        let annotation = EncodedAnnotation::deserialize(&mut cursor);
        annotation_items.push(AnnotationItem {
            visibility,
            annotation,
        });
    }
    return Ok(annotation_items);
}

fn deserialize_encoded_array_items(
    map_item: MapItem,
    bytes: &Vec<u8>,
) -> Result<Vec<EncodedArrayItem>, DeserializeError> {
    let MapItem { size, offset, .. } = map_item;
    let mut encoded_array_items = vec![];
    let mut cursor = Cursor::new(bytes);
    cursor.set_position(offset as u64);

    for _ in 0..size {
        let value = EncodedArray::deserialize(&mut cursor);
        encoded_array_items.push(EncodedArrayItem { value });
    }
    return Ok(encoded_array_items);
}

fn deserialize_annotations_directory_items(
    map_item: MapItem,
    bytes: &Vec<u8>,
) -> Result<Vec<AnnotationsDirectoryItem>, DeserializeError> {
    let MapItem { size, offset, .. } = map_item;
    let mut annotations_directory_items = vec![];
    let mut cursor = Cursor::new(bytes);
    cursor.set_position(offset as u64);

    for _ in 0..size {
        annotations_directory_items.push(AnnotationsDirectoryItem::deserialize(&mut cursor));
    }
    return Ok(annotations_directory_items);
}

fn deserialize_class_data_items(
    map_item: MapItem,
    bytes: &Vec<u8>,
) -> Result<Vec<ClassDataItem>, DeserializeError> {
    let MapItem { size, offset, .. } = map_item;
    let mut class_data_items = vec![];
    let mut cursor = Cursor::new(bytes);
    cursor.set_position(offset as u64);

    for _ in 0..size {
        class_data_items.push(ClassDataItem::deserialize(&mut cursor));
    }
    return Ok(class_data_items);
}

fn deserialize_debug_info_items(
    map_item: MapItem,
    bytes: &Vec<u8>,
) -> Result<Vec<DebugInfoItem>, DeserializeError> {
    let MapItem { size, offset, .. } = map_item;
    let mut debug_info_items = vec![];
    let mut cursor = Cursor::new(bytes);
    cursor.set_position(offset as u64);

    for _ in 0..size {
        debug_info_items.push(DebugInfoItem::deserialize(&mut cursor));
    }
    return Ok(debug_info_items);
}

fn deserialize_code_items(
    map_item: MapItem,
    bytes: &Vec<u8>,
) -> Result<Vec<CodeItem>, DeserializeError> {
    let MapItem { size, offset, .. } = map_item;
    let mut code_items = vec![];
    let mut cursor = Cursor::new(bytes);
    cursor.set_position(offset as u64);

    for _ in 0..size {
        code_items.push(CodeItem::deserialize(&mut cursor));

        // Ensure 4 byte alignment by burning off bytes when needed.
        while cursor.position() % 4 != 0 {
            decode_u8(&mut cursor);
        }
    }
    return Ok(code_items);
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

    let string_data_items = match map_list.get(TypeCode::TypeStringDataItem) {
        Some(map_item) => deserialize_string_data_items(map_item, &bytes)?,
        None => vec![],
    };

    let type_lists = match map_list.get(TypeCode::TypeTypeList) {
        Some(map_item) => deserialize_type_lists(map_item, &bytes)?,
        None => vec![],
    };

    let annotation_set_ref_lists = match map_list.get(TypeCode::TypeAnnotationSetRefList) {
        Some(map_item) => deserialize_annotation_set_ref_lists(map_item, &bytes)?,
        None => vec![],
    };

    let annotation_set_items = match map_list.get(TypeCode::TypeAnnotationSetItem) {
        Some(map_item) => deserialize_annotation_set_items(map_item, &bytes)?,
        None => vec![],
    };

    let annotation_items = match map_list.get(TypeCode::TypeAnnotationItem) {
        Some(map_item) => deserialize_annotation_items(map_item, &bytes)?,
        None => vec![],
    };

    let annotations_directory_items = match map_list.get(TypeCode::TypeAnnotationsDirectoryItem) {
        Some(map_item) => deserialize_annotations_directory_items(map_item, &bytes)?,
        None => vec![],
    };

    let hiddenapi_class_data_items = match map_list.get(TypeCode::TypeHiddenapiClassDataItem) {
        Some(_) => unimplemented!("hope this never happens lol"),
        None => vec![],
    };

    let encoded_array_items = match map_list.get(TypeCode::TypeEncodedArrayItem) {
        Some(map_item) => deserialize_encoded_array_items(map_item, &bytes)?,
        None => vec![],
    };

    let class_data_items = match map_list.get(TypeCode::TypeClassDataItem) {
        Some(map_item) => deserialize_class_data_items(map_item, &bytes)?,
        None => vec![],
    };

    let debug_info_items = match map_list.get(TypeCode::TypeDebugInfoItem) {
        Some(map_item) => deserialize_debug_info_items(map_item, &bytes)?,
        None => vec![],
    };

    let code_items = match map_list.get(TypeCode::TypeCodeItem) {
        Some(map_item) => deserialize_code_items(map_item, &bytes)?,
        None => vec![],
    };

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
        string_data_items,
        type_lists,
        annotation_set_ref_lists,
        annotation_set_items,
        annotation_items,
        annotations_directory_items,
        hiddenapi_class_data_items,
        encoded_array_items,
        class_data_items,
        debug_info_items,
        code_items,
        link_data,
        map_list,
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
