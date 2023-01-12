use std::{
    array::TryFromSliceError,
    fmt::Debug,
    fs::File,
    io::{self, BufReader, Cursor, Read},
};

use decode::decode_u8;
use dex_model::{DexModel, DexModelBuilder};
use dex_structs::{
    AnnotationItem, AnnotationSetItem, AnnotationSetRefList, AnnotationsDirectoryItem,
    CallSiteIdItem, ClassDataItem, ClassDefItem, CodeItem, DebugInfoItem, DexStruct,
    EncodedArrayItem, FieldIdItem, Header, HiddenapiClassDataItem, MapItem, MapList,
    MethodHandleItem, MethodIdItem, ProtoIdItem, StringDataItem, StringIdItem, TypeCode,
    TypeIdItem, TypeList,
};
use encode::encode_u8;

mod decode;
pub mod dex_model;
pub mod dex_structs;
mod encode;
mod encoded_value_utils;
mod instructions;

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

fn deserialize_dex_section<T: DexStruct>(
    map_item: &MapItem,
    cursor: &mut Cursor<Vec<u8>>,
) -> Result<Vec<T>, DeserializeError> {
    let MapItem { size, offset, .. } = map_item;
    let mut items: Vec<T> = vec![];
    cursor.set_position(*offset as u64);

    for _ in 0..*size {
        items.push(T::deserialize(cursor));

        // Ensure alignment by burning off bytes when needed.
        while cursor.position() % T::ALIGNMENT != 0 {
            decode_u8(cursor);
        }
    }
    return Ok(items);
}

pub fn deserialize(filepath: String) -> Result<DexModel, DeserializeError> {
    let file = File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut cursor = Cursor::new(reader.bytes().collect::<Result<Vec<u8>, io::Error>>()?);

    let mut dex_model_builder = DexModelBuilder::new();

    let header = Header::deserialize(&mut cursor);
    dex_model_builder.set_header(header);
    cursor.set_position(header.map_off as u64);

    let map_list = MapList::deserialize(&mut cursor);

    for map_item in map_list.list.iter() {
        match map_item.type_code {
            TypeCode::TypeHeaderItem | TypeCode::TypeMapList => {
                // These structs were parsed earlier, no need to redo them.
                continue;
            }
            TypeCode::TypeStringIdItem => {
                dex_model_builder.set_string_ids(deserialize_dex_section::<StringIdItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeTypeIdItem => {
                dex_model_builder.set_type_ids(deserialize_dex_section::<TypeIdItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeProtoIdItem => {
                dex_model_builder.set_proto_ids(deserialize_dex_section::<ProtoIdItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeFieldIdItem => {
                dex_model_builder.set_field_ids(deserialize_dex_section::<FieldIdItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeMethodIdItem => {
                dex_model_builder.set_method_ids(deserialize_dex_section::<MethodIdItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeClassDefItem => {
                dex_model_builder.set_class_defs(deserialize_dex_section::<ClassDefItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeCallSiteIdItem => {
                dex_model_builder.set_call_site_ids(deserialize_dex_section::<CallSiteIdItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeMethodHandleItem => {
                dex_model_builder.set_method_handles(deserialize_dex_section::<MethodHandleItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeTypeList => {
                dex_model_builder
                    .set_type_lists(deserialize_dex_section::<TypeList>(map_item, &mut cursor)?);
            }
            TypeCode::TypeAnnotationSetRefList => {
                dex_model_builder.set_annotation_set_ref_lists(deserialize_dex_section::<
                    AnnotationSetRefList,
                >(
                    map_item, &mut cursor
                )?);
            }
            TypeCode::TypeAnnotationSetItem => {
                dex_model_builder.set_annotation_set_items(deserialize_dex_section::<
                    AnnotationSetItem,
                >(
                    map_item, &mut cursor
                )?);
            }
            TypeCode::TypeClassDataItem => {
                dex_model_builder.set_class_data_items(deserialize_dex_section::<ClassDataItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeCodeItem => {
                dex_model_builder
                    .set_code_items(deserialize_dex_section::<CodeItem>(map_item, &mut cursor)?);
            }
            TypeCode::TypeStringDataItem => {
                dex_model_builder.set_string_data_items(deserialize_dex_section::<StringDataItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeDebugInfoItem => {
                dex_model_builder.set_debug_info_items(deserialize_dex_section::<DebugInfoItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeAnnotationItem => {
                dex_model_builder.set_annotation_items(deserialize_dex_section::<AnnotationItem>(
                    map_item,
                    &mut cursor,
                )?);
            }
            TypeCode::TypeEncodedArrayItem => {
                dex_model_builder.set_encoded_array_items(deserialize_dex_section::<
                    EncodedArrayItem,
                >(map_item, &mut cursor)?);
            }
            TypeCode::TypeAnnotationsDirectoryItem => {
                dex_model_builder.set_annotations_directory_items(deserialize_dex_section::<
                    AnnotationsDirectoryItem,
                >(
                    map_item, &mut cursor
                )?);
            }
            TypeCode::TypeHiddenapiClassDataItem => {
                dex_model_builder.set_hiddenapi_class_data_items(deserialize_dex_section::<
                    HiddenapiClassDataItem,
                >(
                    map_item, &mut cursor
                )?);
            }
        }
    }

    // TODO: set link_data using header link_off/size

    dex_model_builder.set_map_list(map_list);

    return Ok(dex_model_builder.build());
}

fn serialize_dex_section<T: DexStruct>(
    map_item: &MapItem,
    section: &Vec<T>,
    cursor: &mut Cursor<Vec<u8>>,
) {
    let MapItem { offset, .. } = map_item;
    cursor.set_position(*offset as u64);

    for dex_struct in section {
        // Ensure alignment by padding bytes when needed.
        while cursor.position() % T::ALIGNMENT != 0 {
            encode_u8(cursor, 0);
        }

        dex_struct.serialize(cursor);
    }
}

pub fn serialize(dex: DexModel) -> Vec<u8> {
    let mut cursor = Cursor::new(vec![0u8; dex.header.file_size as usize]);
    dex.header.serialize(&mut cursor);

    cursor.set_position(dex.header.map_off as u64);
    dex.map_list.serialize(&mut cursor);

    for map_item in dex.map_list.list.iter() {
        match map_item.type_code {
            TypeCode::TypeHeaderItem | TypeCode::TypeMapList => {
                continue;
            }
            TypeCode::TypeStringIdItem => {
                serialize_dex_section::<StringIdItem>(map_item, &dex.string_ids, &mut cursor);
            }
            TypeCode::TypeTypeIdItem => {
                serialize_dex_section::<TypeIdItem>(map_item, &dex.type_ids, &mut cursor);
            }
            TypeCode::TypeProtoIdItem => {
                serialize_dex_section::<ProtoIdItem>(map_item, &dex.proto_ids, &mut cursor);
            }
            TypeCode::TypeFieldIdItem => {
                serialize_dex_section::<FieldIdItem>(map_item, &dex.field_ids, &mut cursor);
            }
            TypeCode::TypeMethodIdItem => {
                serialize_dex_section::<MethodIdItem>(map_item, &dex.method_ids, &mut cursor);
            }
            TypeCode::TypeClassDefItem => {
                serialize_dex_section::<ClassDefItem>(map_item, &dex.class_defs, &mut cursor);
            }
            TypeCode::TypeCallSiteIdItem => {
                serialize_dex_section::<CallSiteIdItem>(map_item, &dex.call_site_ids, &mut cursor);
            }
            TypeCode::TypeMethodHandleItem => {
                serialize_dex_section::<MethodHandleItem>(
                    map_item,
                    &dex.method_handles,
                    &mut cursor,
                );
            }
            TypeCode::TypeTypeList => {
                serialize_dex_section::<TypeList>(map_item, &dex.type_lists, &mut cursor);
            }
            TypeCode::TypeAnnotationSetRefList => {
                serialize_dex_section::<AnnotationSetRefList>(
                    map_item,
                    &dex.annotation_set_ref_lists,
                    &mut cursor,
                );
            }
            TypeCode::TypeAnnotationSetItem => {
                serialize_dex_section::<AnnotationSetItem>(
                    map_item,
                    &dex.annotation_set_items,
                    &mut cursor,
                );
            }
            TypeCode::TypeClassDataItem => {
                serialize_dex_section::<ClassDataItem>(
                    map_item,
                    &dex.class_data_items,
                    &mut cursor,
                );
            }
            TypeCode::TypeCodeItem => {
                serialize_dex_section::<CodeItem>(map_item, &dex.code_items, &mut cursor);
            }
            TypeCode::TypeStringDataItem => {
                serialize_dex_section::<StringDataItem>(
                    map_item,
                    &dex.string_data_items,
                    &mut cursor,
                );
            }
            TypeCode::TypeDebugInfoItem => {
                serialize_dex_section::<DebugInfoItem>(
                    map_item,
                    &dex.debug_info_items,
                    &mut cursor,
                );
            }
            TypeCode::TypeAnnotationItem => {
                serialize_dex_section::<AnnotationItem>(
                    map_item,
                    &dex.annotation_items,
                    &mut cursor,
                );
            }
            TypeCode::TypeEncodedArrayItem => {
                serialize_dex_section::<EncodedArrayItem>(
                    map_item,
                    &dex.encoded_array_items,
                    &mut cursor,
                );
            }
            TypeCode::TypeAnnotationsDirectoryItem => {
                serialize_dex_section::<AnnotationsDirectoryItem>(
                    map_item,
                    &dex.annotations_directory_items,
                    &mut cursor,
                );
            }
            TypeCode::TypeHiddenapiClassDataItem => {
                serialize_dex_section::<HiddenapiClassDataItem>(
                    map_item,
                    &dex.hiddenapi_class_data_items,
                    &mut cursor,
                );
            }
        }
    }

    return cursor.into_inner();
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
