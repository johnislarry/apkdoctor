use std::{
    fs::File,
    io::{self, BufReader, Cursor, Read, Write},
    os::unix::prelude::MetadataExt,
};

use apkdoctor::{
    self,
    dex_structs::{
        AnnotationItem, AnnotationSetItem, AnnotationSetRefList, AnnotationsDirectoryItem,
        CallSiteIdItem, ClassDataItem, ClassDefItem, CodeItem, DebugInfoItem, DexStruct,
        EncodedArrayItem, FieldIdItem, Header, MapList, MethodHandleItem, MethodIdItem,
        ProtoIdItem, StringDataItem, StringIdItem, TypeCode, TypeIdItem, TypeList,
    },
};

macro_rules! assert_struct_eq {
    ($typ:ty,$strct:expr) => {{
        let mut cursor = Cursor::new(vec![0u8; $strct.size()]);
        $strct.serialize(&mut cursor);
        cursor.set_position(0);
        dbg!(&$strct);
        let new_strct = <$typ>::deserialize(&mut cursor);
        assert_eq!($strct, new_strct);
    }};
}

macro_rules! assert_section_eq {
    ($typ:ty,$section:expr) => {{
        for item in $section {
            assert_struct_eq!($typ, item);
        }
    }};
}

#[test]
fn test_deserialize_serialize_sections() {
    let filepath = "./tests/assets/classes.dex";
    let dex = apkdoctor::deserialize(filepath.to_string()).unwrap();

    assert_struct_eq!(Header, dex.header);
    assert_struct_eq!(MapList, dex.map_list);

    assert_section_eq!(StringIdItem, dex.string_ids);
    assert_section_eq!(TypeIdItem, dex.type_ids);
    assert_section_eq!(ProtoIdItem, dex.proto_ids);
    assert_section_eq!(FieldIdItem, dex.field_ids);
    assert_section_eq!(MethodIdItem, dex.method_ids);
    assert_section_eq!(ClassDefItem, dex.class_defs);
    assert_section_eq!(CallSiteIdItem, dex.call_site_ids);
    assert_section_eq!(MethodHandleItem, dex.method_handles);
    assert_section_eq!(TypeList, dex.type_lists);
    assert_section_eq!(StringDataItem, dex.string_data_items);
    assert_section_eq!(AnnotationSetRefList, dex.annotation_set_ref_lists);
    assert_section_eq!(AnnotationSetItem, dex.annotation_set_items);
    assert_section_eq!(AnnotationItem, dex.annotation_items);
    assert_section_eq!(AnnotationsDirectoryItem, dex.annotations_directory_items);
    assert_section_eq!(EncodedArrayItem, dex.encoded_array_items);
    assert_section_eq!(ClassDataItem, dex.class_data_items);
    assert_section_eq!(DebugInfoItem, dex.debug_info_items);
    assert_section_eq!(CodeItem, dex.code_items);
}

#[test]
fn test_compare_serialized_annotation_item_sections() {
    let filepath = "./tests/assets/classes.dex";
    let dex = apkdoctor::deserialize(filepath.to_string()).unwrap();

    let file = File::open(filepath).unwrap();
    let reader = BufReader::new(file);
    let bytes = reader
        .bytes()
        .collect::<Result<Vec<u8>, io::Error>>()
        .unwrap();

    let (i, map_item) = dex
        .map_list
        .list
        .iter()
        .enumerate()
        .filter(|(_, x)| x.type_code == TypeCode::TypeAnnotationItem)
        .last()
        .unwrap();
    let start = map_item.offset as usize;
    let end = dex.map_list.list[i + 1].offset as usize;

    let mut serialized_cursor = Cursor::new(vec![0u8; end - start + 1]);

    let mut last_pos = 0;
    for anno_item in dex.annotation_items.iter() {
        anno_item.serialize(&mut serialized_cursor);
        let pos_so_far = serialized_cursor.position() as usize;
        let serialized_so_far = serialized_cursor.clone().into_inner();
        assert_eq!(
            bytes[(start + last_pos)..(start + pos_so_far)],
            serialized_so_far[last_pos..pos_so_far],
            "for {:?}",
            anno_item,
        );
        last_pos = pos_so_far;
    }
}

#[test]
fn test_compare_serialized_encoded_array_item_sections() {
    let filepath = "./tests/assets/classes.dex";
    let dex = apkdoctor::deserialize(filepath.to_string()).unwrap();

    let file = File::open(filepath).unwrap();
    let reader = BufReader::new(file);
    let bytes = reader
        .bytes()
        .collect::<Result<Vec<u8>, io::Error>>()
        .unwrap();

    let (i, map_item) = dex
        .map_list
        .list
        .iter()
        .enumerate()
        .filter(|(_, x)| x.type_code == TypeCode::TypeEncodedArrayItem)
        .last()
        .unwrap();
    let start = map_item.offset as usize;
    let end = dex.map_list.list[i + 1].offset as usize;

    let mut serialized_cursor = Cursor::new(vec![0u8; end - start + 1]);

    let mut last_pos = 0;
    for item in dex.encoded_array_items.iter() {
        item.serialize(&mut serialized_cursor);
        let pos_so_far = serialized_cursor.position() as usize;
        let serialized_so_far = serialized_cursor.clone().into_inner();
        assert_eq!(
            bytes[(start + last_pos)..(start + pos_so_far)],
            serialized_so_far[last_pos..pos_so_far],
            "for {:?}",
            item,
        );
        last_pos = pos_so_far;
    }
}

#[test]
fn test_compare_serialized_code_item_sections() {
    let filepath = "./tests/assets/classes.dex";
    let dex = apkdoctor::deserialize(filepath.to_string()).unwrap();

    let file = File::open(filepath).unwrap();
    let reader = BufReader::new(file);
    let bytes = reader
        .bytes()
        .collect::<Result<Vec<u8>, io::Error>>()
        .unwrap();

    let (i, map_item) = dex
        .map_list
        .list
        .iter()
        .enumerate()
        .filter(|(_, x)| x.type_code == TypeCode::TypeCodeItem)
        .last()
        .unwrap();
    let start = map_item.offset as usize;
    let end = dex.map_list.list[i + 1].offset as usize;

    let mut serialized_cursor = Cursor::new(vec![0u8; end - start + 1]);

    let mut last_pos = 0;
    let mut prev = &dex.code_items[0];
    for item in dex.code_items.iter() {
        // Ensure alignment by padding bytes when needed.
        while serialized_cursor.position() % CodeItem::ALIGNMENT != 0 {
            let buf = [0u8];
            serialized_cursor.write(&buf).unwrap();
        }
        item.serialize(&mut serialized_cursor);
        let pos_so_far = serialized_cursor.position() as usize;
        let serialized_so_far = serialized_cursor.clone().into_inner();
        assert_eq!(
            bytes[(start + last_pos)..(start + pos_so_far)],
            serialized_so_far[last_pos..pos_so_far],
            "for {:?} with prev {:?}",
            item,
            prev
        );
        last_pos = pos_so_far;
        prev = &item;
    }
}

#[test]
fn test_compare_serialized_sections() {
    let filepath = "./tests/assets/classes.dex";
    let dex = apkdoctor::deserialize(filepath.to_string()).unwrap();

    let file = File::open(filepath).unwrap();
    let reader = BufReader::new(file);
    let bytes = reader
        .bytes()
        .collect::<Result<Vec<u8>, io::Error>>()
        .unwrap();

    let mut ranges = vec![];
    for i in 0..(dex.map_list.list.len() - 1) {
        let off1 = dex.map_list.list[i];
        let off2 = dex.map_list.list[i + 1];
        ranges.push((off1.offset as usize, off2.offset as usize, off1.type_code));
    }

    let serialized = apkdoctor::serialize(dex);

    for r in ranges {
        assert_eq!(bytes[r.0..r.1], serialized[r.0..r.1], "for {:?}", r.2);
    }
}

#[test]
fn test_deserialize_serialize_length() {
    let filepath = "./tests/assets/classes.dex";
    let file = File::open(filepath).unwrap();
    let original_file_size = file.metadata().unwrap().size();
    let dex = apkdoctor::deserialize(filepath.to_string()).unwrap();
    let dex_len = dex.header.file_size;
    assert_eq!(dex_len as u64, original_file_size);
    let serialized = apkdoctor::serialize(dex);
    assert_eq!(dex_len as usize, serialized.len());
}

#[test]
fn test_deserialize_serialize_eq() {
    let filepath = "./tests/assets/classes.dex";
    let dex = apkdoctor::deserialize(filepath.to_string()).unwrap();
    assert!(dex.header.magic[0] == 0x64);
    assert!(dex.header.magic[1] == 0x65);
    assert!(dex.header.magic[2] == 0x78);
    assert!(dex.header.magic[6] == 0x38);
    assert!(dex.header.magic[7] == 0x00);

    let serialized = apkdoctor::serialize(dex);
    assert!(serialized[0] == 0x64);
    assert!(serialized[1] == 0x65);
    assert!(serialized[2] == 0x78);

    let file = File::open(filepath).unwrap();
    let reader = BufReader::new(file);
    let bytes = reader
        .bytes()
        .collect::<Result<Vec<u8>, io::Error>>()
        .unwrap();

    // Verify dex == serialize(deserialize(dex))
    assert_eq!(bytes, serialized.as_slice());
}

#[test]
fn test_serialize_header() {
    let filepath = "./tests/assets/classes.dex";
    let dex = apkdoctor::deserialize(filepath.to_string()).unwrap();
    assert!(dex.header.magic[0] == 0x64);
    assert!(dex.header.magic[1] == 0x65);
    assert!(dex.header.magic[2] == 0x78);
    assert!(dex.header.magic[6] == 0x38);
    assert!(dex.header.magic[7] == 0x00);

    let mut cursor = Cursor::new(vec![0u8; 0x70]);
    dex.header.serialize(&mut cursor);
    let serialized_header = cursor.into_inner();

    let file = File::open(filepath).unwrap();
    let reader = BufReader::new(file);
    let bytes = reader
        .bytes()
        .take(0x70)
        .collect::<Result<Vec<u8>, io::Error>>()
        .unwrap();

    assert_eq!(serialized_header, bytes);
}
