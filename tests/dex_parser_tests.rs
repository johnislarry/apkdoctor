use std::{
    fs::File,
    io::{self, BufReader, Cursor, Read},
};

use apkdoctor::{self, dex_structs::DexStruct};

#[test]
fn test_deserialize() {
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
