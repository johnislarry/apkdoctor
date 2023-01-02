use std::{
    fs::File,
    io::{self, BufReader, Read},
};

use apkdoctor;

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
