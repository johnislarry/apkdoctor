use std::io;

use crate::{sleb128, uleb128, uleb128p1};

pub(crate) fn encode_uleb128<W>(w: &mut W, mut data: uleb128)
where
    W: io::Write,
{
    let mut bytes_written = 0;
    loop {
        let mut byte = data as u8 & 0x7f;
        data >>= 7;
        if data != 0 {
            // More bytes to come.
            byte |= 0x80;
        }
        encode_u8(w, byte);
        bytes_written += 1;
        if data == 0 {
            break;
        }
        if bytes_written > 4 {
            panic!("Bad uleb128 encode");
        }
    }
}

pub(crate) fn encode_uleb128p1<W>(w: &mut W, data: uleb128p1)
where
    W: io::Write,
{
    encode_uleb128(w, (data + 1) as uleb128);
}

pub(crate) fn encode_sleb128<W>(w: &mut W, mut data: sleb128)
where
    W: io::Write,
{
    let mut bytes_written = 0;
    let mut more = true;
    while more {
        let mut byte = data as u8 & 0x7f;
        data >>= 7;
        if (data == 0 && (byte & 0x40) == 0) || (data == -1 && (byte & 0x40) == 0x40) {
            more = false;
        } else {
            byte |= 0x80;
        }
        encode_u8(w, byte);
        bytes_written += 1;
        if bytes_written > 4 {
            panic!("Bad sleb128 encode");
        }
    }
}

pub(crate) fn size_uleb128(mut data: uleb128) -> usize {
    let mut bytes_written = 0;
    loop {
        data >>= 7;
        bytes_written += 1;
        if data == 0 {
            break;
        }
        if bytes_written > 4 {
            panic!("Bad uleb128 encode");
        }
    }
    return bytes_written;
}

pub(crate) fn size_sleb128(mut data: sleb128) -> usize {
    let mut bytes_written = 0;
    let mut more = true;
    while more {
        let byte = data as u8 & 0x7f;
        data >>= 7;
        if (data == 0 && (byte & 0x40) == 0) || (data == -1 && (byte & 0x40) == 0x40) {
            more = false;
        }
        bytes_written += 1;
        if bytes_written > 4 {
            panic!("Bad sleb128 encode");
        }
    }
    return bytes_written;
}

pub(crate) fn size_uleb128p1(data: uleb128p1) -> usize {
    size_uleb128((data + 1) as uleb128)
}

pub(crate) fn encode_nbytes<W>(w: &mut W, num: u8, data: u64)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()[0..(num as usize)])
        .expect("could not encode nbytes");
}

pub(crate) fn encode_nbytes_for_float<W>(w: &mut W, num: u8, mut data: u32)
where
    W: io::Write,
{
    data >>= 32 - (num * 8);
    w.write(&data.to_le_bytes()[0..(num as usize)])
        .expect("could not encode nbytes");
}

pub(crate) fn encode_nbytes_for_double<W>(w: &mut W, num: u8, mut data: u64)
where
    W: io::Write,
{
    data >>= 64 - (num * 8);
    w.write(&data.to_le_bytes()[0..(num as usize)])
        .expect("could not encode nbytes");
}

pub(crate) fn encode_u64<W>(w: &mut W, data: u64)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()).expect("could not encode u64");
}

pub(crate) fn encode_u32<W>(w: &mut W, data: u32)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()).expect("could not encode u32");
}

pub(crate) fn encode_u16<W>(w: &mut W, data: u16)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()).expect("could not encode u16");
}

pub(crate) fn encode_u8<W>(w: &mut W, data: u8)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()).expect("could not encode u8");
}

#[cfg(test)]
mod tests {
    use crate::decode::{decode_sleb128, decode_uleb128};

    use super::*;

    #[test]
    fn test1() {
        let mut cursor = io::Cursor::new(vec![0u8]);
        encode_sleb128(&mut cursor, 1);
        cursor.set_position(0);
        let sleb = decode_sleb128(&mut cursor);
        assert_eq!(sleb, 1);
    }

    #[test]
    fn test11016() {
        let mut cursor = io::Cursor::new(vec![0u8; size_uleb128(11016)]);
        encode_uleb128(&mut cursor, 11016);
        cursor.set_position(0);
        let leb = decode_uleb128(&mut cursor);
        assert_eq!(leb, 11016);
    }
}
