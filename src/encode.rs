use std::io;

use crate::uleb128;

pub(crate) fn encode_uleb128<W>(w: &mut W, mut data: uleb128)
where
    W: io::Write,
{
    loop {
        let mut byte = data as u8 & 0x7f;
        data >>= 7;
        if data != 0 {
            // More bytes to come.
            byte &= 0x80;
        }
        encode_u8(w, byte);
        if data == 0 {
            break;
        }
    }
}

pub(crate) fn encode_nbytes<W>(w: &mut W, num: u8, data: u64)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()[0..(num as usize)])
        .expect("could not encode nbytes");
}

pub(crate) fn encode_u32<W>(w: &mut W, data: u32)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()).expect("could not encode u32");
}

pub(crate) fn encode_i32<W>(w: &mut W, data: i32)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()).expect("could not encode i32");
}

pub(crate) fn encode_u16<W>(w: &mut W, data: u16)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()).expect("could not encode u16");
}

pub(crate) fn encode_i16<W>(w: &mut W, data: i16)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()).expect("could not encode i16");
}

pub(crate) fn encode_u8<W>(w: &mut W, data: u8)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()).expect("could not encode u8");
}

pub(crate) fn encode_i8<W>(w: &mut W, data: i8)
where
    W: io::Write,
{
    w.write(&data.to_le_bytes()).expect("could not encode i8");
}
