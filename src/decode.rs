use std::io;

pub(crate) fn decode_uleb128<R>(r: &mut R) -> u32
where
    R: ?Sized + io::Read,
{
    let mut result = 0u32;
    let mut shift = 0u32;
    let mut buf = [0u8];
    loop {
        r.read_exact(&mut buf).expect("Could not decode uleb128");
        result |= ((buf[0] & 0x7fu8) as u32) << shift;
        if buf[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    return result;
}

pub(crate) fn decode_uleb128p1<R>(r: &mut R) -> i32
where
    R: ?Sized + io::Read,
{
    return decode_uleb128(r) as i32 - 1;
}

pub(crate) fn decode_sleb128<R>(r: &mut R) -> i32
where
    R: ?Sized + io::Read,
{
    let mut result = 0i32;
    let mut buf = [0u8];

    r.read_exact(&mut buf).expect("Could not decode sleb128");
    result |= buf[0] as i32;
    if result <= 0x7f {
        result = (result << 25) >> 25;
    } else {
        r.read_exact(&mut buf).expect("Could not decode sleb128");
        let cur = buf[0] as i32;
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if cur <= 0x7f {
            result = (result << 18) >> 18;
        } else {
            r.read_exact(&mut buf).expect("Could not decode sleb128");
            let cur = buf[0] as i32;
            result |= (cur & 0x7f) << 14;
            if cur <= 0x7f {
                result = (result << 11) >> 11;
            } else {
                r.read_exact(&mut buf).expect("Could not decode sleb128");
                let cur = buf[0] as i32;
                result |= (cur & 0x7f) << 21;
                if cur <= 0x7f {
                    result = (result << 4) >> 4;
                } else {
                    r.read_exact(&mut buf).expect("Could not decode sleb128");
                    let cur = buf[0] as i32;
                    result |= cur << 28;
                }
            }
        }
    }
    return result;
}

/// Reads `n` bytes from the stream `r` and interprets it as u64, zero extended to the left.
pub(crate) fn decode_nbytes_unsigned<R>(r: &mut R, n: usize) -> u64
where
    R: ?Sized + io::Read,
{
    assert!(n <= 8);
    let mut buf = vec![0u8; n];
    let mut shift = 0;
    r.read_exact(&mut buf).expect("Could not decode nbytes");
    let mut result = 0u64;
    for b in buf {
        result |= (b as u64) << shift;
        shift += 8;
    }
    return result;
}

/// Reads `n` bytes from the stream `r` and interprets it as i64, sign extended to the left.
pub(crate) fn decode_nbytes_signed<R>(r: &mut R, n: usize) -> i64
where
    R: ?Sized + io::Read,
{
    assert!(n <= 8);
    let mut buf = vec![0u8; n];
    let mut shift = 0;
    r.read_exact(&mut buf).expect("Could not decode nbytes");
    let mut result = 0i64;
    for b in buf {
        result |= (b as i64) << shift;
        shift += 8;
    }
    // Capture sign extension by shifting payload to left side, then back.
    result <<= 8 - n;
    result >>= 8 - n;
    return result;
}

/// Reads `n` bytes from the stream `r` and interprets it as f32, zero extended to the right.
pub(crate) fn decode_nbytes_as_f32<R>(r: &mut R, n: usize) -> f32
where
    R: ?Sized + io::Read,
{
    assert!(n <= 4);
    let mut buf = vec![0u8; n];
    let mut shift = 0;
    r.read_exact(&mut buf).expect("Could not decode nbytes");
    let mut result = 0u32;
    for b in buf {
        result |= (b as u32) << shift;
        shift += 8;
    }
    // Handle right zero extension by shifting contents to left side.
    result <<= 4 - n;
    return result as f32;
}

/// Reads `n` bytes from the stream `r` and interprets it as f64, zero extended to the right.
pub(crate) fn decode_nbytes_as_f64<R>(r: &mut R, n: usize) -> f64
where
    R: ?Sized + io::Read,
{
    assert!(n <= 8);
    let mut buf = vec![0u8; n];
    let mut shift = 0;
    r.read_exact(&mut buf).expect("Could not decode nbytes");
    let mut result = 0u64;
    for b in buf {
        result |= (b as u64) << shift;
        shift += 8;
    }
    // Handle right zero extension by shifting contents to left side.
    result <<= 8 - n;
    return result as f64;
}

pub(crate) fn decode_u64<R>(r: &mut R) -> u64
where
    R: ?Sized + io::Read,
{
    let mut buf = [0u8; 8];
    let mut shift = 0;
    r.read_exact(&mut buf).expect("Could not decode u64");
    let mut result = 0u64;
    for b in buf {
        result |= (b as u64) << shift;
        shift += 8;
    }
    return result;
}

pub(crate) fn decode_i64<R>(r: &mut R) -> i64
where
    R: ?Sized + io::Read,
{
    decode_u64(r) as i64
}

pub(crate) fn decode_f64<R>(r: &mut R) -> f64
where
    R: ?Sized + io::Read,
{
    decode_u64(r) as f64
}

pub(crate) fn decode_u32<R>(r: &mut R) -> u32
where
    R: ?Sized + io::Read,
{
    let mut buf = [0u8; 4];
    let mut shift = 0;
    r.read_exact(&mut buf).expect("Could not decode u32");
    let mut result = 0u32;
    for b in buf {
        result |= (b as u32) << shift;
        shift += 8;
    }
    return result;
}

pub(crate) fn decode_i32<R>(r: &mut R) -> i32
where
    R: ?Sized + io::Read,
{
    decode_u32(r) as i32
}

pub(crate) fn decode_f32<R>(r: &mut R) -> f32
where
    R: ?Sized + io::Read,
{
    decode_u32(r) as f32
}

pub(crate) fn decode_u16<R>(r: &mut R) -> u16
where
    R: ?Sized + io::Read,
{
    let mut buf = [0u8; 2];
    let mut shift = 0;
    r.read_exact(&mut buf).expect("Could not decode u16");
    let mut result = 0u16;
    for b in buf {
        result |= (b as u16) << shift;
        shift += 8;
    }
    return result;
}

pub(crate) fn decode_i16<R>(r: &mut R) -> i16
where
    R: ?Sized + io::Read,
{
    decode_u16(r) as i16
}

pub(crate) fn decode_u8<R>(r: &mut R) -> u8
where
    R: ?Sized + io::Read,
{
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf).expect("Could not decode u8");
    return buf[0];
}

pub(crate) fn decode_i8<R>(r: &mut R) -> i8
where
    R: ?Sized + io::Read,
{
    decode_u8(r) as i8
}
