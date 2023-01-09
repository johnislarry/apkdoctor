pub(crate) fn get_required_bytes(data: i64) -> u8 {
    let required_bits;
    if data < 0 {
        // Add one for the sign bit.
        required_bits = 64 - data.leading_ones() + 1;
    } else {
        required_bits = 64 - data.leading_zeros();

        // Minimum required bytes is 1.
        if required_bits == 0 {
            return 1;
        }
    }

    // Round up to a number of bytes.
    return ((required_bits + 7) / 8) as u8;
}

pub(crate) fn get_required_bytes_for_f32(data: f32) -> u8 {
    let required_bits = 32 - (data as u32).trailing_zeros();
    // Minimum required bytes is 1.
    if required_bits == 0 {
        return 1;
    }

    // Round up to a number of bytes.
    return ((required_bits + 7) / 8) as u8;
}

pub(crate) fn get_required_bytes_for_f64(data: f64) -> u8 {
    let required_bits = 64 - (data as u64).trailing_zeros();
    // Minimum required bytes is 1.
    if required_bits == 0 {
        return 1;
    }

    // Round up to a number of bytes.
    return ((required_bits + 7) / 8) as u8;
}
