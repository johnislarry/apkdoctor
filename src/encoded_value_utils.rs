pub(crate) fn get_required_bytes_signed(data: i64) -> u8 {
    let mut required_bits;
    if data < 0 {
        // Add one for the sign bit.
        required_bits = 64 - data.leading_ones() + 1;
    } else {
        required_bits = 64 - data.leading_zeros();

        // Minimum required bytes is 1.
        if required_bits == 0 {
            return 1;
        }

        // If the leading bit of the encoded value is 1, then it will be
        // incorrectly decoded as negative (one-extended), so add another
        // required bit.
        if required_bits % 8 == 0 {
            required_bits += 1;
        }
    }

    // Round up to a number of bytes.
    return ((required_bits + 7) / 8) as u8;
}

pub(crate) fn get_required_bytes_unsigned(data: u64) -> u8 {
    let required_bits = 64 - data.leading_zeros();

    // Minimum required bytes is 1.
    if required_bits == 0 {
        return 1;
    }

    // Round up to a number of bytes.
    return ((required_bits + 7) / 8) as u8;
}

pub(crate) fn get_required_bytes_for_f32(data: f32) -> u8 {
    let required_bits = 32 - data.to_bits().trailing_zeros();
    // Minimum required bytes is 1.
    if required_bits == 0 {
        return 1;
    }

    // Round up to a number of bytes.
    return ((required_bits + 7) / 8) as u8;
}

pub(crate) fn get_required_bytes_for_f64(data: f64) -> u8 {
    let required_bits = 64 - data.to_bits().trailing_zeros();
    // Minimum required bytes is 1.
    if required_bits == 0 {
        return 1;
    }

    // Round up to a number of bytes.
    return ((required_bits + 7) / 8) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(get_required_bytes_for_f32(66048.0), 2);
    }

    #[test]
    fn test239() {
        assert_eq!(get_required_bytes_signed(239), 2);
    }

    #[test]
    fn test36420() {
        assert_eq!(get_required_bytes_unsigned(36420), 2);
    }
}
