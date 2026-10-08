pub fn enforce_input_cap(input_sats: u64, cap: u64) -> Result<(), String> {
    if input_sats > cap {
        return Err(format!(
            "transaction inputs total {input_sats} sats, above MAX_TX_INPUT_SATS {cap}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_sum_at_the_cap_is_allowed_and_one_sat_over_is_not() {
        enforce_input_cap(100_000, 100_000).unwrap();
        let err = enforce_input_cap(100_001, 100_000).unwrap_err();
        assert!(err.contains("MAX_TX_INPUT_SATS"));
        assert!(err.contains("100001"));
    }
}
