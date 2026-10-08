use serde::{Deserialize, Serialize};

pub const DAY_MS: u64 = 86_400_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendPolicy {
    pub per_tx_cap_sats: u64,
    pub rolling_24h_cap_sats: u64,
    pub max_feerate_sat_vb: u64,
    pub max_fee_sats: u64,
}

impl Default for SpendPolicy {
    fn default() -> Self {
        Self {
            per_tx_cap_sats: 100_000,
            rolling_24h_cap_sats: 250_000,
            max_feerate_sat_vb: 200,
            max_fee_sats: 20_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    ZeroVsize,
    FeeTooHigh { fee: u64, max: u64 },
    FeerateTooHigh { rate: u64, max: u64 },
    PerTx { outflow: u64, max: u64 },
    Rolling { outflow: u64, max: u64, used: u64 },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroVsize => write!(f, "transaction size is zero"),
            Self::FeeTooHigh { fee, max } => {
                write!(f, "fee {fee} sats exceeds max fee {max} sats")
            }
            Self::FeerateTooHigh { rate, max } => {
                write!(f, "feerate {rate} sat/vB exceeds max {max} sat/vB")
            }
            Self::PerTx { outflow, max } => {
                write!(
                    f,
                    "outflow {outflow} sats exceeds per-transaction cap {max} sats"
                )
            }
            Self::Rolling {
                outflow,
                max,
                used,
            } => write!(
                f,
                "outflow {outflow} sats would exceed the rolling 24h cap {max} sats ({used} sats already counted)"
            ),
        }
    }
}

pub fn feerate_sat_vb(fee_sats: u64, vsize: u64) -> Result<u64, PolicyError> {
    if vsize == 0 {
        return Err(PolicyError::ZeroVsize);
    }
    Ok(fee_sats.div_ceil(vsize))
}

pub fn check_fee(fee_sats: u64, vsize: u64, policy: &SpendPolicy) -> Result<u64, PolicyError> {
    let rate = feerate_sat_vb(fee_sats, vsize)?;
    if fee_sats > policy.max_fee_sats {
        return Err(PolicyError::FeeTooHigh {
            fee: fee_sats,
            max: policy.max_fee_sats,
        });
    }
    if rate > policy.max_feerate_sat_vb {
        return Err(PolicyError::FeerateTooHigh {
            rate,
            max: policy.max_feerate_sat_vb,
        });
    }
    Ok(rate)
}

pub fn check_outflow(
    outflow_sats: u64,
    already_sats: u64,
    policy: &SpendPolicy,
) -> Result<(), PolicyError> {
    if outflow_sats > policy.per_tx_cap_sats {
        return Err(PolicyError::PerTx {
            outflow: outflow_sats,
            max: policy.per_tx_cap_sats,
        });
    }
    let used = already_sats.saturating_add(outflow_sats);
    if used > policy.rolling_24h_cap_sats {
        return Err(PolicyError::Rolling {
            outflow: outflow_sats,
            max: policy.rolling_24h_cap_sats,
            used: already_sats,
        });
    }
    Ok(())
}

pub fn fee_for_vsize(feerate_sat_vb: u64, vsize: u64) -> Option<u64> {
    feerate_sat_vb.checked_mul(vsize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SpendPolicy {
        SpendPolicy::default()
    }

    #[test]
    fn fee_at_the_cap_is_allowed() {
        let rate = check_fee(20_000, 100, &policy()).unwrap();
        assert_eq!(rate, 200);
    }

    #[test]
    fn fee_one_sat_over_the_absolute_cap_is_rejected() {
        let err = check_fee(20_001, 200, &policy()).unwrap_err();
        assert_eq!(
            err,
            PolicyError::FeeTooHigh {
                fee: 20_001,
                max: 20_000
            }
        );
    }

    #[test]
    fn feerate_rounds_up() {
        let err = check_fee(201, 1, &policy()).unwrap_err();
        assert_eq!(
            err,
            PolicyError::FeerateTooHigh {
                rate: 201,
                max: 200
            }
        );
        assert_eq!(feerate_sat_vb(401, 2).unwrap(), 201);
    }

    #[test]
    fn zero_vsize_is_rejected() {
        assert_eq!(
            check_fee(1, 0, &policy()).unwrap_err(),
            PolicyError::ZeroVsize
        );
    }

    #[test]
    fn outflow_at_both_caps_is_allowed() {
        check_outflow(100_000, 150_000, &policy()).unwrap();
    }

    #[test]
    fn per_tx_cap_is_independent_of_the_rolling_window() {
        let err = check_outflow(100_001, 0, &policy()).unwrap_err();
        assert_eq!(
            err,
            PolicyError::PerTx {
                outflow: 100_001,
                max: 100_000
            }
        );
    }

    #[test]
    fn rolling_cap_counts_what_was_already_spent() {
        let err = check_outflow(50_000, 200_001, &policy()).unwrap_err();
        assert_eq!(
            err,
            PolicyError::Rolling {
                outflow: 50_000,
                max: 250_000,
                used: 200_001
            }
        );
    }
}
