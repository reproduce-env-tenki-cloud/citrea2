use anyhow::{bail, Result};
use citrea_common::FromEnv;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct FeeServiceConfig {
    #[serde(default = "defaults::capacity_threshold")]
    pub capacity_threshold: f64,
    #[serde(default = "defaults::base_fee_multiplier")]
    pub base_fee_multiplier: f64,
    #[serde(default = "defaults::max_fee_multiplier")]
    pub max_fee_multiplier: f64,
    #[serde(default = "defaults::fee_exponential_factor")]
    pub fee_exponential_factor: f64,
    #[serde(default = "defaults::fee_multiplier_scalar")]
    pub fee_multiplier_scalar: f64,
}

mod defaults {
    // Threshold after which fee start to increase exponentially
    pub const fn capacity_threshold() -> f64 {
        0.50
    }

    // Multiplier used while below CAPACITY_THRESHOLD
    pub const fn base_fee_multiplier() -> f64 {
        1.0
    }

    // Max multiplier over threshold
    pub const fn max_fee_multiplier() -> f64 {
        4.0
    }

    // Exponential factor to adjust steepness of fee rise
    pub const fn fee_exponential_factor() -> f64 {
        4.0
    }

    pub const fn fee_multiplier_scalar() -> f64 {
        10.0
    }
}

impl Default for FeeServiceConfig {
    fn default() -> Self {
        Self {
            capacity_threshold: defaults::capacity_threshold(),
            base_fee_multiplier: defaults::base_fee_multiplier(),
            max_fee_multiplier: defaults::max_fee_multiplier(),
            fee_exponential_factor: defaults::fee_exponential_factor(),
            fee_multiplier_scalar: defaults::fee_multiplier_scalar(),
        }
    }
}

impl FromEnv for FeeServiceConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(FeeServiceConfig {
            capacity_threshold: std::env::var("DA_FEE_CAPACITY_THRESHOLD").map_or_else(
                |_| Ok(defaults::capacity_threshold()),
                |v| v.parse().map_err(Into::<anyhow::Error>::into),
            )?,
            base_fee_multiplier: std::env::var("DA_FEE_BASE_FEE_MULTIPLIER").map_or_else(
                |_| Ok(defaults::base_fee_multiplier()),
                |v| v.parse().map_err(Into::<anyhow::Error>::into),
            )?,
            max_fee_multiplier: std::env::var("DA_FEE_MAX_FEE_MULTIPLIER").map_or_else(
                |_| Ok(defaults::max_fee_multiplier()),
                |v| v.parse().map_err(Into::<anyhow::Error>::into),
            )?,
            fee_exponential_factor: std::env::var("DA_FEE_EXPONENTIAL_FACTOR").map_or_else(
                |_| Ok(defaults::fee_exponential_factor()),
                |v| v.parse().map_err(Into::<anyhow::Error>::into),
            )?,
            fee_multiplier_scalar: std::env::var("DA_FEE_MULTIPLIER_SCALAR").map_or_else(
                |_| Ok(defaults::fee_multiplier_scalar()),
                |v| v.parse().map_err(Into::<anyhow::Error>::into),
            )?,
        })
    }
}

impl FeeServiceConfig {
    pub fn validate(&self) -> Result<()> {
        if !(0.0..=1.0).contains(&self.capacity_threshold) {
            bail!(
                "capacity_threshold must be between 0 and 1, got {}",
                self.capacity_threshold
            );
        }

        if self.base_fee_multiplier < 1.0 {
            bail!(
                "base_fee_multiplier must be >= 1.0, got {}",
                self.base_fee_multiplier
            );
        }

        if self.max_fee_multiplier <= self.base_fee_multiplier {
            bail!(
                "max_fee_multiplier must be > base_fee_multiplier ({} <= {})",
                self.max_fee_multiplier,
                self.base_fee_multiplier
            );
        }

        if self.fee_exponential_factor <= 0.0 {
            bail!(
                "fee_exponential_factor must be > 0, got {}",
                self.fee_exponential_factor
            );
        }

        if self.fee_multiplier_scalar <= 0.0 {
            bail!(
                "fee_multiplier_scalar must be > 0, got {}",
                self.fee_multiplier_scalar
            );
        }

        Ok(())
    }
}
