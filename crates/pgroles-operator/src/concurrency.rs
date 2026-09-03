//! How many reconciles the operator runs at once.

/// The number of reconciles allowed to run concurrently, per controller.
///
/// kube-rs defaults to `0`, meaning unbounded: every object whose watch fires
/// reconciles immediately. Reconciling a `PostgresPolicy` inspects the whole
/// managed surface of its database — one `aclexplode` over every function in
/// every managed schema is ~100k rows on a policy covering 49 schemas and 32
/// roles — so peak memory scales with the number of policies that happen to be
/// due at the same moment, not with the size of any one of them. An operator
/// watching 28 policies allocates 28 of those inspections at once on startup,
/// when every watch fires together.
///
/// A bound also matches what the database can absorb. Pools are capped at a
/// handful of connections per database and a policy already holds an advisory
/// lock for its own database, so reconciles past that point queue on
/// connections rather than progress — the unbounded case converts memory into
/// `pool timed out while waiting for an open connection`, which reads as a
/// database problem rather than a concurrency one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileConcurrency(u16);

impl Default for ReconcileConcurrency {
    fn default() -> Self {
        // Enough to keep a slow database from stalling unrelated policies,
        // low enough that peak inspection memory stays a small multiple of one
        // policy's. Unbounded is the only value that cannot be reasoned about.
        Self(4)
    }
}

impl ReconcileConcurrency {
    /// Overrides the default bound. `0` restores unbounded concurrency.
    pub const ENV: &'static str = "RECONCILE_CONCURRENCY";

    /// Resolve the bound from the process environment.
    ///
    /// Unset keeps the default. An invalid value is an error, not a fallback,
    /// for the same reason the retention bounds refuse startup: an operator
    /// running with different concurrency than the environment asked for is
    /// only discovered as an out-of-memory kill much later.
    pub fn from_env() -> Result<Self, ReconcileConcurrencyConfigError> {
        Self::from_lookup(|variable| match std::env::var(variable) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(ReconcileConcurrencyConfigError::NotUnicode {
                    variable: Self::ENV,
                })
            }
        })
    }

    /// [`Self::from_env`] over an arbitrary lookup, so parsing is testable
    /// without mutating process-global environment state.
    fn from_lookup(
        lookup: impl Fn(&'static str) -> Result<Option<String>, ReconcileConcurrencyConfigError>,
    ) -> Result<Self, ReconcileConcurrencyConfigError> {
        match lookup(Self::ENV)? {
            None => Ok(Self::default()),
            Some(value) => {
                let trimmed = value.trim();
                let parsed = trimmed.parse::<u16>().map_err(|_| {
                    ReconcileConcurrencyConfigError::Invalid {
                        variable: Self::ENV,
                        value: trimmed.to_string(),
                    }
                })?;
                Ok(Self(parsed))
            }
        }
    }

    /// The bound as kube-rs expects it, where `0` means unbounded.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }

    /// Whether this bound leaves concurrency unbounded.
    #[must_use]
    pub fn is_unbounded(self) -> bool {
        self.0 == 0
    }
}

/// Why a `RECONCILE_CONCURRENCY` value was refused at startup.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileConcurrencyConfigError {
    #[error("{variable} must be an integer between 0 and {max}, got {value:?}", max = u16::MAX)]
    Invalid {
        variable: &'static str,
        value: String,
    },
    #[error("{variable} is not valid unicode")]
    NotUnicode { variable: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(
        value: Option<&str>,
    ) -> impl Fn(&'static str) -> Result<Option<String>, ReconcileConcurrencyConfigError> {
        let owned = value.map(str::to_string);
        move |_| Ok(owned.clone())
    }

    #[test]
    fn defaults_to_a_bounded_value() {
        let resolved = ReconcileConcurrency::from_lookup(lookup(None)).expect("default resolves");
        assert_eq!(resolved, ReconcileConcurrency::default());
        assert!(
            !resolved.is_unbounded(),
            "the default must bound concurrency; unbounded is what exhausts memory"
        );
    }

    #[test]
    fn reads_an_override() {
        let resolved = ReconcileConcurrency::from_lookup(lookup(Some("9"))).expect("parses");
        assert_eq!(resolved.get(), 9);
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let resolved = ReconcileConcurrency::from_lookup(lookup(Some(" 2 "))).expect("parses");
        assert_eq!(resolved.get(), 2);
    }

    #[test]
    fn zero_restores_unbounded() {
        let resolved = ReconcileConcurrency::from_lookup(lookup(Some("0"))).expect("parses");
        assert!(resolved.is_unbounded());
    }

    #[test]
    fn a_malformed_value_refuses_startup() {
        let error = ReconcileConcurrency::from_lookup(lookup(Some("lots")))
            .expect_err("a malformed value must not fall back to the default");
        assert!(
            error.to_string().contains(ReconcileConcurrency::ENV),
            "the error names the variable, got: {error}"
        );
    }

    #[test]
    fn a_value_past_the_range_refuses_startup() {
        ReconcileConcurrency::from_lookup(lookup(Some("70000")))
            .expect_err("a value beyond u16 must be refused, not truncated");
    }
}
