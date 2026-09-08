//! Per-interaction-group Read/Write permissions for member-tied API keys.
//!
//! A member-tied API key is a delegate holding a `ProxyType::Scoped(ScopeSet)`
//! proxy on its member's account. The runtime maps every tenant-facing call to
//! the [`ScopeSet`] it requires and admits the call iff the key's set covers it.
//!
//! **This is a wire contract, mirrored from `matter-node`'s `common/src/scopes.rs`.**
//! A `ScopeSet` is a bare `u32` whose bit for `(scope, access)` is
//! `scope as u32 * 2 + access as u32`. Both enums are append-only: a new group
//! takes the next discriminant and the next two bits, and nothing already
//! assigned ever moves. [`tests::bit_layout_is_pinned`] is a copy of the
//! runtime's own test, so a reordering on either side fails here.
//!
//! # Why this lives in the key crate
//!
//! A scope set is what an API key *is permitted to do* — it belongs beside
//! [`ApiKey`](crate::ApiKey), not beside the threshold cryptography. Keeping it
//! here also keeps it reachable from `bindings/wasm` without pulling the crypto
//! stack along, which is the same reason key ingestion lives here at all.
//!
//! ```
//! use matter_vault_key::{Access, Scope, ScopeSet};
//!
//! let held: ScopeSet = "deployments:w, secrets:r".parse()?;
//! assert!(held.contains(Scope::Deployments, Access::Write));
//! // Read and Write are independent: writing deployments does not imply reading them.
//! assert!(!held.contains(Scope::Deployments, Access::Read));
//! assert_eq!(held.to_string(), "deployments:w, secrets:r");
//! # Ok::<(), matter_vault_key::ScopeParseError>(())
//! ```

use core::fmt;
use core::str::FromStr;

/// An interaction group a key may be permissioned for. Discriminants are the
/// bit-pair index in a [`ScopeSet`] and are append-only.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Scope {
    /// Deployment lifecycle (`jobs.*` tenant calls, including the launcher).
    Deployments = 0,
    /// MPC collaboration sessions (`collaborations.*`).
    Collaborations = 1,
    /// Threshold-encrypted secrets (`secrets.*`; `Read` = may decrypt as the member).
    Secrets = 2,
    /// Persistent volumes (`volumes.*`).
    Volumes = 3,
    /// Dataset catalog (`datasets.*`).
    Datasets = 4,
    /// Overlay networks and deployment WireGuard peers.
    Networking = 5,
    /// Owner-side resource (node) management (`resources.*`).
    Resources = 6,
    /// Org membership and projects (`organizations.*`, not org lifecycle).
    Organization = 7,
    /// Credit allotment and billing links (`budgets.*`, never treasury value movers).
    Billing = 8,
    /// Communities (`communities.*`).
    Communities = 9,
}

impl Scope {
    /// Every scope, in discriminant order.
    pub const ALL: [Scope; 10] = [
        Scope::Deployments,
        Scope::Collaborations,
        Scope::Secrets,
        Scope::Volumes,
        Scope::Datasets,
        Scope::Networking,
        Scope::Resources,
        Scope::Organization,
        Scope::Billing,
        Scope::Communities,
    ];

    /// Number of defined scopes; the set uses `2 * COUNT` bits.
    pub const COUNT: u32 = Self::ALL.len() as u32;

    /// The lowercase wire name, as used by [`ScopeSet`]'s `Display` and `FromStr`.
    pub const fn name(self) -> &'static str {
        NAMES[self as usize].0
    }
}

/// Scope names, indexed by discriminant. One table so `Display` and `FromStr`
/// cannot disagree about a spelling.
const NAMES: [(&str, Scope); 10] = [
    ("deployments", Scope::Deployments),
    ("collaborations", Scope::Collaborations),
    ("secrets", Scope::Secrets),
    ("volumes", Scope::Volumes),
    ("datasets", Scope::Datasets),
    ("networking", Scope::Networking),
    ("resources", Scope::Resources),
    ("organization", Scope::Organization),
    ("billing", Scope::Billing),
    ("communities", Scope::Communities),
];

/// How an empty set renders, and one of the two spellings that parse back to it.
/// A bare empty string is the other; both exist so a log line reads as something
/// rather than as nothing.
const EMPTY_TEXT: &str = "(none)";

/// The half of a scope a key is granted. `Read` and `Write` are independent
/// bits: neither implies the other.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Access {
    /// May observe (enforced by whichever service gates the read).
    Read = 0,
    /// May dispatch the group's calls as the member (enforced by the runtime).
    Write = 1,
}

/// A set of `(scope, access)` grants, encoded as a bare `u32` bitmask.
///
/// Construction never validates — bits above the defined range are
/// representable — so a set that came off the wire should be checked with
/// [`ScopeSet::is_valid`]. The runtime filter simply never maps a call to an
/// undefined bit, so stray bits grant nothing.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct ScopeSet(u32);

impl ScopeSet {
    /// No grants.
    pub const EMPTY: ScopeSet = ScopeSet(0);

    /// Every defined `(scope, access)` bit.
    pub const ALL: ScopeSet = ScopeSet((1u32 << (Scope::COUNT * 2)) - 1);

    /// The bit for `(scope, access)`.
    const fn bit(scope: Scope, access: Access) -> u32 {
        1u32 << ((scope as u32) * 2 + access as u32)
    }

    /// A set from raw bits — the wire form. Validate with [`Self::is_valid`]
    /// before trusting it.
    pub const fn from_bits(bits: u32) -> ScopeSet {
        ScopeSet(bits)
    }

    /// The raw bits — the wire form.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The set holding exactly `(scope, access)`.
    pub const fn single(scope: Scope, access: Access) -> ScopeSet {
        ScopeSet(Self::bit(scope, access))
    }

    /// Both halves of every listed scope — the mask "anything within these groups".
    pub const fn covering(scopes: &[Scope]) -> ScopeSet {
        let mut bits = 0u32;
        let mut i = 0;
        while i < scopes.len() {
            bits |= Self::bit(scopes[i], Access::Read) | Self::bit(scopes[i], Access::Write);
            i += 1;
        }
        ScopeSet(bits)
    }

    /// `self` plus `(scope, access)`.
    pub const fn with(self, scope: Scope, access: Access) -> ScopeSet {
        ScopeSet(self.0 | Self::bit(scope, access))
    }

    /// `self ∪ other`.
    pub const fn union(self, other: ScopeSet) -> ScopeSet {
        ScopeSet(self.0 | other.0)
    }

    /// Whether `(scope, access)` is granted.
    pub const fn contains(self, scope: Scope, access: Access) -> bool {
        self.0 & Self::bit(scope, access) != 0
    }

    /// Whether every grant in `other` is also in `self` (`self ⊇ other`).
    /// Read bits count: a set is not a superset of one it can only write.
    pub const fn is_superset(self, other: ScopeSet) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether every grant in `self` is also in `other` (`self ⊆ other`).
    pub const fn is_subset(self, other: ScopeSet) -> bool {
        other.is_superset(self)
    }

    /// Whether the set grants nothing.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether every set bit names a defined `(scope, access)`.
    pub const fn is_valid(self) -> bool {
        self.0 & !Self::ALL.0 == 0
    }
}

impl fmt::Display for ScopeSet {
    /// `deployments:rw, secrets:r`, in discriminant order. An empty set renders
    /// as `(none)`; both that and the empty string parse back to it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str(EMPTY_TEXT);
        }
        let mut first = true;
        for (name, scope) in NAMES {
            let r = self.contains(scope, Access::Read);
            let w = self.contains(scope, Access::Write);
            if !r && !w {
                continue;
            }
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            f.write_str(name)?;
            f.write_str(":")?;
            if r {
                f.write_str("r")?;
            }
            if w {
                f.write_str("w")?;
            }
        }
        Ok(())
    }
}

/// Why a scope-set string could not be parsed.
///
/// Deliberately separate from [`KeyError`](crate::KeyError): scope text arrives
/// from a CLI flag or an environment variable, never from key material, so it
/// carries no redaction obligation and echoing the offending token is helpful
/// rather than dangerous.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeParseError {
    /// An entry had no `:` separating the scope from its access letters.
    #[error("scope entry {entry:?} is missing its `:r`, `:w` or `:rw` suffix")]
    MissingAccess {
        /// The entry as written.
        entry: String,
    },

    /// The text before the `:` is not a known scope.
    #[error("unknown scope {name:?}")]
    UnknownScope {
        /// The name as written.
        name: String,
    },

    /// The text after the `:` is not some combination of `r` and `w`.
    #[error("scope {name:?} has invalid access {access:?}: expected r, w, or rw")]
    InvalidAccess {
        /// The scope the bad access applied to.
        name: String,
        /// The access letters as written.
        access: String,
    },
}

impl FromStr for ScopeSet {
    type Err = ScopeParseError;

    /// Parses `deployments:rw, secrets:r`. Case-insensitive; entries may be
    /// separated by commas, whitespace, or both. An empty string and `(none)`
    /// both yield [`ScopeSet::EMPTY`], so `Display` round-trips.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case(EMPTY_TEXT) {
            return Ok(ScopeSet::EMPTY);
        }

        let mut set = ScopeSet::EMPTY;
        for entry in trimmed
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|e| !e.is_empty())
        {
            let (name, access) =
                entry
                    .split_once(':')
                    .ok_or_else(|| ScopeParseError::MissingAccess {
                        entry: entry.to_string(),
                    })?;

            let scope = NAMES
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, s)| *s)
                .ok_or_else(|| ScopeParseError::UnknownScope {
                    name: name.to_string(),
                })?;

            // Reject a repeated letter rather than silently folding it: `r`
            // appearing twice means the caller's generator is confused.
            let (mut read, mut write) = (false, false);
            for c in access.chars() {
                match c.to_ascii_lowercase() {
                    'r' if !read => read = true,
                    'w' if !write => write = true,
                    _ => {
                        return Err(ScopeParseError::InvalidAccess {
                            name: name.to_string(),
                            access: access.to_string(),
                        })
                    }
                }
            }
            if !read && !write {
                return Err(ScopeParseError::InvalidAccess {
                    name: name.to_string(),
                    access: access.to_string(),
                });
            }

            if read {
                set = set.with(scope, Access::Read);
            }
            if write {
                set = set.with(scope, Access::Write);
            }
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire contract: bit = scope * 2 + access, pinned with literals so a
    /// reordering of either enum fails here. This is a copy of matter-node's
    /// `common::scopes::tests::bit_layout_is_pinned`; the duplication is the
    /// point, since the two repos share no crate.
    #[test]
    fn bit_layout_is_pinned() {
        assert_eq!(
            ScopeSet::single(Scope::Deployments, Access::Read).bits(),
            1 << 0
        );
        assert_eq!(
            ScopeSet::single(Scope::Deployments, Access::Write).bits(),
            1 << 1
        );
        assert_eq!(
            ScopeSet::single(Scope::Collaborations, Access::Read).bits(),
            1 << 2
        );
        assert_eq!(
            ScopeSet::single(Scope::Secrets, Access::Read).bits(),
            1 << 4
        );
        assert_eq!(
            ScopeSet::single(Scope::Secrets, Access::Write).bits(),
            1 << 5
        );
        assert_eq!(
            ScopeSet::single(Scope::Volumes, Access::Write).bits(),
            1 << 7
        );
        assert_eq!(
            ScopeSet::single(Scope::Datasets, Access::Write).bits(),
            1 << 9
        );
        assert_eq!(
            ScopeSet::single(Scope::Networking, Access::Write).bits(),
            1 << 11
        );
        assert_eq!(
            ScopeSet::single(Scope::Resources, Access::Write).bits(),
            1 << 13
        );
        assert_eq!(
            ScopeSet::single(Scope::Organization, Access::Write).bits(),
            1 << 15
        );
        assert_eq!(
            ScopeSet::single(Scope::Billing, Access::Write).bits(),
            1 << 17
        );
        assert_eq!(
            ScopeSet::single(Scope::Communities, Access::Read).bits(),
            1 << 18
        );
        assert_eq!(
            ScopeSet::single(Scope::Communities, Access::Write).bits(),
            1 << 19
        );
        assert_eq!(ScopeSet::ALL.bits(), (1 << 20) - 1);
    }

    #[test]
    fn scope_discriminants_are_pinned() {
        let expected: [(Scope, u8); 10] = [
            (Scope::Deployments, 0),
            (Scope::Collaborations, 1),
            (Scope::Secrets, 2),
            (Scope::Volumes, 3),
            (Scope::Datasets, 4),
            (Scope::Networking, 5),
            (Scope::Resources, 6),
            (Scope::Organization, 7),
            (Scope::Billing, 8),
            (Scope::Communities, 9),
        ];
        for (i, (scope, disc)) in expected.iter().enumerate() {
            assert_eq!(*scope as u8, *disc);
            assert_eq!(Scope::ALL[i], *scope);
        }
        assert_eq!(Scope::COUNT, 10);
    }

    /// The name table is indexed by discriminant, so `Scope::name` and the
    /// parser agree by construction only if the table is in that order.
    #[test]
    fn name_table_is_in_discriminant_order() {
        for (i, (name, scope)) in NAMES.iter().enumerate() {
            assert_eq!(*scope as usize, i);
            assert_eq!(scope.name(), *name);
            assert_eq!(Scope::ALL[i], *scope);
        }
    }

    #[test]
    fn contains_and_with_track_each_bit_independently() {
        let mut set = ScopeSet::EMPTY;
        for scope in Scope::ALL {
            for access in [Access::Read, Access::Write] {
                assert!(!set.contains(scope, access));
                set = set.with(scope, access);
                assert!(set.contains(scope, access));
            }
        }
        assert_eq!(set, ScopeSet::ALL);
        // Write never implies Read and vice versa.
        let write_only = ScopeSet::single(Scope::Secrets, Access::Write);
        assert!(!write_only.contains(Scope::Secrets, Access::Read));
        let read_only = ScopeSet::single(Scope::Secrets, Access::Read);
        assert!(!read_only.contains(Scope::Secrets, Access::Write));
    }

    #[test]
    fn superset_counts_read_bits() {
        let rw = ScopeSet::covering(&[Scope::Secrets]);
        let w = ScopeSet::single(Scope::Secrets, Access::Write);
        assert!(rw.is_superset(w));
        assert!(w.is_subset(rw));
        assert!(!w.is_superset(rw));
        assert!(w.is_superset(w));
        assert!(ScopeSet::ALL.is_superset(rw));
        assert!(ScopeSet::EMPTY.is_subset(w));
        assert!(!ScopeSet::EMPTY.is_superset(w));
    }

    #[test]
    fn covering_and_union_compose() {
        let deploy_like = ScopeSet::covering(&[Scope::Deployments, Scope::Secrets]);
        assert!(deploy_like.contains(Scope::Deployments, Access::Read));
        assert!(deploy_like.contains(Scope::Deployments, Access::Write));
        assert!(deploy_like.contains(Scope::Secrets, Access::Read));
        assert!(!deploy_like.contains(Scope::Volumes, Access::Read));
        assert_eq!(
            ScopeSet::covering(&[Scope::Deployments]).union(ScopeSet::covering(&[Scope::Secrets])),
            deploy_like
        );
        assert_eq!(ScopeSet::covering(&Scope::ALL), ScopeSet::ALL);
    }

    /// Bits above the defined range are representable; the call boundary is
    /// what rejects them.
    #[test]
    fn undefined_bits_are_representable_but_invalid() {
        assert!(!ScopeSet::from_bits(u32::MAX).is_valid());
        assert!(!ScopeSet::from_bits(1 << 20).is_valid());
        assert!(ScopeSet::ALL.is_valid());
        assert!(ScopeSet::EMPTY.is_valid());
        assert!(ScopeSet::EMPTY.is_empty());
        assert!(!ScopeSet::ALL.is_empty());
    }

    #[test]
    fn display_renders_in_discriminant_order() {
        let set = ScopeSet::EMPTY
            .with(Scope::Secrets, Access::Read)
            .with(Scope::Deployments, Access::Write)
            .with(Scope::Deployments, Access::Read);
        assert_eq!(set.to_string(), "deployments:rw, secrets:r");
        assert_eq!(ScopeSet::EMPTY.to_string(), EMPTY_TEXT);
    }

    #[test]
    fn display_and_parse_round_trip_over_every_set_shape() {
        for set in [
            ScopeSet::EMPTY,
            ScopeSet::ALL,
            ScopeSet::single(Scope::Communities, Access::Write),
            ScopeSet::covering(&[Scope::Deployments, Scope::Billing]),
            ScopeSet::EMPTY
                .with(Scope::Deployments, Access::Write)
                .with(Scope::Secrets, Access::Read),
        ] {
            assert_eq!(set.to_string().parse::<ScopeSet>(), Ok(set));
        }
    }

    #[test]
    fn parse_is_lenient_about_case_and_separators() {
        let expected = ScopeSet::EMPTY
            .with(Scope::Deployments, Access::Write)
            .with(Scope::Secrets, Access::Read);
        for text in [
            "deployments:w,secrets:r",
            "deployments:w, secrets:r",
            "Deployments:W  Secrets:R",
            "  secrets:r , deployments:w  ",
        ] {
            assert_eq!(text.parse::<ScopeSet>(), Ok(expected), "parsing {text:?}");
        }
        assert_eq!(
            "secrets:wr".parse::<ScopeSet>().unwrap().to_string(),
            "secrets:rw"
        );
        assert_eq!("".parse::<ScopeSet>(), Ok(ScopeSet::EMPTY));
        assert_eq!("(NONE)".parse::<ScopeSet>(), Ok(ScopeSet::EMPTY));
    }

    #[test]
    fn parse_rejects_malformed_entries() {
        assert!(matches!(
            "deployments".parse::<ScopeSet>(),
            Err(ScopeParseError::MissingAccess { .. })
        ));
        assert!(matches!(
            "deploy:r".parse::<ScopeSet>(),
            Err(ScopeParseError::UnknownScope { .. })
        ));
        assert!(matches!(
            "secrets:x".parse::<ScopeSet>(),
            Err(ScopeParseError::InvalidAccess { .. })
        ));
        assert!(matches!(
            "secrets:".parse::<ScopeSet>(),
            Err(ScopeParseError::InvalidAccess { .. })
        ));
        // A repeated letter is a confused generator, not a wider set.
        assert!(matches!(
            "secrets:rr".parse::<ScopeSet>(),
            Err(ScopeParseError::InvalidAccess { .. })
        ));
    }
}
