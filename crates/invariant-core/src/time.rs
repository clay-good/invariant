//! Wall-clock UTC timestamps for the protocol.
//!
//! [`Timestamp`] wraps [`jiff::Timestamp`] but renders exactly as the
//! previous `chrono::DateTime<Utc>` did. That matters: timestamps are part of
//! hashed and signed data (audit entries, authority chains, proof manifests),
//! so a change in their string form would break verification of existing
//! records. In particular, fractional seconds are padded to 3, 6, or 9 digits
//! (`.120Z`, not jiff's `.12Z`).
//!
//! | Use                         | Output                           |
//! |-----------------------------|----------------------------------|
//! | serde / `Debug`             | `2023-11-14T22:13:20.120Z`       |
//! | [`Timestamp::to_rfc3339`]   | `2023-11-14T22:13:20.120+00:00`  |
//! | `Display`                   | `2023-11-14 22:13:20.120 UTC`    |

use std::fmt;
use std::ops::{Add, Sub};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use jiff::SignedDuration;

/// A UTC instant with nanosecond precision.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(jiff::Timestamp);

/// Error returned when a string is not a valid RFC 3339 timestamp.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid RFC 3339 timestamp {input:?}: {reason}")]
pub struct TimestampParseError {
    input: String,
    reason: String,
}

impl Timestamp {
    /// The Unix epoch, `1970-01-01T00:00:00Z`.
    pub const UNIX_EPOCH: Timestamp = Timestamp(jiff::Timestamp::UNIX_EPOCH);

    /// The current system time.
    pub fn now() -> Self {
        Timestamp(jiff::Timestamp::now())
    }

    /// Builds a timestamp from Unix seconds plus a nanosecond fraction
    /// (`0..1_000_000_000`). Returns `None` if out of range.
    pub fn from_unix(seconds: i64, nanos: u32) -> Option<Self> {
        let nanos = i32::try_from(nanos).ok().filter(|n| *n < 1_000_000_000)?;
        jiff::Timestamp::new(seconds, nanos).ok().map(Timestamp)
    }

    /// Builds a timestamp from Unix milliseconds. Returns `None` if out of range.
    pub fn from_unix_millis(millis: i64) -> Option<Self> {
        jiff::Timestamp::from_millisecond(millis)
            .ok()
            .map(Timestamp)
    }

    /// Parses an RFC 3339 timestamp with any UTC offset.
    pub fn parse_rfc3339(s: &str) -> Result<Self, TimestampParseError> {
        s.parse::<jiff::Timestamp>()
            .map(Timestamp)
            .map_err(|e| TimestampParseError {
                input: s.to_string(),
                reason: e.to_string(),
            })
    }

    /// Milliseconds since the Unix epoch, rounded down (toward negative
    /// infinity, as chrono's `timestamp_millis` did; jiff truncates toward zero).
    pub fn as_unix_millis(&self) -> i64 {
        // jiff's range (years -9999..=9999) always fits in i64 milliseconds.
        self.0.as_nanosecond().div_euclid(1_000_000) as i64
    }

    /// RFC 3339 with a `+00:00` offset, e.g. `2023-11-14T22:13:20.120+00:00`.
    pub fn to_rfc3339(&self) -> String {
        let mut s = String::with_capacity(32);
        self.write_iso(&mut s, 'T', "+00:00")
            .expect("writing to a String cannot fail");
        s
    }

    /// Signed time elapsed from `earlier` to `self`.
    pub fn duration_since(&self, earlier: Timestamp) -> SignedDuration {
        self.0.duration_since(earlier.0)
    }

    /// `self + d`, or `None` on overflow.
    pub fn checked_add(&self, d: SignedDuration) -> Option<Self> {
        self.0.checked_add(d).ok().map(Timestamp)
    }

    /// `self - d`, or `None` on overflow.
    pub fn checked_sub(&self, d: SignedDuration) -> Option<Self> {
        self.0.checked_sub(d).ok().map(Timestamp)
    }

    /// The underlying jiff timestamp.
    pub fn as_jiff(&self) -> jiff::Timestamp {
        self.0
    }

    /// Writes `YYYY-MM-DD<sep>HH:MM:SS[.fff|.ffffff|.fffffffff]<suffix>`,
    /// padding the fraction the way chrono's `SecondsFormat::AutoSi` does.
    fn write_iso(&self, w: &mut impl fmt::Write, sep: char, suffix: &str) -> fmt::Result {
        let dt = jiff::tz::Offset::UTC.to_datetime(self.0);
        write!(
            w,
            "{:04}-{:02}-{:02}{sep}{:02}:{:02}:{:02}",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        )?;
        let nanos = dt.subsec_nanosecond();
        if nanos == 0 {
        } else if nanos % 1_000_000 == 0 {
            write!(w, ".{:03}", nanos / 1_000_000)?;
        } else if nanos % 1_000 == 0 {
            write!(w, ".{:06}", nanos / 1_000)?;
        } else {
            write!(w, ".{nanos:09}")?;
        }
        w.write_str(suffix)
    }
}

impl From<jiff::Timestamp> for Timestamp {
    fn from(ts: jiff::Timestamp) -> Self {
        Timestamp(ts)
    }
}

impl FromStr for Timestamp {
    type Err = TimestampParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Timestamp::parse_rfc3339(s)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_iso(f, 'T', "Z")
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_iso(f, ' ', " UTC")
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{self:?}"))
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Timestamp::parse_rfc3339(&s).map_err(serde::de::Error::custom)
    }
}

impl Add<SignedDuration> for Timestamp {
    type Output = Timestamp;

    fn add(self, d: SignedDuration) -> Timestamp {
        self.checked_add(d).expect("timestamp overflow")
    }
}

impl Sub<SignedDuration> for Timestamp {
    type Output = Timestamp;

    fn sub(self, d: SignedDuration) -> Timestamp {
        self.checked_sub(d).expect("timestamp overflow")
    }
}

impl Sub<Timestamp> for Timestamp {
    type Output = SignedDuration;

    fn sub(self, rhs: Timestamp) -> SignedDuration {
        self.duration_since(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected strings were captured from chrono 0.4.45 (`Timestamp`
    // serde, `to_rfc3339()`, and `Display`) before the migration.
    const CASES: &[(i64, u32, &str, &str, &str)] = &[
        (
            1_700_000_000,
            0,
            "2023-11-14T22:13:20Z",
            "2023-11-14T22:13:20+00:00",
            "2023-11-14 22:13:20 UTC",
        ),
        (
            1_700_000_000,
            120_000_000,
            "2023-11-14T22:13:20.120Z",
            "2023-11-14T22:13:20.120+00:00",
            "2023-11-14 22:13:20.120 UTC",
        ),
        (
            1_700_000_000,
            123_456_000,
            "2023-11-14T22:13:20.123456Z",
            "2023-11-14T22:13:20.123456+00:00",
            "2023-11-14 22:13:20.123456 UTC",
        ),
        (
            1_700_000_000,
            123_456_789,
            "2023-11-14T22:13:20.123456789Z",
            "2023-11-14T22:13:20.123456789+00:00",
            "2023-11-14 22:13:20.123456789 UTC",
        ),
        (
            1_700_000_000,
            100,
            "2023-11-14T22:13:20.000000100Z",
            "2023-11-14T22:13:20.000000100+00:00",
            "2023-11-14 22:13:20.000000100 UTC",
        ),
    ];

    #[test]
    fn formats_match_chrono() {
        for &(secs, nanos, serde, rfc, display) in CASES {
            let ts = Timestamp::from_unix(secs, nanos).unwrap();
            assert_eq!(serde_json::to_string(&ts).unwrap(), format!("\"{serde}\""));
            assert_eq!(format!("{ts:?}"), serde);
            assert_eq!(ts.to_rfc3339(), rfc);
            assert_eq!(ts.to_string(), display);
        }
    }

    #[test]
    fn serde_round_trips_byte_for_byte() {
        for &(secs, nanos, serde, rfc, _) in CASES {
            let expected = Timestamp::from_unix(secs, nanos).unwrap();
            let json = format!("\"{serde}\"");
            let parsed: Timestamp = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
            assert_eq!(Timestamp::parse_rfc3339(rfc).unwrap(), expected);
        }
    }

    #[test]
    fn parses_non_utc_offsets() {
        let ts = Timestamp::parse_rfc3339("2023-11-14T23:13:20+01:00").unwrap();
        assert_eq!(ts, Timestamp::from_unix(1_700_000_000, 0).unwrap());
    }

    #[test]
    fn rejects_missing_offset() {
        assert!(Timestamp::parse_rfc3339("2023-11-14T22:13:20").is_err());
        assert!(Timestamp::parse_rfc3339("not a time").is_err());
    }

    #[test]
    fn pre_epoch_fraction_is_non_negative() {
        let ts = Timestamp::from_unix_millis(-1).unwrap();
        assert_eq!(format!("{ts:?}"), "1969-12-31T23:59:59.999Z");
        // Millis round down, as chrono's `timestamp_millis` did.
        let ts = Timestamp::from_unix(-1, 500_000).unwrap();
        assert_eq!(ts.as_unix_millis(), -1000);
    }

    #[test]
    fn arithmetic() {
        let t = Timestamp::from_unix(1_700_000_000, 0).unwrap();
        let later = t + SignedDuration::from_secs(90);
        assert_eq!(later - t, SignedDuration::from_secs(90));
        assert_eq!(later - SignedDuration::from_secs(90), t);
        assert_eq!(t.as_unix_millis(), 1_700_000_000_000);
        assert_eq!(Timestamp::default(), Timestamp::UNIX_EPOCH);
    }
}
