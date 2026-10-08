//! Every fixed value that the crate uses. None of them is public.

use std::time::Duration;

/// The latest timestamp that the server accepts, in milliseconds since the
/// Unix epoch: the last millisecond of the year 9999.
pub(crate) const MAXIMUM_TIMESTAMP: u128 = 253_402_300_799_999;

/// The largest replay lookback that the server accepts: an unsigned 32-bit
/// count of milliseconds.
pub(crate) const MAXIMUM_REPLAY_LOOKBACK: Duration = Duration::from_millis(4_294_967_295);

/// The longest channel reference that the server accepts, in bytes.
pub(crate) const MAXIMUM_CHANNEL_REFERENCE_LENGTH: usize = 255;
