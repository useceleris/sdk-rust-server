use std::time::Duration;

/// What one set of credentials grants. Your server decides the claims for a
/// user that it has authenticated. Nothing from the client can make them
/// wider.
///
/// `Claims` has no default. You must choose the channels and the permissions,
/// so unrestricted access is never granted by omission (AUTH-02).
/// [`Claims::new`] sets the other fields to their defaults: no reference, no
/// replay and no echo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// The channels that the credentials can connect to.
    pub channels: ChannelScope,

    /// The access to the segments of those channels.
    pub permissions: SegmentPermissions,

    /// Identifies the token, such as a user id, in presence and in
    /// deliveries. It must not be empty and must not contain a colon, CR or
    /// LF. `None` leaves it out.
    pub reference: Option<String>,

    /// The history that the server replays each time the connection joins a
    /// segment.
    pub replay: Replay,

    /// Lets a connection receive its own publishes.
    pub allow_echo: bool,
} // end struct Claims

impl Claims {
    /// Claims with the given channels and permissions, no reference, no
    /// replay and no echo.
    pub fn new(channels: ChannelScope, permissions: SegmentPermissions) -> Claims {
        Claims {
            channels,
            permissions,
            reference: None,
            replay: Replay::None,
            allow_echo: false,
        }
    } // end fn new
} // end impl Claims

/// The channels that credentials can connect to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelScope {
    /// Every channel of the application.
    All,

    /// Only the listed channel references. List at least one, and each one
    /// only once. A reference has 1 to 255 ASCII letters, digits, hyphens (-)
    /// or underscores (_).
    Restricted(Vec<String>),
} // end enum ChannelScope

/// The read and write access to segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SegmentPermissions {
    /// The same access to every segment.
    All { read: bool, write: bool },

    /// Access to the listed segments only, each one listed once. With no
    /// segments, the credentials can connect but cannot read or write.
    Restricted(Vec<SegmentClaim>),
} // end enum SegmentPermissions

/// The access to one segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentClaim {
    /// Must not be empty and must not contain CR or LF.
    pub segment_id: String,

    pub read: bool,

    pub write: bool,
} // end struct SegmentClaim

/// The history that the server replays when a connection joins a segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replay {
    /// Replays nothing.
    None,

    /// Replays all the history that the server keeps for the segment.
    Backlog,

    /// Replays what the segment received in this period before the join: whole
    /// milliseconds, from 0 to 4294967295. Zero replays nothing older than the
    /// join, which is different from [`Replay::None`].
    Lookback(Duration),
} // end enum Replay
