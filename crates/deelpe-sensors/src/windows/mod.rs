//! Sensors for Windows workstations. One event stream (ETW) for both: who
//! reads which file, and who sends how much where.
//!
//! No driver and no kernel extension, same as on the Mac: there it is
//! Apple's own tools, here it is the event tracing built into Windows. For
//! that, the service has to run as LocalSystem or as a member of
//! "Performance Log Users".

pub mod etw;
pub mod procinfo;
pub mod signature;
// Only for the sensors in this module: the functions take ETW's raw event
// pointer and have no business being visible outside.
pub(crate) mod tdh;
