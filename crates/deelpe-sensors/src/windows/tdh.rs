//! Read event fields **by name**, not by byte offset.
//!
//! The payloads of "Kernel-File" and "Kernel-Network" have different
//! lengths across Windows versions, and partly different fields. Hard-code
//! offsets and on one machine you get the number of bytes read, on the next
//! one half a pointer address — and you never notice, because both are a
//! number.
//!
//! `TdhGetProperty` resolves the field name through the manifest that ships
//! with the provider. That costs two calls per field, and in return it is
//! either right or it fails visibly. Decoding the raw bytes lives in
//! `crate::winpath` and is tested there.

use crate::winpath;
use windows::Win32::System::Diagnostics::Etw::{
    TdhGetProperty, TdhGetPropertySize, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR,
};

fn descriptor(name: &[u16]) -> PROPERTY_DATA_DESCRIPTOR {
    PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    }
}

/// Raw bytes of a field. `None` if the event does not have that field.
pub(crate) fn prop_bytes(rec: *mut EVENT_RECORD, name: &str) -> Option<Vec<u8>> {
    let n: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let desc = [descriptor(&n)];
    let mut size = 0u32;
    let rc = unsafe { TdhGetPropertySize(rec, None, &desc, &mut size) };
    if rc != 0 || size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe { TdhGetProperty(rec, None, &desc, &mut buf) };
    if rc != 0 {
        return None;
    }
    Some(buf)
}

pub(crate) fn prop_u32(rec: *mut EVENT_RECORD, name: &str) -> Option<u32> {
    let b = prop_bytes(rec, name)?;
    match b.len() {
        4 => Some(u32::from_le_bytes(b[..4].try_into().ok()?)),
        2 => Some(u16::from_le_bytes(b[..2].try_into().ok()?) as u32),
        8 => Some(u64::from_le_bytes(b[..8].try_into().ok()?) as u32),
        _ => None,
    }
}

pub(crate) fn prop_u64(rec: *mut EVENT_RECORD, name: &str) -> Option<u64> {
    let b = prop_bytes(rec, name)?;
    match b.len() {
        8 => Some(u64::from_le_bytes(b[..8].try_into().ok()?)),
        4 => Some(u32::from_le_bytes(b[..4].try_into().ok()?) as u64),
        _ => None,
    }
}

pub(crate) fn prop_port(rec: *mut EVENT_RECORD, name: &str) -> Option<u16> {
    winpath::port_from_bytes(&prop_bytes(rec, name)?)
}

pub(crate) fn prop_string(rec: *mut EVENT_RECORD, name: &str) -> Option<String> {
    Some(winpath::utf16_from_bytes(&prop_bytes(rec, name)?))
}

pub(crate) fn prop_ip(rec: *mut EVENT_RECORD, name: &str) -> Option<std::net::IpAddr> {
    winpath::ip_from_bytes(&prop_bytes(rec, name)?)
}
