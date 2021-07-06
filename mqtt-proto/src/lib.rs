// Copyright (c) Microsoft. All rights reserved.

/*!
 * MQTT protocol types common to both 3.1.1 and 5.0.
 *
 * Ref:
 * - <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html>
 * - <https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html>
 */

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::large_enum_variant,
    clippy::let_and_return,
    clippy::let_underscore_drop,
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::pub_enum_variant_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use std::time::Duration;

const PROTOCOL_NAME: &[u8] = b"\x00\x04MQTT";

macro_rules! define_u8_code {
    (
        $(#[$meta:meta])*
        $ty:ident,
        $error_variant:ident,
        $($variant:ident = $value:expr ,)*
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $ty {
            $($variant),*
        }

        impl std::convert::TryFrom<u8> for $ty {
            type Error = DecodeError;

            fn try_from(code: u8) -> Result<Self, Self::Error> {
                Ok(match code {
                    $($value => $ty::$variant ,)*
                    code => return Err(DecodeError::$error_variant(code)),
                })
            }
        }

        impl From<$ty> for u8 {
            fn from(code: $ty) -> Self {
                match code {
                    $($ty::$variant => $value ,)*
                }
            }
        }
    };
}

pub mod buffer;
pub use buffer::{BufferPool, Owned, Shared};

mod byte_str;
pub use byte_str::ByteStr;

pub mod v3;

pub mod v5;

#[allow(clippy::doc_markdown)] // clippy thinks "ClientId" is a Rust ident and should be in backticks.
/// The client ID
///
/// Ref:
/// - 3.1.1:
///   - 3.1.3.1 Client Identifier
///   - 3.1.2.4 Clean Session
/// - 5.0:
///   - 3.1.3.1 Client Identifier (ClientID)
///   - 3.1.2.4 Clean Start
#[derive(Clone, Eq, PartialEq)]
pub enum ClientId<P>
where
    P: BufferPool,
{
    ServerGenerated,
    IdWithCleanSession(ByteStr<P>),
    IdWithExistingSession(ByteStr<P>),
}

impl<P> std::fmt::Debug for ClientId<P>
where
    P: BufferPool,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientId::ServerGenerated => f.debug_tuple("ServerGenerated").finish(),

            ClientId::IdWithCleanSession(client_id) => f
                .debug_tuple("IdWithCleanSession")
                .field(client_id)
                .finish(),

            ClientId::IdWithExistingSession(client_id) => f
                .debug_tuple("IdWithExistingSession")
                .field(client_id)
                .finish(),
        }
    }
}

/// Decode MQTT-format "remaining length" numbers.
///
/// These numbers are encoded with a variable-length scheme that uses the MSB of each byte as a continuation bit.
///
/// Ref:
/// - 3.1.1: 2.2.3 Remaining Length
/// - 5.0:   2.1.4 Remaining Length
fn decode_remaining_length(src: &mut &[u8]) -> Result<Option<usize>, DecodeError> {
    let mut result = 0_usize;
    let mut num_bytes_read = 0_usize;

    loop {
        let (encoded_byte, rest) = match src.split_first() {
            Some((encoded_byte, rest)) => (encoded_byte, rest),
            None => return Ok(None),
        };
        *src = rest;

        result |= ((encoded_byte & 0x7F) as usize) << (num_bytes_read * 7);
        num_bytes_read += 1;

        if encoded_byte & 0x80 == 0 {
            return Ok(Some(result));
        }

        if num_bytes_read == 4 {
            return Err(DecodeError::RemainingLengthTooHigh);
        }
    }
}

fn encode_remaining_length<B>(mut item: usize, dst: &mut B) -> Result<(), EncodeError>
where
    B: ByteBuf,
{
    let original = item;
    let mut num_bytes_written = 0_usize;

    loop {
        #[allow(clippy::cast_possible_truncation)]
        let mut encoded_byte = (item & 0x7F) as u8;

        item >>= 7;

        if item > 0 {
            encoded_byte |= 0x80;
        }

        dst.try_put_u8(encoded_byte)?;
        num_bytes_written += 1;

        if item == 0 {
            break;
        }

        if num_bytes_written == 4 {
            return Err(EncodeError::RemainingLengthTooHigh(original));
        }
    }

    Ok(())
}

/// A packet identifier. Two-byte unsigned integer that cannot be zero.
///
/// Ref:
/// - 3.1.1: 2.3.1 Packet Identifier
/// - 5.0:   2.2.1 Packet Identifier
#[derive(Clone, Copy, Debug, Eq, Ord, Hash, PartialEq, PartialOrd)]
pub struct PacketIdentifier(u16);

impl PacketIdentifier {
    /// Returns the largest value that is a valid packet identifier.
    pub const fn max_value() -> Self {
        PacketIdentifier(u16::max_value())
    }

    /// Convert the given raw packet identifier into this type.
    pub fn new(raw: u16) -> Option<Self> {
        match raw {
            0 => None,
            raw => Some(PacketIdentifier(raw)),
        }
    }

    /// Get the raw packet identifier.
    pub fn get(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for PacketIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::ops::Add<u16> for PacketIdentifier {
    type Output = Self;

    fn add(self, other: u16) -> Self::Output {
        PacketIdentifier(match self.0.wrapping_add(other) {
            0 => 1,
            value => value,
        })
    }
}

impl std::ops::AddAssign<u16> for PacketIdentifier {
    fn add_assign(&mut self, other: u16) {
        *self = *self + other;
    }
}

define_u8_code! {
    /// The level of reliability for a publication
    ///
    /// Ref:
    /// - 3.1.1: 4.3 Quality of Service levels and protocol flows
    /// - 5.0:   4.3 Quality of Service levels and protocol flows
    QoS,
    UnrecognizedQoS,
    AtMostOnce = 0x00,
    AtLeastOnce = 0x01,
    ExactlyOnce = 0x02,
}

#[derive(Debug)]
pub enum DecodeError {
    // Common
    ConnectReservedSet,
    ConnectZeroLengthIdWithExistingSession,
    IncompletePacket,
    Io(std::io::Error),
    NoTopics,
    PublishDupAtMostOnce,
    RemainingLengthTooHigh,
    StringNotUtf8(std::str::Utf8Error),
    TrailingGarbage,
    UnrecognizedConnAckFlags(u8),
    UnrecognizedPacket {
        packet_type: u8,
        flags: u8,
        remaining_length: usize,
    },
    UnrecognizedProtocolName(String),
    UnrecognizedProtocolVersion(u8),
    UnrecognizedQoS(u8),
    ZeroPacketIdentifier,

    // Specific to v3

    // Specific to v5
    DuplicateProperty(&'static str),
    MissingRequiredProperty(&'static str),
    UnexpectedProperty,
    UnrecognizedPropertyIdentifier(u8),

    InvalidMaximumPacketSize(u32),
    UnrecognizedAuthenticateReasonCode(u8),
    UnrecognizedConnectReasonCode(u8),
    UnrecognizedDisconnectReasonCode(u8),
    UnrecognizedMaximumQoS(u8),
    UnrecognizedPayloadFormatIndicator(u8),
    UnrecognizedPubAckReasonCode(u8),
    UnrecognizedPubCompReasonCode(u8),
    UnrecognizedPubRecReasonCode(u8),
    UnrecognizedPubRelReasonCode(u8),
    UnrecognizedRequestProblemInformation(u8),
    UnrecognizedRequestResponseInformation(u8),
    UnrecognizedRetainAvailable(u8),
    UnrecognizedRetainHandling(u8),
    UnrecognizedSharedSubscriptionAvailable(u8),
    UnrecognizedSubscribeReasonCode(u8),
    UnrecognizedSubscriptionIdentifierAvailable(u8),
    UnrecognizedUnsubscribeReasonCode(u8),
    UnrecognizedWildcardSubscriptionAvailable(u8),

    SubscriptionOptionsReservedSet,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Common
            DecodeError::ConnectReservedSet => {
                f.write_str("the reserved byte of the CONNECT flags is set")
            }
            DecodeError::ConnectZeroLengthIdWithExistingSession =>
                f.write_str("a zero length client_id was received without the clean session flag set"),
            DecodeError::IncompletePacket => f.write_str("packet is truncated"),
            DecodeError::Io(err) => write!(f, "I/O error: {}", err),
            DecodeError::NoTopics => f.write_str("expected at least one topic but there were none"),
            DecodeError::PublishDupAtMostOnce => {
                f.write_str("PUBLISH packet has DUP flag set and QoS 0")
            }
            DecodeError::RemainingLengthTooHigh => {
                f.write_str("remaining length is too high to be decoded")
            }
            DecodeError::StringNotUtf8(err) => err.fmt(f),
            DecodeError::TrailingGarbage => f.write_str("packet has trailing garbage"),
            DecodeError::UnrecognizedConnAckFlags(flags) => {
                write!(f, "could not parse CONNACK flags 0x{:02X}", flags)
            }
            DecodeError::UnrecognizedPacket {
                packet_type,
                flags,
                remaining_length,
            } => write!(
                f,
                "could not identify packet with type 0x{:1X}, flags 0x{:1X} and remaining length {}",
                packet_type,
                flags,
                remaining_length,
            ),
            DecodeError::UnrecognizedProtocolName(name) => {
                write!(f, "unexpected protocol name {:?}", name)
            }
            DecodeError::UnrecognizedProtocolVersion(version) => {
                write!(f, "unexpected protocol version {:?}", version)
            }
            DecodeError::UnrecognizedQoS(qos) => write!(f, "could not parse QoS 0x{:02X}", qos),
            DecodeError::ZeroPacketIdentifier => f.write_str("packet identifier is 0"),

            // Specific to v3

            // Specific to v5
            DecodeError::DuplicateProperty(identifier) => {
                write!(f, "duplicate property {}", identifier)
            }
            DecodeError::MissingRequiredProperty(identifier) => {
                write!(f, "required property {} is missing", identifier)
            }
            DecodeError::UnexpectedProperty => f.write_str("unexpected property"),
            DecodeError::UnrecognizedPropertyIdentifier(identifier) => {
                write!(f, "unrecognized property identifier 0x{:02x}", identifier)
            }

            DecodeError::InvalidMaximumPacketSize(value) => write!(
                f,
                "maximum packet size property set to invalid value {}",
                value
            ),
            DecodeError::UnrecognizedAuthenticateReasonCode(code) => {
                write!(f, "unrecognized authenticate reason code 0x{:02x}", code)
            }
            DecodeError::UnrecognizedConnectReasonCode(code) => {
                write!(f, "unrecognized connect reason code 0x{:02x}", code)
            }
            DecodeError::UnrecognizedDisconnectReasonCode(code) => {
                write!(f, "unrecognized disconnect reason code 0x{:02x}", code)
            }
            DecodeError::UnrecognizedMaximumQoS(value) => {
                write!(f, "unrecognized maximum QoS 0x{:02x}", value)
            }
            DecodeError::UnrecognizedPayloadFormatIndicator(value) => {
                write!(f, "unrecognized payload format indicator 0x{:02x}", value)
            }
            DecodeError::UnrecognizedPubAckReasonCode(code) => {
                write!(f, "unrecognized puback reason code 0x{:02x}", code)
            }
            DecodeError::UnrecognizedPubCompReasonCode(code) => {
                write!(f, "unrecognized pubcomp reason code 0x{:02x}", code)
            }
            DecodeError::UnrecognizedPubRecReasonCode(code) => {
                write!(f, "unrecognized pubrec reason code 0x{:02x}", code)
            }
            DecodeError::UnrecognizedPubRelReasonCode(code) => {
                write!(f, "unrecognized pubrel reason code 0x{:02x}", code)
            }
            DecodeError::UnrecognizedRequestProblemInformation(value) => write!(
                f,
                "unrecognized request problem information 0x{:02x}",
                value
            ),
            DecodeError::UnrecognizedRequestResponseInformation(value) => write!(
                f,
                "unrecognized request response information 0x{:02x}",
                value
            ),
            DecodeError::UnrecognizedRetainAvailable(value) => {
                write!(f, "unrecognized retain available 0x{:02x}", value)
            }
            DecodeError::UnrecognizedRetainHandling(value) => {
                write!(f, "unrecognized retain handling 0x{:02x}", value)
            }
            DecodeError::UnrecognizedSharedSubscriptionAvailable(value) => write!(
                f,
                "unrecognized shared subscription available 0x{:02x}",
                value
            ),
            DecodeError::UnrecognizedSubscribeReasonCode(code) => {
                write!(f, "unrecognized subscribe reason code 0x{:02x}", code)
            }
            DecodeError::UnrecognizedSubscriptionIdentifierAvailable(value) => write!(
                f,
                "unrecognized subscription identifier available 0x{:02x}",
                value
            ),
            DecodeError::UnrecognizedUnsubscribeReasonCode(code) => {
                write!(f, "unrecognized unsubscribe reason code 0x{:02x}", code)
            }
            DecodeError::UnrecognizedWildcardSubscriptionAvailable(value) => write!(
                f,
                "unrecognized wildcard subscription available 0x{:02x}",
                value
            ),

            DecodeError::SubscriptionOptionsReservedSet => {
                f.write_str("the reserved bits of the subscription options are set")
            }
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            // Common
            DecodeError::ConnectReservedSet => None,
            DecodeError::ConnectZeroLengthIdWithExistingSession => None,
            DecodeError::IncompletePacket => None,
            DecodeError::Io(err) => Some(err),
            DecodeError::NoTopics => None,
            DecodeError::PublishDupAtMostOnce => None,
            DecodeError::RemainingLengthTooHigh => None,
            DecodeError::StringNotUtf8(err) => Some(err),
            DecodeError::TrailingGarbage => None,
            DecodeError::UnrecognizedConnAckFlags(_) => None,
            DecodeError::UnrecognizedPacket { .. } => None,
            DecodeError::UnrecognizedProtocolName(_) => None,
            DecodeError::UnrecognizedProtocolVersion(_) => None,
            DecodeError::UnrecognizedQoS(_) => None,
            DecodeError::ZeroPacketIdentifier => None,

            // Specific to v3

            // Specific to v5
            DecodeError::DuplicateProperty(_) => None,
            DecodeError::MissingRequiredProperty(_) => None,
            DecodeError::UnexpectedProperty => None,
            DecodeError::UnrecognizedPropertyIdentifier(_) => None,

            DecodeError::InvalidMaximumPacketSize(_) => None,
            DecodeError::UnrecognizedAuthenticateReasonCode(_) => None,
            DecodeError::UnrecognizedConnectReasonCode(_) => None,
            DecodeError::UnrecognizedDisconnectReasonCode(_) => None,
            DecodeError::UnrecognizedMaximumQoS(_) => None,
            DecodeError::UnrecognizedPayloadFormatIndicator(_) => None,
            DecodeError::UnrecognizedPubAckReasonCode(_) => None,
            DecodeError::UnrecognizedPubCompReasonCode(_) => None,
            DecodeError::UnrecognizedPubRecReasonCode(_) => None,
            DecodeError::UnrecognizedPubRelReasonCode(_) => None,
            DecodeError::UnrecognizedRequestProblemInformation(_) => None,
            DecodeError::UnrecognizedRequestResponseInformation(_) => None,
            DecodeError::UnrecognizedRetainAvailable(_) => None,
            DecodeError::UnrecognizedRetainHandling(_) => None,
            DecodeError::UnrecognizedSharedSubscriptionAvailable(_) => None,
            DecodeError::UnrecognizedSubscribeReasonCode(_) => None,
            DecodeError::UnrecognizedSubscriptionIdentifierAvailable(_) => None,
            DecodeError::UnrecognizedUnsubscribeReasonCode(_) => None,
            DecodeError::UnrecognizedWildcardSubscriptionAvailable(_) => None,

            DecodeError::SubscriptionOptionsReservedSet => None,
        }
    }
}

impl From<std::io::Error> for DecodeError {
    fn from(err: std::io::Error) -> Self {
        DecodeError::Io(err)
    }
}

#[derive(Debug)]
pub enum EncodeError {
    // Common
    InsufficientBuffer,
    Io(std::io::Error),
    KeepAliveTooHigh(std::time::Duration),
    RemainingLengthTooHigh(usize),
    StringTooLarge(usize),
    WillTooLarge(usize),

    // Specific to v3

    // Specific to v5
    InvalidMaximumPacketSize(usize),
    InvalidMessageExpiryInterval(Duration),
    InvalidReceiveMaximum(usize),
    InvalidServerKeepAlive(Duration),
    InvalidSessionExpiryInterval(Duration),
    InvalidTopicAlias(u16),
    InvalidWillDelayInterval(Duration),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Common
            EncodeError::InsufficientBuffer => f.write_str("insufficient buffer"),
            EncodeError::Io(err) => write!(f, "I/O error: {}", err),
            EncodeError::KeepAliveTooHigh(keep_alive) => {
                write!(f, "keep-alive {:?} is too high", keep_alive)
            }
            EncodeError::RemainingLengthTooHigh(len) => {
                write!(f, "remaining length {} is too high to be encoded", len)
            }
            EncodeError::StringTooLarge(len) => {
                write!(f, "string of length {} is too large to be encoded", len)
            }
            EncodeError::WillTooLarge(len) => write!(
                f,
                "will payload of length {} is too large to be encoded",
                len
            ),

            // Specific to v3

            // Specific to v5
            EncodeError::InvalidMaximumPacketSize(value) => write!(
                f,
                "maximum packet size property set to invalid value {}",
                value
            ),
            EncodeError::InvalidMessageExpiryInterval(interval) => write!(
                f,
                "message expiry interval property set to invalid value {}s",
                interval.as_secs()
            ),
            EncodeError::InvalidReceiveMaximum(value) => {
                write!(f, "receive maximum property set to invalid value {}", value)
            }
            EncodeError::InvalidServerKeepAlive(keep_alive) => write!(
                f,
                "server keep alive property set to invalid value {}s",
                keep_alive.as_secs()
            ),
            EncodeError::InvalidSessionExpiryInterval(interval) => write!(
                f,
                "session expiry interval property set to invalid value {}s",
                interval.as_secs()
            ),
            EncodeError::InvalidTopicAlias(value) => {
                write!(f, "topic alias property set to invalid value {}", value)
            }
            EncodeError::InvalidWillDelayInterval(interval) => write!(
                f,
                "will delay interval property set to invalid value {}s",
                interval.as_secs()
            ),
        }
    }
}

impl std::error::Error for EncodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            // Common
            EncodeError::InsufficientBuffer => None,
            EncodeError::Io(err) => Some(err),
            EncodeError::KeepAliveTooHigh(_) => None,
            EncodeError::RemainingLengthTooHigh(_) => None,
            EncodeError::StringTooLarge(_) => None,
            EncodeError::WillTooLarge(_) => None,

            // Specific to v3

            // Specific to v5
            EncodeError::InvalidMaximumPacketSize(_) => None,
            EncodeError::InvalidMessageExpiryInterval(_) => None,
            EncodeError::InvalidReceiveMaximum(_) => None,
            EncodeError::InvalidServerKeepAlive(_) => None,
            EncodeError::InvalidSessionExpiryInterval(_) => None,
            EncodeError::InvalidTopicAlias(_) => None,
            EncodeError::InvalidWillDelayInterval(_) => None,
        }
    }
}

impl From<std::io::Error> for EncodeError {
    fn from(err: std::io::Error) -> Self {
        EncodeError::Io(err)
    }
}

pub trait ByteBuf {
    fn try_put_u8(&mut self, n: u8) -> Result<(), EncodeError> {
        self.try_put_slice(&n.to_be_bytes())
    }

    fn try_put_u16_be(&mut self, n: u16) -> Result<(), EncodeError> {
        self.try_put_slice(&n.to_be_bytes())
    }

    fn try_put_u32_be(&mut self, n: u32) -> Result<(), EncodeError> {
        self.try_put_slice(&n.to_be_bytes())
    }

    fn try_put_packet_identifier(
        &mut self,
        packet_identifier: PacketIdentifier,
    ) -> Result<(), EncodeError> {
        self.try_put_u16_be(packet_identifier.0)
    }

    fn try_put_bytes<P>(&mut self, src: Shared<P>) -> Result<(), EncodeError>
    where
        P: BufferPool,
    {
        self.try_put_slice(&src[..])
    }

    fn try_put_slice(&mut self, src: &[u8]) -> Result<(), EncodeError>;
}

impl<P> ByteBuf for Owned<P>
where
    P: BufferPool,
{
    fn try_put_slice(&mut self, src: &[u8]) -> Result<(), EncodeError> {
        let dst = self.unfilled_mut();
        let dst = dst
            .get_mut(..src.len())
            .ok_or(EncodeError::InsufficientBuffer)?;
        dst.copy_from_slice(src);
        self.fill(src.len());
        Ok(())
    }
}

#[derive(Default)]
struct ByteCounter(usize);

impl ByteBuf for ByteCounter {
    fn try_put_slice(&mut self, src: &[u8]) -> Result<(), EncodeError> {
        self.0 += src.len();
        Ok(())
    }
}

/// Decode the fixed header of an MQTT packet.
///
/// Ref:
/// - 3.1.1: 2 MQTT Control Packet format
/// - 5.0:   2 MQTT Control Packet format
pub fn decode_fixed_header(src: &mut &[u8]) -> Result<Option<(u8, usize)>, DecodeError> {
    let (first_byte, rest) = match src.split_first() {
        Some((first_byte, rest)) => (*first_byte, rest),
        None => return Ok(None),
    };
    *src = rest;

    let remaining_length = match decode_remaining_length(src)? {
        Some(remaining_length) => remaining_length,
        None => return Ok(None),
    };

    Ok(Some((first_byte, remaining_length)))
}

/// Metadata about a packet
trait PacketMeta<P>: Clone + Sized
where
    P: BufferPool,
{
    /// The packet type for this kind of packet
    const PACKET_TYPE: u8;

    /// Decodes this packet from the given buffer
    fn decode(flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError>;

    /// Encodes the variable header and payload corresponding to this packet into the given buffer.
    /// The buffer is expected to already have the packet type and body length encoded into it,
    /// and to have reserved enough space to put the bytes of this packet directly into the buffer.
    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf;
}

pub enum Connect<P>
where
    P: BufferPool,
{
    V3(v3::Connect<P>),
    V5(v5::Connect<P>),
}

impl<P> Connect<P>
where
    P: Clone + BufferPool,
{
    pub fn decode(flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        match decode_connect_start(flags, src)? {
            v3::PROTOCOL_LEVEL => Ok(Connect::V3(v3::Connect::decode_rest(src)?)),
            v5::PROTOCOL_VERSION => Ok(Connect::V5(v5::Connect::decode_rest(src)?)),
            protocol_version => Err(DecodeError::UnrecognizedProtocolVersion(protocol_version)),
        }
    }
}

fn decode_connect_start<P>(flags: u8, src: &mut Shared<P>) -> Result<u8, DecodeError>
where
    P: Clone + BufferPool,
{
    if flags != 0 {
        return Err(DecodeError::UnrecognizedPacket {
            packet_type: 0x10,
            flags,
            remaining_length: src.len(),
        });
    }

    let protocol_name = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
    if protocol_name != PROTOCOL_NAME {
        return Err(DecodeError::UnrecognizedProtocolName(
            protocol_name.as_ref().to_owned(),
        ));
    }

    let protocol_level = src.try_get_u8()?;
    Ok(protocol_level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_length_encode() {
        remaining_length_encode_inner_ok(0x00, &[0x00]);
        remaining_length_encode_inner_ok(0x01, &[0x01]);

        remaining_length_encode_inner_ok(0x7F, &[0x7F]);
        remaining_length_encode_inner_ok(0x80, &[0x80, 0x01]);
        remaining_length_encode_inner_ok(0x3FFF, &[0xFF, 0x7F]);
        remaining_length_encode_inner_ok(0x4000, &[0x80, 0x80, 0x01]);
        remaining_length_encode_inner_ok(0x001F_FFFF, &[0xFF, 0xFF, 0x7F]);
        remaining_length_encode_inner_ok(0x0020_0000, &[0x80, 0x80, 0x80, 0x01]);
        remaining_length_encode_inner_ok(0x0FFF_FFFF, &[0xFF, 0xFF, 0xFF, 0x7F]);

        remaining_length_encode_inner_too_high(0x1000_0000);
        remaining_length_encode_inner_too_high(0xFFFF_FFFF);

        #[cfg(target_pointer_width = "64")]
        remaining_length_encode_inner_too_high(0xFFFF_FFFF_FFFF_FFFF);
    }

    fn remaining_length_encode_inner_ok(value: usize, expected: &[u8]) {
        let pool = TestBufferPool;

        // Can't encode into a buffer with no unfilled space left
        let mut bytes = Owned::new(pool, pool.take(0));
        match encode_remaining_length(value, &mut bytes) {
            Err(EncodeError::InsufficientBuffer) => (),
            result => panic!("{:?}", result),
        }

        // Can encode into a buffer with unfilled space left and no filled space
        let mut bytes = Owned::new(pool, pool.take(8));
        encode_remaining_length(value, &mut bytes).unwrap();
        assert_eq!(bytes.filled(), expected);

        // Can encode into a buffer with unfilled space left and some filled space
        let mut bytes = Owned::new(pool, pool.take(8));
        ByteBuf::try_put_slice(&mut bytes, &[0x00; 3][..]).unwrap();
        encode_remaining_length(value, &mut bytes).unwrap();
        assert_eq!(bytes.filled()[3..], *expected);
    }

    fn remaining_length_encode_inner_too_high(value: usize) {
        let pool = TestBufferPool;

        let mut bytes = Owned::new(pool, pool.take(8));
        match encode_remaining_length(value, &mut bytes) {
            Err(EncodeError::RemainingLengthTooHigh(v)) => assert_eq!(v, value),
            result => panic!("{:?}", result),
        }
    }

    #[derive(Clone, Copy)]
    struct TestBufferPool;

    impl TestBufferPool {
        #[allow(clippy::trivially_copy_pass_by_ref, clippy::unused_self)]
        fn take(&self, len: usize) -> std::sync::Arc<[u8]> {
            vec![0_u8; len].into_iter().collect()
        }
    }

    impl BufferPool for TestBufferPool {
        fn put_back(&self, _backing: std::sync::Arc<[u8]>) {}
    }

    #[test]
    fn remaining_length_decode() {
        remaining_length_decode_inner_ok(&[0x00], 0x00);
        remaining_length_decode_inner_ok(&[0x01], 0x01);

        remaining_length_decode_inner_ok(&[0x7F], 0x7F);
        remaining_length_decode_inner_ok(&[0x80, 0x01], 0x80);
        remaining_length_decode_inner_ok(&[0xFF, 0x7F], 0x3FFF);
        remaining_length_decode_inner_ok(&[0x80, 0x80, 0x01], 0x4000);
        remaining_length_decode_inner_ok(&[0xFF, 0xFF, 0x7F], 0x001F_FFFF);
        remaining_length_decode_inner_ok(&[0x80, 0x80, 0x80, 0x01], 0x0020_0000);
        remaining_length_decode_inner_ok(&[0xFF, 0xFF, 0xFF, 0x7F], 0x0FFF_FFFF);

        // Longer-than-necessary encodings are not disallowed by the spec
        remaining_length_decode_inner_ok(&[0x81, 0x00], 0x01);
        remaining_length_decode_inner_ok(&[0x81, 0x80, 0x00], 0x01);
        remaining_length_decode_inner_ok(&[0x81, 0x80, 0x80, 0x00], 0x01);

        remaining_length_decode_inner_too_high(&[0x80, 0x80, 0x80, 0x80]);
        remaining_length_decode_inner_too_high(&[0xFF, 0xFF, 0xFF, 0xFF]);

        remaining_length_decode_inner_incomplete_packet(&[0x80]);
        remaining_length_decode_inner_incomplete_packet(&[0x80, 0x80]);
        remaining_length_decode_inner_incomplete_packet(&[0x80, 0x80, 0x80]);
    }

    fn remaining_length_decode_inner_ok(mut bytes: &[u8], expected: usize) {
        let actual = decode_remaining_length(&mut bytes).unwrap();
        assert_eq!(actual, Some(expected));
        assert!(bytes.is_empty());
    }

    fn remaining_length_decode_inner_too_high(mut bytes: &[u8]) {
        match decode_remaining_length(&mut bytes) {
            Err(DecodeError::RemainingLengthTooHigh) => (),
            result => panic!("{:?}", result),
        }
    }

    fn remaining_length_decode_inner_incomplete_packet(mut bytes: &[u8]) {
        let actual = decode_remaining_length(&mut bytes).unwrap();
        assert_eq!(actual, None);
    }
}
