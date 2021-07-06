// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryInto;
use std::time::Duration;

use super::{decode_connect_start, encode_remaining_length};
use crate::{
    BufferPool, ByteBuf, ByteCounter, ByteStr, ClientId, DecodeError, EncodeError,
    PacketIdentifier, PacketMeta, QoS, Shared,
};

pub(crate) const PROTOCOL_LEVEL: u8 = 0x04;

/// The return code for a connection attempt
///
/// Ref: 3.2.2.3 Connect Return code
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectReturnCode {
    Accepted { session_present: bool },
    Refused(ConnectionRefusedReason),
}

/// The reason the connection was refused by the server
///
/// Ref: 3.2.2.3 Connect Return code
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionRefusedReason {
    UnacceptableProtocolVersion,
    IdentifierRejected,
    ServerUnavailable,
    BadUserNameOrPassword,
    NotAuthorized,
    Other(u8),
}

impl ConnectReturnCode {
    fn from(code: u8, session_present: bool) -> Self {
        match code {
            0x00 => ConnectReturnCode::Accepted { session_present },
            0x01 => {
                ConnectReturnCode::Refused(ConnectionRefusedReason::UnacceptableProtocolVersion)
            }
            0x02 => ConnectReturnCode::Refused(ConnectionRefusedReason::IdentifierRejected),
            0x03 => ConnectReturnCode::Refused(ConnectionRefusedReason::ServerUnavailable),
            0x04 => ConnectReturnCode::Refused(ConnectionRefusedReason::BadUserNameOrPassword),
            0x05 => ConnectReturnCode::Refused(ConnectionRefusedReason::NotAuthorized),
            code => ConnectReturnCode::Refused(ConnectionRefusedReason::Other(code)),
        }
    }
}

impl From<ConnectReturnCode> for u8 {
    fn from(code: ConnectReturnCode) -> Self {
        match code {
            ConnectReturnCode::Accepted { .. } => 0x00,
            ConnectReturnCode::Refused(ConnectionRefusedReason::UnacceptableProtocolVersion) => {
                0x01
            }
            ConnectReturnCode::Refused(ConnectionRefusedReason::IdentifierRejected) => 0x02,
            ConnectReturnCode::Refused(ConnectionRefusedReason::ServerUnavailable) => 0x03,
            ConnectReturnCode::Refused(ConnectionRefusedReason::BadUserNameOrPassword) => 0x04,
            ConnectReturnCode::Refused(ConnectionRefusedReason::NotAuthorized) => 0x05,
            ConnectReturnCode::Refused(ConnectionRefusedReason::Other(code)) => code,
        }
    }
}

/// An MQTT packet
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet<P>
where
    P: BufferPool,
{
    /// Ref: 3.2 CONNACK – Acknowledge connection request
    ConnAck(ConnAck),

    /// Ref: 3.1 CONNECT – Client requests a connection to a Server
    Connect(Connect<P>),

    /// Ref: 3.14 DISCONNECT - Disconnect notification
    Disconnect(Disconnect),

    /// Ref: 3.12 PINGREQ – PING request
    PingReq(PingReq),

    /// Ref: 3.13 PINGRESP – PING response
    PingResp(PingResp),

    /// Ref: 3.4 PUBACK – Publish acknowledgement
    PubAck(PubAck),

    /// Ref: 3.7 PUBCOMP – Publish complete (QoS 2 publish received, part 3)
    PubComp(PubComp),

    /// 3.3 PUBLISH – Publish message
    Publish(Publish<P>),

    /// Ref: 3.5 PUBREC – Publish received (QoS 2 publish received, part 1)
    PubRec(PubRec),

    /// Ref: 3.6 PUBREL – Publish release (QoS 2 publish received, part 2)
    PubRel(PubRel),

    /// Ref: 3.9 SUBACK – Subscribe acknowledgement
    SubAck(SubAck),

    /// Ref: 3.8 SUBSCRIBE - Subscribe to topics
    Subscribe(Subscribe<P>),

    /// Ref: 3.11 UNSUBACK – Unsubscribe acknowledgement
    UnsubAck(UnsubAck),

    /// Ref: 3.10 UNSUBSCRIBE – Unsubscribe from topics
    Unsubscribe(Unsubscribe<P>),
}

/// Ref: 3.2 CONNACK – Acknowledge connection request
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnAck {
    pub return_code: ConnectReturnCode,
}

impl<P> PacketMeta<P> for ConnAck
where
    P: BufferPool,
{
    const PACKET_TYPE: u8 = 0x20;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let connack_flags = src.try_get_u8()?;
        let session_present = match connack_flags {
            0x00 => false,
            0x01 => true,
            connack_flags => {
                return Err(DecodeError::UnrecognizedConnAckFlags(connack_flags));
            }
        };

        let return_code = ConnectReturnCode::from(src.try_get_u8()?, session_present);

        Ok(ConnAck { return_code })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let ConnAck { return_code } = self;

        let session_present = if let ConnectReturnCode::Accepted { session_present } = return_code {
            session_present
        } else {
            false
        };
        if session_present {
            dst.try_put_u8(0x01)?;
        } else {
            dst.try_put_u8(0x00)?;
        }

        dst.try_put_u8(return_code.into())?;

        Ok(())
    }
}

/// Ref: 3.1 CONNECT – Client requests a connection to a Server
#[derive(Clone, Eq, PartialEq)]
pub struct Connect<P>
where
    P: BufferPool,
{
    pub username: Option<ByteStr<P>>,
    pub password: Option<ByteStr<P>>,
    pub will: Option<Publication<P>>,
    pub client_id: ClientId<P>,
    pub keep_alive: Duration,
}

impl<P> Connect<P>
where
    P: Clone + BufferPool,
{
    pub(crate) fn decode_rest(src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let connect_flags = src.try_get_u8()?;
        if connect_flags & 0x01 != 0 {
            return Err(DecodeError::ConnectReservedSet);
        }

        let keep_alive = Duration::from_secs(u64::from(src.try_get_u16_be()?));

        let client_id = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
        let client_id = if client_id.is_empty() {
            if connect_flags & 0x02 == 0 {
                return Err(DecodeError::ConnectZeroLengthIdWithExistingSession);
            }
            ClientId::ServerGenerated
        } else if connect_flags & 0x02 == 0 {
            ClientId::IdWithExistingSession(client_id)
        } else {
            ClientId::IdWithCleanSession(client_id)
        };

        let will = if connect_flags & 0x04 == 0 {
            None
        } else {
            let topic_name = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;

            let qos = match connect_flags & 0x18 {
                0x00 => QoS::AtMostOnce,
                0x08 => QoS::AtLeastOnce,
                0x10 => QoS::ExactlyOnce,
                qos => return Err(DecodeError::UnrecognizedQoS(qos >> 3)),
            };

            let retain = connect_flags & 0x20 != 0;

            let payload_len = usize::from(src.try_get_u16_be()?);
            if src.len() < payload_len {
                return Err(DecodeError::IncompletePacket);
            }
            let payload = src.split_to(payload_len);

            Some(Publication {
                topic_name,
                qos,
                retain,
                payload,
            })
        };

        let username = if connect_flags & 0x80 == 0 {
            None
        } else {
            Some(ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?)
        };

        let password = if connect_flags & 0x40 == 0 {
            None
        } else {
            Some(ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?)
        };

        Ok(Connect {
            username,
            password,
            will,
            client_id,
            keep_alive,
        })
    }
}

impl<P> std::fmt::Debug for Connect<P>
where
    P: BufferPool,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connect")
            .field("username", &self.username)
            .field("will", &self.will)
            .field("client_id", &self.client_id)
            .field("keep_alive", &self.keep_alive)
            .finish()
    }
}

impl<P> PacketMeta<P> for Connect<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0x10;

    fn decode(flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let protocol_level = decode_connect_start(flags, src)?;
        if protocol_level != PROTOCOL_LEVEL {
            return Err(DecodeError::UnrecognizedProtocolVersion(protocol_level));
        }

        Self::decode_rest(src)
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let Connect {
            username,
            password,
            will,
            client_id,
            keep_alive,
        } = self;

        dst.try_put_slice(crate::PROTOCOL_NAME)?;

        dst.try_put_u8(PROTOCOL_LEVEL)?;

        {
            let mut connect_flags = 0b0000_0000_u8;
            if username.is_some() {
                connect_flags |= 0b1000_0000;
            }
            if password.is_some() {
                connect_flags |= 0b0100_0000;
            }
            if let Some(will) = &will {
                connect_flags |= 0b0000_0100;
                if will.retain {
                    connect_flags |= 0b0010_0000;
                }
                connect_flags |= u8::from(will.qos) << 3;
            }
            match client_id {
                ClientId::ServerGenerated | ClientId::IdWithCleanSession(_) => {
                    connect_flags |= 0b0000_0010;
                }
                ClientId::IdWithExistingSession(_) => (),
            }
            dst.try_put_u8(connect_flags)?;
        }

        dst.try_put_u16_be(
            keep_alive
                .as_secs()
                .try_into()
                .map_err(|_| EncodeError::KeepAliveTooHigh(keep_alive))?,
        )?;

        match client_id {
            ClientId::ServerGenerated => dst.try_put_slice(ByteStr::<P>::EMPTY)?,
            ClientId::IdWithCleanSession(id) | ClientId::IdWithExistingSession(id) => {
                id.encode(dst)?
            }
        }

        if let Some(will) = will {
            let Publication {
                topic_name,
                qos: _,    // Encoded in connect_flags above
                retain: _, // Encoded in connect_flags above
                payload,
            } = will;

            topic_name.encode(dst)?;

            let will_len = payload.len();
            dst.try_put_u16_be(
                will_len
                    .try_into()
                    .map_err(|_| EncodeError::WillTooLarge(will_len))?,
            )?;

            dst.try_put_bytes(payload)?;
        }

        if let Some(username) = username {
            username.encode(dst)?;
        }

        if let Some(password) = password {
            password.encode(dst)?;
        }

        Ok(())
    }
}

/// Ref: 3.14 DISCONNECT - Disconnect notification
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Disconnect;

impl<P> PacketMeta<P> for Disconnect
where
    P: BufferPool,
{
    const PACKET_TYPE: u8 = 0xE0;

    fn decode(_flags: u8, _src: &mut Shared<P>) -> Result<Self, DecodeError> {
        Ok(Disconnect)
    }

    fn encode<B>(self, _dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        Ok(())
    }
}

/// Ref: 3.12 PINGREQ – PING request
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingReq;

impl<P> PacketMeta<P> for PingReq
where
    P: BufferPool,
{
    const PACKET_TYPE: u8 = 0xC0;

    fn decode(_flags: u8, _src: &mut Shared<P>) -> Result<Self, DecodeError> {
        Ok(PingReq)
    }

    fn encode<B>(self, _dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        Ok(())
    }
}

/// Ref: 3.13 PINGRESP – PING response
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingResp;

impl<P> PacketMeta<P> for PingResp
where
    P: BufferPool,
{
    const PACKET_TYPE: u8 = 0xD0;

    fn decode(_flags: u8, _src: &mut Shared<P>) -> Result<Self, DecodeError> {
        Ok(PingResp)
    }

    fn encode<B>(self, _dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        Ok(())
    }
}

/// Ref: 3.4 PUBACK – Publish acknowledgement
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubAck {
    pub packet_identifier: PacketIdentifier,
}

impl<P> PacketMeta<P> for PubAck
where
    P: BufferPool,
{
    const PACKET_TYPE: u8 = 0x40;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        Ok(PubAck { packet_identifier })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let PubAck { packet_identifier } = self;
        dst.try_put_packet_identifier(packet_identifier)?;
        Ok(())
    }
}

#[allow(clippy::doc_markdown)]
/// Ref: 3.7 PUBCOMP – Publish complete (QoS 2 publish received, part 3)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubComp {
    pub packet_identifier: PacketIdentifier,
}

impl<P> PacketMeta<P> for PubComp
where
    P: BufferPool,
{
    const PACKET_TYPE: u8 = 0x70;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        Ok(PubComp { packet_identifier })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let PubComp { packet_identifier } = self;
        dst.try_put_packet_identifier(packet_identifier)?;
        Ok(())
    }
}

/// 3.3 PUBLISH – Publish message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publish<P>
where
    P: BufferPool,
{
    pub packet_identifier_dup_qos: PacketIdentifierDupQoS,
    pub retain: bool,
    pub topic_name: ByteStr<P>,
    pub payload: Shared<P>,
}

impl<P> PacketMeta<P> for Publish<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0x30;

    fn decode(flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let dup = (flags & 0x08) != 0;
        let retain = (flags & 0x01) != 0;

        let topic_name = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;

        let packet_identifier_dup_qos = match (flags & 0x06) >> 1 {
            0x00 if dup => return Err(DecodeError::PublishDupAtMostOnce),

            0x00 => PacketIdentifierDupQoS::AtMostOnce,

            0x01 => {
                let packet_identifier = src.try_get_packet_identifier()?;
                PacketIdentifierDupQoS::AtLeastOnce(packet_identifier, dup)
            }

            0x02 => {
                let packet_identifier = src.try_get_packet_identifier()?;
                PacketIdentifierDupQoS::ExactlyOnce(packet_identifier, dup)
            }

            qos => return Err(DecodeError::UnrecognizedQoS(qos)),
        };

        let payload = src.split_to(src.len());

        Ok(Publish {
            packet_identifier_dup_qos,
            retain,
            topic_name,
            payload,
        })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        #[allow(clippy::unneeded_field_pattern)]
        let Publish {
            packet_identifier_dup_qos,
            retain: _,
            topic_name,
            payload,
        } = self;

        topic_name.encode(dst)?;

        match packet_identifier_dup_qos {
            PacketIdentifierDupQoS::AtMostOnce => (),
            PacketIdentifierDupQoS::AtLeastOnce(packet_identifier, _)
            | PacketIdentifierDupQoS::ExactlyOnce(packet_identifier, _) => {
                dst.try_put_packet_identifier(packet_identifier)?
            }
        }

        dst.try_put_bytes(payload)?;

        Ok(())
    }
}

#[allow(clippy::doc_markdown)]
/// Ref: 3.5 PUBREC – Publish received (QoS 2 publish received, part 1)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubRec {
    pub packet_identifier: PacketIdentifier,
}

impl<P> PacketMeta<P> for PubRec
where
    P: BufferPool,
{
    const PACKET_TYPE: u8 = 0x50;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        Ok(PubRec { packet_identifier })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let PubRec { packet_identifier } = self;
        dst.try_put_packet_identifier(packet_identifier)?;
        Ok(())
    }
}

#[allow(clippy::doc_markdown)]
/// Ref: 3.6 PUBREL – Publish release (QoS 2 publish received, part 2)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubRel {
    pub packet_identifier: PacketIdentifier,
}

impl<P> PacketMeta<P> for PubRel
where
    P: BufferPool,
{
    const PACKET_TYPE: u8 = 0x60;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        Ok(PubRel { packet_identifier })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let PubRel { packet_identifier } = self;
        dst.try_put_packet_identifier(packet_identifier)?;
        Ok(())
    }
}

/// Ref: 3.9 SUBACK – Subscribe acknowledgement
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubAck {
    pub packet_identifier: PacketIdentifier,
    pub qos: Vec<SubAckQos>,
}

impl<P> PacketMeta<P> for SubAck
where
    P: BufferPool,
{
    const PACKET_TYPE: u8 = 0x90;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        let qos: Result<Vec<_>, _> = src
            .as_ref()
            .iter()
            .map(|&qos| match qos {
                0x00 => Ok(SubAckQos::Success(QoS::AtMostOnce)),
                0x01 => Ok(SubAckQos::Success(QoS::AtLeastOnce)),
                0x02 => Ok(SubAckQos::Success(QoS::ExactlyOnce)),
                0x80 => Ok(SubAckQos::Failure),
                qos => Err(DecodeError::UnrecognizedQoS(qos)),
            })
            .collect();
        let qos = qos?;
        src.drain(qos.len());

        if qos.is_empty() {
            return Err(DecodeError::NoTopics);
        }

        Ok(SubAck {
            packet_identifier,
            qos,
        })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let SubAck {
            packet_identifier,
            qos,
        } = self;

        dst.try_put_packet_identifier(packet_identifier)?;

        for qos in qos {
            dst.try_put_u8(qos.into())?;
        }

        Ok(())
    }
}

/// Ref: 3.8 SUBSCRIBE - Subscribe to topics
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Subscribe<P>
where
    P: BufferPool,
{
    pub packet_identifier: PacketIdentifier,
    pub subscribe_to: Vec<SubscribeTo<P>>,
}

impl<P> PacketMeta<P> for Subscribe<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0x80;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        let mut subscribe_to = vec![];

        while !src.is_empty() {
            let topic_filter = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
            let qos = match src.try_get_u8()? {
                0x00 => QoS::AtMostOnce,
                0x01 => QoS::AtLeastOnce,
                0x02 => QoS::ExactlyOnce,
                qos => return Err(DecodeError::UnrecognizedQoS(qos)),
            };
            subscribe_to.push(SubscribeTo { topic_filter, qos });
        }

        if subscribe_to.is_empty() {
            return Err(DecodeError::NoTopics);
        }

        Ok(Subscribe {
            packet_identifier,
            subscribe_to,
        })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let Subscribe {
            packet_identifier,
            subscribe_to,
        } = self;

        dst.try_put_packet_identifier(packet_identifier)?;

        for SubscribeTo { topic_filter, qos } in subscribe_to {
            topic_filter.encode(dst)?;
            dst.try_put_u8(qos.into())?;
        }

        Ok(())
    }
}

/// Ref: 3.11 UNSUBACK – Unsubscribe acknowledgement
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsubAck {
    pub packet_identifier: PacketIdentifier,
}

impl<P> PacketMeta<P> for UnsubAck
where
    P: BufferPool,
{
    const PACKET_TYPE: u8 = 0xB0;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        Ok(UnsubAck { packet_identifier })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let UnsubAck { packet_identifier } = self;
        dst.try_put_packet_identifier(packet_identifier)?;
        Ok(())
    }
}

/// Ref: 3.10 UNSUBSCRIBE – Unsubscribe from topics
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unsubscribe<P>
where
    P: BufferPool,
{
    pub packet_identifier: PacketIdentifier,
    pub unsubscribe_from: Vec<ByteStr<P>>,
}

impl<P> PacketMeta<P> for Unsubscribe<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0xA0;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        let mut unsubscribe_from = vec![];

        while !src.is_empty() {
            unsubscribe_from.push(ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?);
        }

        if unsubscribe_from.is_empty() {
            return Err(DecodeError::NoTopics);
        }

        Ok(Unsubscribe {
            packet_identifier,
            unsubscribe_from,
        })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let Unsubscribe {
            packet_identifier,
            unsubscribe_from,
        } = self;

        dst.try_put_packet_identifier(packet_identifier)?;

        for unsubscribe_from in unsubscribe_from {
            unsubscribe_from.encode(dst)?;
        }

        Ok(())
    }
}

#[allow(clippy::doc_markdown)]
/// A combination of the packet identifier, dup flag and QoS that only allows valid combinations of these three properties.
/// Used in [`Packet::Publish`]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketIdentifierDupQoS {
    AtMostOnce,
    AtLeastOnce(PacketIdentifier, bool),
    ExactlyOnce(PacketIdentifier, bool),
}

/// A subscription request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscribeTo<P>
where
    P: BufferPool,
{
    pub topic_filter: ByteStr<P>,
    pub qos: QoS,
}

#[allow(clippy::doc_markdown)]
/// QoS returned in a SUBACK packet. Either one of the [`QoS`] values, or an error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubAckQos {
    Success(QoS),
    Failure,
}

impl From<SubAckQos> for u8 {
    fn from(qos: SubAckQos) -> Self {
        match qos {
            SubAckQos::Success(qos) => qos.into(),
            SubAckQos::Failure => 0x80,
        }
    }
}

/// A message that can be published to the server
//  but not yet assigned a packet identifier.
#[derive(Clone, Eq, PartialEq)]
pub struct Publication<P>
where
    P: BufferPool,
{
    pub topic_name: ByteStr<P>,
    pub qos: QoS,
    pub retain: bool,
    pub payload: Shared<P>,
}

impl<P> std::fmt::Debug for Publication<P>
where
    P: BufferPool,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Publication")
            .field("topic_name", &self.topic_name)
            .field("qos", &self.qos)
            .field("retain", &self.retain)
            .field("payload", &self.payload)
            .finish()
    }
}

/// Decode the body (variable header + payload) of an MQTT packet.
///
/// Ref: 2 MQTT Control Packet format
pub fn decode<P>(first_byte: u8, mut body: Shared<P>) -> Result<Packet<P>, DecodeError>
where
    P: Clone + BufferPool,
{
    let packet_type = first_byte & 0xF0;
    let flags = first_byte & 0x0F;

    let packet = match (packet_type, flags) {
        (<ConnAck as PacketMeta<P>>::PACKET_TYPE, 0) => {
            Packet::ConnAck(ConnAck::decode(flags, &mut body)?)
        }

        (Connect::<P>::PACKET_TYPE, 0) => Packet::Connect(Connect::decode(flags, &mut body)?),

        (<Disconnect as PacketMeta<P>>::PACKET_TYPE, 0) => {
            Packet::Disconnect(Disconnect::decode(flags, &mut body)?)
        }

        (<PingReq as PacketMeta<P>>::PACKET_TYPE, 0) => {
            Packet::PingReq(PingReq::decode(flags, &mut body)?)
        }

        (<PingResp as PacketMeta<P>>::PACKET_TYPE, 0) => {
            Packet::PingResp(PingResp::decode(flags, &mut body)?)
        }

        (<PubAck as PacketMeta<P>>::PACKET_TYPE, 0) => {
            Packet::PubAck(PubAck::decode(flags, &mut body)?)
        }

        (<PubComp as PacketMeta<P>>::PACKET_TYPE, 0) => {
            Packet::PubComp(PubComp::decode(flags, &mut body)?)
        }

        (Publish::<P>::PACKET_TYPE, flags) => Packet::Publish(Publish::decode(flags, &mut body)?),

        (<PubRec as PacketMeta<P>>::PACKET_TYPE, 0) => {
            Packet::PubRec(PubRec::decode(flags, &mut body)?)
        }

        (<PubRel as PacketMeta<P>>::PACKET_TYPE, 2) => {
            Packet::PubRel(PubRel::decode(flags, &mut body)?)
        }

        (<SubAck as PacketMeta<P>>::PACKET_TYPE, 0) => {
            Packet::SubAck(SubAck::decode(flags, &mut body)?)
        }

        (Subscribe::<P>::PACKET_TYPE, 2) => Packet::Subscribe(Subscribe::decode(flags, &mut body)?),

        (<UnsubAck as PacketMeta<P>>::PACKET_TYPE, 0) => {
            Packet::UnsubAck(UnsubAck::decode(flags, &mut body)?)
        }

        (Unsubscribe::<P>::PACKET_TYPE, 2) => {
            Packet::Unsubscribe(Unsubscribe::decode(flags, &mut body)?)
        }

        (packet_type, flags) => {
            return Err(DecodeError::UnrecognizedPacket {
                packet_type,
                flags,
                remaining_length: body.len(),
            });
        }
    };

    if !body.is_empty() {
        return Err(DecodeError::TrailingGarbage);
    }

    Ok(packet)
}

pub fn encode<B, P>(item: Packet<P>, dst: &mut B) -> Result<(), EncodeError>
where
    B: ByteBuf,
    P: Clone + BufferPool,
{
    fn encode_inner<B, P, TPacket>(
        packet: TPacket,
        flags: u8,
        dst: &mut B,
    ) -> Result<(), EncodeError>
    where
        B: ByteBuf,
        P: Clone + BufferPool,
        TPacket: PacketMeta<P>,
    {
        let mut counter: ByteCounter = Default::default();
        packet.clone().encode(&mut counter)?;
        let body_len = counter.0;

        dst.try_put_u8(TPacket::PACKET_TYPE | flags)?;
        encode_remaining_length(body_len, dst)?;
        packet.encode(dst)?;

        Ok(())
    }

    match item {
        Packet::ConnAck(packet) => encode_inner::<_, P, _>(packet, 0, dst),
        Packet::Connect(packet) => encode_inner(packet, 0, dst),
        Packet::Disconnect(packet) => encode_inner::<_, P, _>(packet, 0, dst),
        Packet::PingReq(packet) => encode_inner::<_, P, _>(packet, 0, dst),
        Packet::PingResp(packet) => encode_inner::<_, P, _>(packet, 0, dst),
        Packet::PubAck(packet) => encode_inner::<_, P, _>(packet, 0, dst),
        Packet::PubComp(packet) => encode_inner::<_, P, _>(packet, 0, dst),
        Packet::Publish(packet) => {
            let mut flags = match packet.packet_identifier_dup_qos {
                PacketIdentifierDupQoS::AtMostOnce => 0x00,
                PacketIdentifierDupQoS::AtLeastOnce(_, true) => 0x0A,
                PacketIdentifierDupQoS::AtLeastOnce(_, false) => 0x02,
                PacketIdentifierDupQoS::ExactlyOnce(_, true) => 0x0C,
                PacketIdentifierDupQoS::ExactlyOnce(_, false) => 0x04,
            };
            if packet.retain {
                flags |= 0x01;
            };
            encode_inner(packet, flags, dst)
        }
        Packet::PubRec(packet) => encode_inner::<_, P, _>(packet, 0, dst),
        Packet::PubRel(packet) => encode_inner::<_, P, _>(packet, 0x02, dst),
        Packet::SubAck(packet) => encode_inner::<_, P, _>(packet, 0, dst),
        Packet::Subscribe(packet) => encode_inner(packet, 0x02, dst),
        Packet::UnsubAck(packet) => encode_inner::<_, P, _>(packet, 0, dst),
        Packet::Unsubscribe(packet) => encode_inner(packet, 0x02, dst),
    }
}
