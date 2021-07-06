// Copyright (c) Microsoft. All rights reserved.

use std::time::Duration;

use super::{decode_connect_start, decode_remaining_length, encode_remaining_length};
use crate::{
    BufferPool, ByteBuf, ByteCounter, ByteStr, DecodeError, EncodeError, PacketMeta, QoS, Shared,
};

#[macro_use]
mod property;
use property::Property;

mod auth;
pub use auth::{Auth, AuthenticateReasonCode};

mod connack;
pub use connack::{ConnAck, ConnectReasonCode};

mod connect;
pub use connect::Connect;

mod disconnect;
pub use disconnect::{Disconnect, DisconnectReasonCode};

mod pingreq;
pub use pingreq::PingReq;

mod pingresp;
pub use pingresp::PingResp;

mod puback;
pub use puback::{PubAck, PubAckReasonCode};

mod pubcomp;
pub use pubcomp::{PubComp, PubCompReasonCode};

mod pubrec;
pub use pubrec::{PubRec, PubRecReasonCode};

mod pubrel;
pub use pubrel::{PubRel, PubRelReasonCode};

mod publish;
pub use publish::{PacketIdentifierDupQoS, Publish};

mod suback;
pub use suback::{SubAck, SubscribeReasonCode};

mod subscribe;
pub use subscribe::{RetainHandling, Subscribe, SubscribeTo};

mod unsuback;
pub use unsuback::{UnsubAck, UnsubscribeReasonCode};

mod unsubscribe;
pub use unsubscribe::Unsubscribe;

pub(crate) const PROTOCOL_VERSION: u8 = 0x05;

/// An MQTT packet
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet<P>
where
    P: BufferPool,
{
    /// Ref: 3.15 AUTH – Authentication exchange
    Auth(Auth<P>),

    /// Ref: 3.2 CONNACK – Connect acknowledgement
    ConnAck(ConnAck<P>),

    /// Ref: 3.1 CONNECT – Connection Request
    Connect(Connect<P>),

    /// Ref: 3.14 DISCONNECT - Disconnect notification
    Disconnect(Disconnect<P>),

    /// Ref: 3.12 PINGREQ – PING request
    PingReq(PingReq),

    /// Ref: 3.13 PINGRESP – PING response
    PingResp(PingResp),

    /// Ref: 3.4 PUBACK – Publish acknowledgement
    PubAck(PubAck<P>),

    /// Ref: 3.7 PUBCOMP – Publish complete (QoS 2 delivery part 3)
    PubComp(PubComp<P>),

    /// 3.3 PUBLISH – Publish message
    Publish(Publish<P>),

    /// Ref: 3.5 PUBREC – Publish received (QoS 2 delivery part 1)
    PubRec(PubRec<P>),

    /// Ref: 3.6 PUBREL – Publish release (QoS 2 delivery part 2)
    PubRel(PubRel<P>),

    /// Ref: 3.9 SUBACK – Subscribe acknowledgement
    SubAck(SubAck<P>),

    /// Ref: 3.8 SUBSCRIBE - Subscribe request
    Subscribe(Subscribe<P>),

    /// Ref: 3.11 UNSUBACK – Unsubscribe acknowledgement
    UnsubAck(UnsubAck<P>),

    /// Ref: 3.10 UNSUBSCRIBE – Unsubscribe request
    Unsubscribe(Unsubscribe<P>),
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
    pub payload_is_utf8: bool,
    pub message_expiry_interval: Option<Duration>,
    pub topic_alias: Option<u16>,
    pub response_topic: Option<ByteStr<P>>,
    pub correlation_data: Option<Shared<P>>,
    pub user_properties: Vec<(ByteStr<P>, ByteStr<P>)>,
    pub content_type: Option<ByteStr<P>>,
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
        (Auth::<P>::PACKET_TYPE, 0) => Packet::Auth(Auth::decode(flags, &mut body)?),

        (ConnAck::<P>::PACKET_TYPE, 0) => Packet::ConnAck(ConnAck::decode(flags, &mut body)?),

        (Connect::<P>::PACKET_TYPE, 0) => Packet::Connect(Connect::decode(flags, &mut body)?),

        (Disconnect::<P>::PACKET_TYPE, 0) => {
            Packet::Disconnect(Disconnect::decode(flags, &mut body)?)
        }

        (<PingReq as PacketMeta<P>>::PACKET_TYPE, 0) => {
            Packet::PingReq(PingReq::decode(flags, &mut body)?)
        }

        (<PingResp as PacketMeta<P>>::PACKET_TYPE, 0) => {
            Packet::PingResp(PingResp::decode(flags, &mut body)?)
        }

        (PubAck::<P>::PACKET_TYPE, 0) => Packet::PubAck(PubAck::decode(flags, &mut body)?),

        (PubComp::<P>::PACKET_TYPE, 0) => Packet::PubComp(PubComp::decode(flags, &mut body)?),

        (Publish::<P>::PACKET_TYPE, flags) => Packet::Publish(Publish::decode(flags, &mut body)?),

        (PubRec::<P>::PACKET_TYPE, 0) => Packet::PubRec(PubRec::decode(flags, &mut body)?),

        (PubRel::<P>::PACKET_TYPE, 2) => Packet::PubRel(PubRel::decode(flags, &mut body)?),

        (SubAck::<P>::PACKET_TYPE, 0) => Packet::SubAck(SubAck::decode(flags, &mut body)?),

        (Subscribe::<P>::PACKET_TYPE, 2) => Packet::Subscribe(Subscribe::decode(flags, &mut body)?),

        (UnsubAck::<P>::PACKET_TYPE, 0) => Packet::UnsubAck(UnsubAck::decode(flags, &mut body)?),

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
        Packet::Auth(packet) => encode_inner::<_, P, _>(packet, 0, dst),
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
