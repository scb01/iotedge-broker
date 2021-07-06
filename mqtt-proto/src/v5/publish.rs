// Copyright (c) Microsoft. All rights reserved.

use std::time::Duration;

use super::{PacketMeta, Property};
use crate::{BufferPool, ByteBuf, ByteStr, DecodeError, EncodeError, PacketIdentifier, Shared};

/// 3.3 PUBLISH – Publish message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publish<P>
where
    P: BufferPool,
{
    pub topic_name: ByteStr<P>,
    pub packet_identifier_dup_qos: PacketIdentifierDupQoS,
    pub retain: bool,
    pub payload_is_utf8: bool,
    pub message_expiry_interval: Option<Duration>,
    pub topic_alias: Option<u16>,
    pub response_topic: Option<ByteStr<P>>,
    pub correlation_data: Option<Shared<P>>,
    pub user_properties: Vec<(ByteStr<P>, ByteStr<P>)>,
    pub subscription_identifiers: Vec<usize>,
    pub content_type: Option<ByteStr<P>>,
    pub payload: Shared<P>,
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

impl<P> PacketMeta<P> for Publish<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0x30;

    fn decode(flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let dup = (flags & 0b0000_1000) != 0;
        let retain = (flags & 0b0000_0001) != 0;

        let topic_name = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;

        let packet_identifier_dup_qos = match (flags & 0b0000_0110) >> 1 {
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

        decode_properties!(
            src,
            payload_is_utf8: PayloadIsUtf8,
            message_expiry_interval: MessageExpiryInterval,
            topic_alias: TopicAlias,
            response_topic: ResponseTopic,
            correlation_data: CorrelationData,
            user_properties: Vec<UserProperty>,
            subscription_identifiers: Vec<SubscriptionIdentifier>,
            content_type: ContentType,
        );

        let payload = src.split_to(src.len());

        Ok(Publish {
            topic_name,
            packet_identifier_dup_qos,
            retain,
            payload_is_utf8: payload_is_utf8.unwrap_or(false),
            message_expiry_interval,
            topic_alias,
            response_topic,
            correlation_data,
            user_properties,
            subscription_identifiers,
            content_type,
            payload,
        })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        #[allow(clippy::unneeded_field_pattern)]
        let Publish {
            topic_name,
            packet_identifier_dup_qos,
            retain: _,
            payload_is_utf8,
            message_expiry_interval,
            topic_alias,
            response_topic,
            correlation_data,
            user_properties,
            subscription_identifiers,
            content_type,
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

        encode_properties!(
            dst,
            payload_is_utf8: PayloadIsUtf8,
            message_expiry_interval: Option<MessageExpiryInterval>,
            topic_alias: Option<TopicAlias>,
            response_topic: Option<ResponseTopic>,
            correlation_data: Option<CorrelationData>,
            user_properties: Vec<UserProperty>,
            subscription_identifiers: Vec<SubscriptionIdentifier>,
            content_type: Option<ContentType>,
        );

        dst.try_put_bytes(payload)?;

        Ok(())
    }
}
