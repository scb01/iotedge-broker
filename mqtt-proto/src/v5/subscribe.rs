// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryInto;

use super::{PacketMeta, Property};
use crate::{
    BufferPool, ByteBuf, ByteStr, DecodeError, EncodeError, PacketIdentifier, QoS, Shared,
};

/// Ref: 3.8 SUBSCRIBE - Subscribe to topics
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Subscribe<P>
where
    P: BufferPool,
{
    pub packet_identifier: PacketIdentifier,
    pub subscription_identifier: Option<usize>,
    pub user_properties: Vec<(ByteStr<P>, ByteStr<P>)>,
    pub subscribe_to: Vec<SubscribeTo<P>>,
}

/// A subscription request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscribeTo<P>
where
    P: BufferPool,
{
    pub topic_filter: ByteStr<P>,
    pub maximum_qos: QoS,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: RetainHandling,
}

define_u8_code! {
    /// Ref: 3.8.3.1 Subscription Options
    RetainHandling,
    UnrecognizedRetainHandling,
    Send = 0x00,
    SendOnlyIfSubscriptionDoesNotCurrentlyExist = 0x01,
    DoNotSend = 0x02,
}

impl<P> PacketMeta<P> for Subscribe<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0x80;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        decode_properties!(
            src,
            subscription_identifier: SubscriptionIdentifier,
            user_properties: Vec<UserProperty>,
        );

        let mut subscribe_to = vec![];

        while !src.is_empty() {
            let topic_filter = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;

            let options = src.try_get_u8()?;

            let maximum_qos = (options & 0b0000_0011).try_into()?;

            let no_local = (options & 0b0000_0100) != 0;

            let retain_as_published = (options & 0b0000_1000) != 0;

            let retain_handling = ((options & 0b0011_0000) >> 4).try_into()?;

            if (options & 0b1100_0000) != 0 {
                return Err(DecodeError::SubscriptionOptionsReservedSet);
            }

            subscribe_to.push(SubscribeTo {
                topic_filter,
                maximum_qos,
                no_local,
                retain_as_published,
                retain_handling,
            });
        }

        if subscribe_to.is_empty() {
            return Err(DecodeError::NoTopics);
        }

        Ok(Subscribe {
            packet_identifier,
            subscription_identifier,
            user_properties,
            subscribe_to,
        })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let Subscribe {
            packet_identifier,
            subscription_identifier,
            user_properties,
            subscribe_to,
        } = self;

        dst.try_put_packet_identifier(packet_identifier)?;

        encode_properties!(
            dst,
            subscription_identifier: Option<SubscriptionIdentifier>,
            user_properties: Vec<UserProperty>,
        );

        for SubscribeTo {
            topic_filter,
            maximum_qos,
            no_local,
            retain_as_published,
            retain_handling,
        } in subscribe_to
        {
            topic_filter.encode(dst)?;

            let mut subscription_options = 0_u8;
            subscription_options |= u8::from(maximum_qos);
            if no_local {
                subscription_options |= 0b0000_0100;
            }
            if retain_as_published {
                subscription_options |= 0b0000_1000;
            }
            subscription_options |= u8::from(retain_handling) << 4;

            dst.try_put_u8(subscription_options)?;
        }

        Ok(())
    }
}
