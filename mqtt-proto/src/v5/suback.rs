// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryInto;

use super::{PacketMeta, Property};
use crate::{BufferPool, ByteBuf, ByteStr, DecodeError, EncodeError, PacketIdentifier, Shared};

/// Ref: 3.9 SUBACK – Subscribe acknowledgement
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubAck<P>
where
    P: BufferPool,
{
    pub packet_identifier: PacketIdentifier,
    pub reason_string: Option<ByteStr<P>>,
    pub user_properties: Vec<(ByteStr<P>, ByteStr<P>)>,
    pub reason_codes: Vec<SubscribeReasonCode>,
}

define_u8_code! {
    /// Ref: 3.9.3 SUBACK Payload
    SubscribeReasonCode,
    UnrecognizedSubscribeReasonCode,
    GrantedQoS0 = 0x00,
    GrantedQoS1 = 0x01,
    GrantedQoS2 = 0x02,
    UnspecifiedError = 0x80,
    ImplementationSpecificError = 0x83,
    NotAuthorized = 0x87,
    TopicFilterInvalid = 0x8F,
    PacketIdentifierInUse = 0x91,
    QuotaExceeded = 0x97,
    SharedSubscriptionsNotSupported = 0x9E,
    SubscriptionIdentifiersNotSupported = 0xA1,
    WildcardSubscriptionsNotSupported = 0xA2,
}

impl<P> PacketMeta<P> for SubAck<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0x90;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        decode_properties!(
            src,
            reason_string: ReasonString,
            user_properties: Vec<UserProperty>,
        );

        let reason_codes: Result<Vec<_>, _> = src
            .as_ref()
            .iter()
            .map(|&reason_code| reason_code.try_into())
            .collect();
        let reason_codes = reason_codes?;
        src.drain(reason_codes.len());

        if reason_codes.is_empty() {
            return Err(DecodeError::NoTopics);
        }

        Ok(SubAck {
            packet_identifier,
            reason_string,
            user_properties,
            reason_codes,
        })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let SubAck {
            packet_identifier,
            reason_string,
            user_properties,
            reason_codes,
        } = self;

        dst.try_put_packet_identifier(packet_identifier)?;

        encode_properties!(
            dst,
            reason_string: Option<ReasonString>,
            user_properties: Vec<UserProperty>,
        );

        for reason_code in reason_codes {
            dst.try_put_u8(reason_code.into())?;
        }

        Ok(())
    }
}
