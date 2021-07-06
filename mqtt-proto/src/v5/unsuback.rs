// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryInto;

use super::{PacketMeta, Property};
use crate::{BufferPool, ByteBuf, ByteStr, DecodeError, EncodeError, PacketIdentifier, Shared};

/// Ref: 3.11 UNSUBACK – Unsubscribe acknowledgement
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsubAck<P>
where
    P: BufferPool,
{
    pub packet_identifier: PacketIdentifier,
    pub reason_string: Option<ByteStr<P>>,
    pub user_properties: Vec<(ByteStr<P>, ByteStr<P>)>,
    pub reason_codes: Vec<UnsubscribeReasonCode>,
}

define_u8_code! {
    /// Ref: 3.11.3 UNSUBACK Payload
    UnsubscribeReasonCode,
    UnrecognizedUnsubscribeReasonCode,
    Success = 0x00,
    NoSubscriptionExisted = 0x01,
    UnspecifiedError = 0x80,
    ImplementationSpecificError = 0x83,
    NotAuthorized = 0x87,
    TopicFilterInvalid = 0x8F,
    PacketIdentifierInUse = 0x91,
}

impl<P> PacketMeta<P> for UnsubAck<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0xB0;

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

        Ok(UnsubAck {
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
        let UnsubAck {
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
