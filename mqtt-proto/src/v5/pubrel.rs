// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryInto;

use super::{PacketMeta, Property};
use crate::{BufferPool, ByteBuf, ByteStr, DecodeError, EncodeError, PacketIdentifier, Shared};

#[allow(clippy::doc_markdown)]
/// Ref: 3.6 PUBREL – Publish release (QoS 2 publish received, part 2)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubRel<P>
where
    P: BufferPool,
{
    pub packet_identifier: PacketIdentifier,
    pub reason_code: PubRelReasonCode,
    pub reason_string: Option<ByteStr<P>>,
    pub user_properties: Vec<(ByteStr<P>, ByteStr<P>)>,
}

define_u8_code! {
    /// Ref: 3.6.2.1 PUBREL Reason Code
    PubRelReasonCode,
    UnrecognizedPubRelReasonCode,
    Success = 0x00,
    PacketIdentifierNotFound = 0x92,
}

impl<P> PacketMeta<P> for PubRel<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0x60;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        match src.try_get_u8() {
            Ok(reason_code) => {
                let reason_code = reason_code.try_into()?;

                decode_properties!(
                    src,
                    reason_string: ReasonString,
                    user_properties: Vec<UserProperty>,
                );

                Ok(PubRel {
                    packet_identifier,
                    reason_code,
                    reason_string,
                    user_properties,
                })
            }

            Err(DecodeError::IncompletePacket) => Ok(PubRel {
                packet_identifier,
                reason_code: PubRelReasonCode::Success,
                reason_string: None,
                user_properties: vec![],
            }),

            Err(err) => Err(err),
        }
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let PubRel {
            packet_identifier,
            reason_code,
            reason_string,
            user_properties,
        } = self;

        dst.try_put_packet_identifier(packet_identifier)?;

        let need_variable_header = reason_code != PubRelReasonCode::Success
            || reason_string.is_some()
            || !user_properties.is_empty();
        if need_variable_header {
            dst.try_put_u8(reason_code.into())?;

            encode_properties!(
                dst,
                reason_string: Option<ReasonString>,
                user_properties: Vec<UserProperty>,
            );
        }

        Ok(())
    }
}
