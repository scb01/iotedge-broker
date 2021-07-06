// Copyright (c) Microsoft. All rights reserved.

use super::{PacketMeta, Property};
use crate::{BufferPool, ByteBuf, ByteStr, DecodeError, EncodeError, PacketIdentifier, Shared};

/// Ref: 3.10 UNSUBSCRIBE – Unsubscribe from topics
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unsubscribe<P>
where
    P: BufferPool,
{
    pub packet_identifier: PacketIdentifier,
    pub user_properties: Vec<(ByteStr<P>, ByteStr<P>)>,
    pub unsubscribe_from: Vec<ByteStr<P>>,
}

impl<P> PacketMeta<P> for Unsubscribe<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0xA0;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let packet_identifier = src.try_get_packet_identifier()?;

        decode_properties!(src, user_properties: Vec<UserProperty>,);

        let mut unsubscribe_from = vec![];

        while !src.is_empty() {
            unsubscribe_from.push(ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?);
        }

        if unsubscribe_from.is_empty() {
            return Err(DecodeError::NoTopics);
        }

        Ok(Unsubscribe {
            packet_identifier,
            user_properties,
            unsubscribe_from,
        })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let Unsubscribe {
            packet_identifier,
            user_properties,
            unsubscribe_from,
        } = self;

        dst.try_put_packet_identifier(packet_identifier)?;

        encode_properties!(dst, user_properties: Vec<UserProperty>,);

        for unsubscribe_from in unsubscribe_from {
            unsubscribe_from.encode(dst)?;
        }

        Ok(())
    }
}
