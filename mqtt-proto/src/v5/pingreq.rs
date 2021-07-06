// Copyright (c) Microsoft. All rights reserved.

use super::PacketMeta;
use crate::{BufferPool, ByteBuf, DecodeError, EncodeError, Shared};

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
