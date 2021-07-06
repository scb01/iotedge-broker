// Copyright (c) Microsoft. All rights reserved.

use super::PacketMeta;
use crate::{BufferPool, ByteBuf, DecodeError, EncodeError, Shared};

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
