// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryInto;

use super::{PacketMeta, Property};
use crate::{BufferPool, ByteBuf, ByteStr, DecodeError, EncodeError, Shared};

/// Ref: 3.2 CONNACK – Acknowledge connection request
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Auth<P>
where
    P: BufferPool,
{
    pub reason_code: AuthenticateReasonCode,
    pub authentication_method: Option<ByteStr<P>>,
    pub authentication_data: Option<Shared<P>>,
    pub reason_string: Option<ByteStr<P>>,
    pub user_properties: Vec<(ByteStr<P>, ByteStr<P>)>,
}

define_u8_code! {
    /// Ref: 3.15.2.1 Authenticate Reason Code
    AuthenticateReasonCode,
    UnrecognizedAuthenticateReasonCode,
    Success = 0x00,
    ContinueAuthentication = 0x18,
    ReAuthenticate = 0x19,
}

impl<P> PacketMeta<P> for Auth<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0xF0;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        match src.try_get_u8() {
            Ok(reason_code) => {
                let reason_code = reason_code.try_into()?;

                decode_properties!(
                    src,
                    authentication_method: AuthenticationMethod,
                    authentication_data: AuthenticationData,
                    reason_string: ReasonString,
                    user_properties: Vec<UserProperty>,
                );

                Ok(Auth {
                    reason_code,
                    authentication_method: Some(authentication_method.ok_or(
                        DecodeError::MissingRequiredProperty("authentication method"),
                    )?),
                    authentication_data,
                    reason_string,
                    user_properties,
                })
            }

            Err(DecodeError::IncompletePacket) => Ok(Auth {
                reason_code: AuthenticateReasonCode::Success,
                authentication_method: None,
                authentication_data: None,
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
        let Auth {
            reason_code,
            authentication_method,
            authentication_data,
            reason_string,
            user_properties,
        } = self;

        let need_variable_header = reason_code != AuthenticateReasonCode::Success
            || authentication_method.is_some()
            || authentication_data.is_some()
            || reason_string.is_some()
            || !user_properties.is_empty();
        if need_variable_header {
            dst.try_put_u8(reason_code.into())?;

            encode_properties!(
                dst,
                authentication_method: Option<AuthenticationMethod>,
                authentication_data: Option<AuthenticationData>,
                reason_string: Option<ReasonString>,
                user_properties: Vec<UserProperty>,
            );
        }

        Ok(())
    }
}
