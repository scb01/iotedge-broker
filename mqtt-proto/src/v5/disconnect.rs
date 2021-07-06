// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryInto;
use std::time::Duration;

use super::{PacketMeta, Property};
use crate::{BufferPool, ByteBuf, ByteStr, DecodeError, EncodeError, Shared};

/// Ref: 3.14 DISCONNECT - Disconnect notification
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Disconnect<P>
where
    P: BufferPool,
{
    reason_code: DisconnectReasonCode,
    session_expiry_interval: Option<Duration>,
    reason_string: Option<ByteStr<P>>,
    user_properties: Vec<(ByteStr<P>, ByteStr<P>)>,
    server_reference: Option<ByteStr<P>>,
}

define_u8_code! {
    /// Ref: 3.14.2.1 Disconnect Reason Code
    DisconnectReasonCode,
    UnrecognizedDisconnectReasonCode,
    Normal = 0x00,
    DisconnectWithWillMessage = 0x04,
    UnspecifiedError = 0x80,
    MalformedPacket = 0x81,
    ProtocolError = 0x82,
    ImplementationSpecificError = 0x83,
    NotAuthorized = 0x87,
    ServerBusy = 0x89,
    ServerShuttingDown = 0x8B,
    KeepAliveTimeout = 0x8D,
    SessionTakenOver = 0x8E,
    TopicFilterInvalid = 0x8F,
    TopicNameInvalid = 0x90,
    ReceiveMaximumExceeded = 0x93,
    TopicAliasInvalid = 0x94,
    PacketTooLarge = 0x95,
    MessageRateTooHigh = 0x96,
    QuotaExceeded = 0x97,
    AdministrativeAction = 0x98,
    PayloadFormatInvalid = 0x99,
    RetainNotSupported = 0x9A,
    QosNotSupported = 0x9B,
    UseAnotherServer = 0x9C,
    ServerMoved = 0x9D,
    SharedSubscriptionsNotSupported = 0x9E,
    ConnectionRateExceeded = 0x9F,
    MaximumConnectTime = 0xA0,
    SubscriptionIdentifiersNotSupported = 0xA1,
    WildcardSubscriptionsNotSupported = 0xA2,
}

impl<P> PacketMeta<P> for Disconnect<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0xE0;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        match src.try_get_u8() {
            Ok(reason_code) => {
                let reason_code = reason_code.try_into()?;

                decode_properties!(
                    src,
                    session_expiry_interval: SessionExpiryInterval,
                    reason_string: ReasonString,
                    user_properties: Vec<UserProperty>,
                    server_reference: ServerReference,
                );

                Ok(Disconnect {
                    reason_code,
                    session_expiry_interval,
                    reason_string,
                    user_properties,
                    server_reference,
                })
            }

            Err(DecodeError::IncompletePacket) => Ok(Disconnect {
                reason_code: DisconnectReasonCode::Normal,
                session_expiry_interval: None,
                reason_string: None,
                user_properties: vec![],
                server_reference: None,
            }),

            Err(err) => Err(err),
        }
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let Disconnect {
            reason_code,
            session_expiry_interval,
            reason_string,
            user_properties,
            server_reference,
        } = self;

        let need_variable_header = reason_code != DisconnectReasonCode::Normal
            || session_expiry_interval.is_some()
            || reason_string.is_some()
            || !user_properties.is_empty()
            || server_reference.is_some();
        if need_variable_header {
            dst.try_put_u8(reason_code.into())?;

            encode_properties!(
                dst,
                session_expiry_interval: Option<SessionExpiryInterval>,
                reason_string: Option<ReasonString>,
                user_properties: Vec<UserProperty>,
                server_reference: Option<ServerReference>,
            );
        }

        Ok(())
    }
}
