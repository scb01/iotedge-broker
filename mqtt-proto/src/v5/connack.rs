// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryInto;
use std::time::Duration;

use super::{PacketMeta, Property};
use crate::{BufferPool, ByteBuf, ByteStr, DecodeError, EncodeError, QoS, Shared};

/// Ref: 3.2 CONNACK – Acknowledge connection request
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnAck<P>
where
    P: BufferPool,
{
    pub return_code: ConnectReasonCode,
    pub session_expiry_interval: Option<Duration>,
    pub receive_maximum: usize,
    pub maximum_qos: QoS,
    pub retain_available: bool,
    pub maximum_packet_size: Option<usize>,
    pub assigned_client_id: Option<ByteStr<P>>,
    pub topic_alias_maximum: u16,
    pub reason_string: Option<ByteStr<P>>,
    pub user_properties: Vec<(ByteStr<P>, ByteStr<P>)>,
    pub wildcard_subscription_available: bool,
    pub shared_subscription_available: bool,
    pub subscription_identifier_available: bool,
    pub server_keep_alive: Option<Duration>,
    pub response_information: Option<ByteStr<P>>,
    pub server_reference: Option<ByteStr<P>>,
    pub authentication_method: Option<ByteStr<P>>,
    pub authentication_data: Option<Shared<P>>,
}

/// Ref: 3.2.2.2 Connect Reason Code
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectReasonCode {
    Success { session_present: bool },
    Refused(ConnectionRefusedReason),
}

define_u8_code! {
    /// Ref: 3.2.2.2 Connect Reason Code
    ConnectionRefusedReason,
    UnrecognizedConnectReasonCode,
    UnspecifiedError = 0x80,
    MalformedPacket = 0x81,
    ProtocolError = 0x82,
    ImplementationSpecificError = 0x83,
    UnsupportedProtocolVersion = 0x84,
    ClientIdentifierNotValid = 0x85,
    BadUserNameOrPassword = 0x86,
    NotAuthorized = 0x87,
    ServerUnavailable = 0x88,
    ServerBusy = 0x89,
    Banned = 0x8A,
    BadAuthenticationMethod = 0x8C,
    TopicNameInvalid = 0x90,
    PacketTooLarge = 0x95,
    QuotaExceeded = 0x97,
    PayloadFormatInvalid = 0x99,
    RetainNotSupported = 0x9A,
    QoSNotSupported = 0x9B,
    UseAnotherServer = 0x9C,
    ServerMoved = 0x9D,
    ConnectionRateExceeded = 0x9F,
}

impl<P> PacketMeta<P> for ConnAck<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0x20;

    fn decode(_flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let connack_flags = src.try_get_u8()?;
        let session_present = match connack_flags {
            0x00 => false,
            0x01 => true,
            connack_flags => {
                return Err(DecodeError::UnrecognizedConnAckFlags(connack_flags));
            }
        };

        let return_code = ConnectReasonCode::from(src.try_get_u8()?, session_present)?;

        decode_properties!(
            src,
            session_expiry_interval: SessionExpiryInterval,
            receive_maximum: ReceiveMaximum,
            maximum_qos: MaximumQoS,
            retain_available: RetainAvailable,
            maximum_packet_size: MaximumPacketSize,
            assigned_client_id: AssignedClientIdentifier,
            topic_alias_maximum: TopicAliasMaximum,
            reason_string: ReasonString,
            user_properties: Vec<UserProperty>,
            wildcard_subscription_available: WildcardSubscriptionAvailable,
            shared_subscription_available: SharedSubscriptionAvailable,
            subscription_identifier_available: SubscriptionIdentifierAvailable,
            server_keep_alive: ServerKeepAlive,
            response_information: ResponseInformation,
            server_reference: ServerReference,
            authentication_method: AuthenticationMethod,
            authentication_data: AuthenticationData,
        );

        Ok(ConnAck {
            return_code,
            session_expiry_interval,
            receive_maximum: receive_maximum.unwrap_or_else(|| usize::from(u16::max_value())),
            maximum_qos: maximum_qos.unwrap_or(QoS::ExactlyOnce),
            retain_available: retain_available.unwrap_or(true),
            maximum_packet_size,
            assigned_client_id,
            topic_alias_maximum: topic_alias_maximum.unwrap_or(0),
            reason_string,
            user_properties,
            wildcard_subscription_available: wildcard_subscription_available.unwrap_or(true),
            shared_subscription_available: shared_subscription_available.unwrap_or(true),
            subscription_identifier_available: subscription_identifier_available.unwrap_or(true),
            server_keep_alive,
            response_information,
            server_reference,
            authentication_method,
            authentication_data,
        })
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let ConnAck {
            return_code,
            session_expiry_interval,
            receive_maximum,
            maximum_qos,
            retain_available,
            maximum_packet_size,
            assigned_client_id,
            topic_alias_maximum,
            reason_string,
            user_properties,
            wildcard_subscription_available,
            shared_subscription_available,
            subscription_identifier_available,
            server_keep_alive,
            response_information,
            server_reference,
            authentication_method,
            authentication_data,
        } = self;

        let session_present = if let ConnectReasonCode::Success { session_present } = return_code {
            session_present
        } else {
            false
        };
        if session_present {
            dst.try_put_u8(0x01)?;
        } else {
            dst.try_put_u8(0x00)?;
        }

        dst.try_put_u8(return_code.into())?;

        encode_properties!(
            dst,
            session_expiry_interval: Option<SessionExpiryInterval>,
            receive_maximum: ReceiveMaximum,
            maximum_qos: MaximumQoS,
            retain_available: RetainAvailable,
            maximum_packet_size: Option<MaximumPacketSize>,
            assigned_client_id: Option<AssignedClientIdentifier>,
            topic_alias_maximum: TopicAliasMaximum,
            reason_string: Option<ReasonString>,
            user_properties: Vec<UserProperty>,
            wildcard_subscription_available: WildcardSubscriptionAvailable,
            shared_subscription_available: SharedSubscriptionAvailable,
            subscription_identifier_available: SubscriptionIdentifierAvailable,
            server_keep_alive: Option<ServerKeepAlive>,
            response_information: Option<ResponseInformation>,
            server_reference: Option<ServerReference>,
            authentication_method: Option<AuthenticationMethod>,
            authentication_data: Option<AuthenticationData>,
        );

        Ok(())
    }
}

impl ConnectReasonCode {
    fn from(code: u8, session_present: bool) -> Result<Self, DecodeError> {
        Ok(match code {
            0x00 => ConnectReasonCode::Success { session_present },
            code => ConnectReasonCode::Refused(code.try_into()?),
        })
    }
}

impl From<ConnectReasonCode> for u8 {
    fn from(code: ConnectReasonCode) -> Self {
        match code {
            ConnectReasonCode::Success { .. } => 0x00,
            ConnectReasonCode::Refused(reason) => reason.into(),
        }
    }
}
