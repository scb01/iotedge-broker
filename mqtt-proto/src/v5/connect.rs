// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryInto;
use std::time::Duration;

use super::{decode_connect_start, PacketMeta, Property, PROTOCOL_VERSION};
use crate::v5::Publication;
use crate::{BufferPool, ByteBuf, ByteStr, ClientId, DecodeError, EncodeError, QoS, Shared};

/// Ref: 3.1 CONNECT – Client requests a connection to a Server
#[derive(Clone, Eq, PartialEq)]
pub struct Connect<P>
where
    P: BufferPool,
{
    pub username: Option<ByteStr<P>>,
    pub password: Option<ByteStr<P>>,
    pub will: Option<(Publication<P>, Duration)>,
    pub client_id: ClientId<P>,
    pub keep_alive: Duration,
    pub session_expiry_interval: Option<Duration>,
    pub receive_maximum: usize,
    pub maximum_packet_size: Option<usize>,
    pub topic_alias_maximum: u16,
    pub request_response_information: bool,
    pub request_problem_information: bool,
    pub user_properties: Vec<(ByteStr<P>, ByteStr<P>)>,
    pub authentication_method: Option<ByteStr<P>>,
    pub authentication_data: Option<Shared<P>>,
}

impl<P> Connect<P>
where
    P: Clone + BufferPool,
{
    pub(crate) fn decode_rest(src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let protocol_name = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
        if protocol_name != crate::PROTOCOL_NAME {
            return Err(DecodeError::UnrecognizedProtocolName(
                protocol_name.as_ref().to_owned(),
            ));
        }

        let protocol_version = src.try_get_u8()?;
        if protocol_version != PROTOCOL_VERSION {
            return Err(DecodeError::UnrecognizedProtocolVersion(protocol_version));
        }

        let connect_flags = src.try_get_u8()?;
        if connect_flags & 0b0000_0001 != 0 {
            return Err(DecodeError::ConnectReservedSet);
        }

        let keep_alive = Duration::from_secs(u64::from(src.try_get_u16_be()?));

        decode_properties!(
            src,
            session_expiry_interval: SessionExpiryInterval,
            receive_maximum: ReceiveMaximum,
            maximum_packet_size: MaximumPacketSize,
            topic_alias_maximum: TopicAliasMaximum,
            request_response_information: RequestResponseInformation,
            request_problem_information: RequestProblemInformation,
            user_properties: Vec<UserProperty>,
            authentication_method: AuthenticationMethod,
            authentication_data: AuthenticationData,
        );

        let client_id = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
        let client_id = if client_id.is_empty() {
            ClientId::ServerGenerated
        } else if connect_flags & 0b0000_0010 == 0 {
            ClientId::IdWithExistingSession(client_id)
        } else {
            ClientId::IdWithCleanSession(client_id)
        };

        let will = if connect_flags & 0b0000_0100 == 0 {
            None
        } else {
            decode_properties!(
                src,
                will_delay_interval: WillDelayInterval,
                will_payload_is_utf8: PayloadIsUtf8,
                will_message_expiry_interval: MessageExpiryInterval,
                will_content_type: ContentType,
                will_response_topic: ResponseTopic,
                will_correlation_data: CorrelationData,
                will_user_properties: Vec<UserProperty>,
            );

            let topic_name = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;

            let qos = match connect_flags & 0b0001_1000 {
                0x00 => QoS::AtMostOnce,
                0x08 => QoS::AtLeastOnce,
                0x10 => QoS::ExactlyOnce,
                qos => return Err(DecodeError::UnrecognizedQoS(qos >> 3)),
            };

            let retain = connect_flags & 0b0010_0000 != 0;

            let payload_len = usize::from(src.try_get_u16_be()?);
            if src.len() < payload_len {
                return Err(DecodeError::IncompletePacket);
            }
            let payload = src.split_to(payload_len);

            Some((
                Publication {
                    topic_name,
                    qos,
                    retain,
                    payload_is_utf8: will_payload_is_utf8.unwrap_or(false),
                    message_expiry_interval: will_message_expiry_interval,
                    topic_alias: None,
                    response_topic: will_response_topic,
                    correlation_data: will_correlation_data,
                    user_properties: will_user_properties,
                    content_type: will_content_type,
                    payload,
                },
                will_delay_interval.unwrap_or(Duration::ZERO),
            ))
        };

        let username = if connect_flags & 0b1000_0000 == 0 {
            None
        } else {
            Some(ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?)
        };

        let password = if connect_flags & 0b0100_0000 == 0 {
            None
        } else {
            Some(ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?)
        };

        Ok(Connect {
            username,
            password,
            will,
            client_id,
            keep_alive,
            session_expiry_interval,
            receive_maximum: receive_maximum.unwrap_or_else(|| usize::from(u16::max_value())),
            maximum_packet_size,
            topic_alias_maximum: topic_alias_maximum.unwrap_or(0),
            request_response_information: request_response_information.unwrap_or(false),
            request_problem_information: request_problem_information.unwrap_or(true),
            user_properties,
            authentication_method,
            authentication_data,
        })
    }
}

impl<P> std::fmt::Debug for Connect<P>
where
    P: BufferPool,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connect")
            .field("username", &self.username)
            .field("will", &self.will)
            .field("client_id", &self.client_id)
            .field("keep_alive", &self.keep_alive)
            .finish()
    }
}

impl<P> PacketMeta<P> for Connect<P>
where
    P: Clone + BufferPool,
{
    const PACKET_TYPE: u8 = 0x10;

    fn decode(flags: u8, src: &mut Shared<P>) -> Result<Self, DecodeError> {
        let protocol_version = decode_connect_start(flags, src)?;
        if protocol_version != PROTOCOL_VERSION {
            return Err(DecodeError::UnrecognizedProtocolVersion(protocol_version));
        }

        Self::decode_rest(src)
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        let Connect {
            username,
            password,
            will,
            client_id,
            keep_alive,
            session_expiry_interval,
            receive_maximum,
            maximum_packet_size,
            topic_alias_maximum,
            request_response_information,
            request_problem_information,
            user_properties,
            authentication_method,
            authentication_data,
        } = self;

        dst.try_put_slice(crate::PROTOCOL_NAME)?;

        dst.try_put_u8(PROTOCOL_VERSION)?;

        {
            let mut connect_flags = 0b0000_0000_u8;
            if username.is_some() {
                connect_flags |= 0b1000_0000;
            }
            if password.is_some() {
                connect_flags |= 0b0100_0000;
            }
            if let Some((will, _)) = &will {
                connect_flags |= 0b0000_0100;
                if will.retain {
                    connect_flags |= 0b0010_0000;
                }
                connect_flags |= u8::from(will.qos) << 3;
            }
            match client_id {
                ClientId::ServerGenerated | ClientId::IdWithCleanSession(_) => {
                    connect_flags |= 0b0000_0010;
                }
                ClientId::IdWithExistingSession(_) => (),
            }
            dst.try_put_u8(connect_flags)?;
        }

        dst.try_put_u16_be(
            keep_alive
                .as_secs()
                .try_into()
                .map_err(|_| EncodeError::KeepAliveTooHigh(keep_alive))?,
        )?;

        encode_properties! {
            dst,
            session_expiry_interval: Option<SessionExpiryInterval>,
            receive_maximum: ReceiveMaximum,
            maximum_packet_size: Option<MaximumPacketSize>,
            topic_alias_maximum: TopicAliasMaximum,
            request_response_information: RequestResponseInformation,
            request_problem_information: RequestProblemInformation,
            user_properties: Vec<UserProperty>,
            authentication_method: Option<AuthenticationMethod>,
            authentication_data: Option<AuthenticationData>,
        }

        match client_id {
            ClientId::ServerGenerated => dst.try_put_slice(ByteStr::<P>::EMPTY)?,
            ClientId::IdWithCleanSession(id) | ClientId::IdWithExistingSession(id) => {
                id.encode(dst)?
            }
        }

        if let Some((will, will_delay_interval)) = will {
            let Publication {
                topic_name,
                qos: _,    // Encoded in connect_flags above
                retain: _, // Encoded in connect_flags above
                payload_is_utf8,
                message_expiry_interval,
                topic_alias,
                response_topic,
                correlation_data,
                user_properties,
                content_type,
                payload,
            } = will;

            encode_properties!(
                dst,
                will_delay_interval: WillDelayInterval,
                payload_is_utf8: PayloadIsUtf8,
                message_expiry_interval: Option<MessageExpiryInterval>,
                topic_alias: Option<TopicAlias>,
                content_type: Option<ContentType>,
                response_topic: Option<ResponseTopic>,
                correlation_data: Option<CorrelationData>,
                user_properties: Vec<UserProperty>,
            );

            topic_name.encode(dst)?;

            let will_len = payload.len();
            dst.try_put_u16_be(
                will_len
                    .try_into()
                    .map_err(|_| EncodeError::WillTooLarge(will_len))?,
            )?;

            dst.try_put_bytes(payload)?;
        }

        if let Some(username) = username {
            username.encode(dst)?;
        }

        if let Some(password) = password {
            password.encode(dst)?;
        }

        Ok(())
    }
}
