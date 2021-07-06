// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryInto;
use std::mem::size_of;
use std::time::Duration;

use super::{decode_remaining_length, encode_remaining_length};
use crate::{BufferPool, ByteBuf, ByteCounter, ByteStr, DecodeError, EncodeError, QoS, Shared};

/// Ref: 2.2.2.2 Property
#[allow(clippy::enum_variant_names)] // clippy wants `UserProperty` to not end with `Property`
#[derive(Clone)]
pub(super) enum Property<P>
where
    P: BufferPool,
{
    /// Ref: 3.2.2.3.7 Assigned Client Identifier
    AssignedClientIdentifier(ByteStr<P>),

    /// Note: Value includes the two-byte length prefix.
    ///
    /// Ref: 3.1.2.11.10 Authentication Data
    AuthenticationData(Shared<P>),

    /// Ref: 3.1.2.11.9 Authentication Method
    AuthenticationMethod(ByteStr<P>),

    /// Ref: 3.1.3.2.5 Content Type
    ContentType(ByteStr<P>),

    /// Note: Value includes the two-byte length prefix.
    ///
    /// Ref: 3.1.3.2.7 Correlation Data
    CorrelationData(Shared<P>),

    /// Ref: 3.1.2.11.4 Maximum Packet Size
    MaximumPacketSize(usize),

    /// Ref: 3.2.2.3.4 Maximum QoS
    MaximumQoS(QoS),

    /// Ref: 3.1.3.2.4 Message Expiry Interval
    MessageExpiryInterval(Duration),

    /// Ref: 3.1.3.2.3 Payload Format Indicator
    PayloadIsUtf8(bool),

    /// Ref: 3.2.2.3.9 Reason String
    ReasonString(ByteStr<P>),

    /// Ref: 3.1.2.11.3 Receive Maximum
    ReceiveMaximum(usize),

    /// Ref: 3.1.2.11.7 Request Problem Information
    RequestProblemInformation(bool),

    /// Ref: 3.1.2.11.6 Request Response Information
    RequestResponseInformation(bool),

    /// Ref: 3.2.2.3.15 Response Information
    ResponseInformation(ByteStr<P>),

    /// Ref: 3.1.3.2.6 Response Topic
    ResponseTopic(ByteStr<P>),

    /// Ref: 3.2.2.3.5 Retain Available
    RetainAvailable(bool),

    /// Ref: 3.2.2.3.14 Server Keep Alive
    ServerKeepAlive(Duration),

    /// Ref: 3.2.2.3.16 Server Reference
    ServerReference(ByteStr<P>),

    /// Ref: 3.1.2.11.2 Session Expiry Interval
    SessionExpiryInterval(Duration),

    /// Ref: 3.2.2.3.13 Shared Subscription Available
    SharedSubscriptionAvailable(bool),

    /// Ref: 3.8.2.1.2 Subscription Identifier
    SubscriptionIdentifier(usize),

    /// Ref: 3.2.2.3.12 Subscription Identifiers Available
    SubscriptionIdentifierAvailable(bool),

    /// Ref: 3.3.2.3.4 Topic Alias
    TopicAlias(u16),

    /// Ref: 3.1.2.11.5 Topic Alias Maximum
    TopicAliasMaximum(u16),

    /// Ref: 3.1.2.11.8 User Property
    UserProperty(ByteStr<P>, ByteStr<P>),

    /// Ref: 3.2.2.3.11 Wildcard Subscription Available
    WildcardSubscriptionAvailable(bool),

    /// Ref: 3.1.3.2.2 Will Delay Interval
    WillDelayInterval(Duration),
}

impl<P> Property<P>
where
    P: BufferPool,
{
    pub(super) fn decode_all(
        src: &mut Shared<P>,
    ) -> Result<impl Iterator<Item = Result<Self, DecodeError>>, DecodeError>
    where
        P: Clone,
    {
        struct PropertyDecodeIter<P>
        where
            P: BufferPool,
        {
            src: Shared<P>,
        }

        impl<P> Iterator for PropertyDecodeIter<P>
        where
            P: BufferPool + Clone,
        {
            type Item = Result<Property<P>, DecodeError>;

            fn next(&mut self) -> Option<Self::Item> {
                if self.src.is_empty() {
                    return None;
                }

                Some(Property::decode(&mut self.src))
            }
        }

        let (remaining_length, remaining_length_len) = {
            let mut src = &src[..];
            let original_src_len = src.len();
            let remaining_length =
                decode_remaining_length(&mut src)?.ok_or(DecodeError::IncompletePacket)?;
            let new_src_len = src.len();
            (remaining_length, original_src_len - new_src_len)
        };
        src.drain(remaining_length_len);

        if src.len() < remaining_length {
            return Err(DecodeError::IncompletePacket);
        }
        let src = src.split_to(remaining_length);

        Ok(PropertyDecodeIter { src })
    }

    fn decode(src: &mut Shared<P>) -> Result<Self, DecodeError>
    where
        P: Clone,
    {
        // Note: The spec says property identifiers are technically variable-length integers,
        // but also that all the current defined identifiers are one-byte long,
        // so for now we take the easy route and just parse a byte.
        let identifier = src.try_get_u8()?;

        Ok(match identifier {
            0x01 => {
                let is_utf8 = match src.try_get_u8()? {
                    0x00 => false,
                    0x01 => true,
                    value => return Err(DecodeError::UnrecognizedPayloadFormatIndicator(value)),
                };
                Property::PayloadIsUtf8(is_utf8)
            }

            0x02 => {
                let interval = Duration::from_secs(u64::from(src.try_get_u32_be()?));
                Property::MessageExpiryInterval(interval)
            }

            0x03 => {
                let content_type = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
                Property::ContentType(content_type)
            }

            0x08 => {
                let response_topic = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
                Property::ResponseTopic(response_topic)
            }

            0x09 => {
                let len: usize = match src.as_ref().get(..size_of::<u16>()) {
                    Some(src) => u16::from_be_bytes(src.try_into().unwrap()).into(),
                    None => return Err(DecodeError::IncompletePacket),
                };

                if src.len() < size_of::<u16>() + len {
                    return Err(DecodeError::IncompletePacket);
                }

                let correlation_data = src.split_to(size_of::<u16>() + len);
                Property::CorrelationData(correlation_data)
            }

            0x0B => {
                let (remaining_length, remaining_length_len) = {
                    let mut src = &src[..];
                    let original_src_len = src.len();
                    let remaining_length =
                        decode_remaining_length(&mut src)?.ok_or(DecodeError::IncompletePacket)?;
                    let new_src_len = src.len();
                    (remaining_length, original_src_len - new_src_len)
                };
                src.drain(remaining_length_len);
                Property::SubscriptionIdentifier(remaining_length)
            }

            0x11 => {
                let interval = Duration::from_secs(u64::from(src.try_get_u32_be()?));
                Property::SessionExpiryInterval(interval)
            }

            0x12 => {
                let client_id = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
                Property::AssignedClientIdentifier(client_id)
            }

            0x13 => {
                let keep_alive = Duration::from_secs(u64::from(src.try_get_u16_be()?));
                Property::ServerKeepAlive(keep_alive)
            }

            0x15 => {
                let method = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
                Property::AuthenticationMethod(method)
            }

            0x16 => {
                let len: usize = match src.as_ref().get(..size_of::<u16>()) {
                    Some(src) => u16::from_be_bytes(src.try_into().unwrap()).into(),
                    None => return Err(DecodeError::IncompletePacket),
                };

                if src.len() < size_of::<u16>() + len {
                    return Err(DecodeError::IncompletePacket);
                }

                let authentication_data = src.split_to(size_of::<u16>() + len);
                Property::AuthenticationData(authentication_data)
            }

            0x17 => {
                let requested = match src.try_get_u8()? {
                    0x00 => false,
                    0x01 => true,
                    value => return Err(DecodeError::UnrecognizedRequestProblemInformation(value)),
                };
                Property::RequestProblemInformation(requested)
            }

            0x18 => {
                let interval = Duration::from_secs(u64::from(src.try_get_u32_be()?));
                Property::WillDelayInterval(interval)
            }

            0x19 => {
                let requested = match src.try_get_u8()? {
                    0x00 => false,
                    0x01 => true,
                    value => {
                        return Err(DecodeError::UnrecognizedRequestResponseInformation(value))
                    }
                };
                Property::RequestResponseInformation(requested)
            }

            0x1A => {
                let response_information =
                    ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
                Property::ResponseInformation(response_information)
            }

            0x1C => {
                let server_reference =
                    ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
                Property::ServerReference(server_reference)
            }

            0x1F => {
                let reason_string = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
                Property::ReasonString(reason_string)
            }

            0x21 => {
                let value = src.try_get_u16_be()?;
                Property::ReceiveMaximum(usize::from(value))
            }

            0x22 => {
                let value = src.try_get_u16_be()?;
                Property::TopicAliasMaximum(value)
            }

            0x23 => {
                let value = src.try_get_u16_be()?;
                Property::TopicAlias(value)
            }

            0x24 => {
                let qos = match src.try_get_u8()? {
                    0x00 => QoS::AtMostOnce,
                    0x01 => QoS::AtLeastOnce,
                    value => return Err(DecodeError::UnrecognizedMaximumQoS(value)),
                };
                Property::MaximumQoS(qos)
            }

            0x25 => {
                let available = match src.try_get_u8()? {
                    0x00 => false,
                    0x01 => true,
                    value => return Err(DecodeError::UnrecognizedRetainAvailable(value)),
                };
                Property::RetainAvailable(available)
            }

            0x26 => {
                let name = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
                let value = ByteStr::decode(src)?.ok_or(DecodeError::IncompletePacket)?;
                Property::UserProperty(name, value)
            }

            0x27 => {
                let value = src.try_get_u32_be()?;
                if value == 0 {
                    return Err(DecodeError::InvalidMaximumPacketSize(value));
                }
                let value: usize = value
                    .try_into()
                    .map_err(|_| DecodeError::InvalidMaximumPacketSize(value))?;
                Property::MaximumPacketSize(value)
            }

            0x28 => {
                let available = match src.try_get_u8()? {
                    0x00 => false,
                    0x01 => true,
                    value => {
                        return Err(DecodeError::UnrecognizedWildcardSubscriptionAvailable(
                            value,
                        ))
                    }
                };
                Property::WildcardSubscriptionAvailable(available)
            }

            0x29 => {
                let available = match src.try_get_u8()? {
                    0x00 => false,
                    0x01 => true,
                    value => {
                        return Err(DecodeError::UnrecognizedSubscriptionIdentifierAvailable(
                            value,
                        ))
                    }
                };
                Property::SubscriptionIdentifierAvailable(available)
            }

            0x2A => {
                let available = match src.try_get_u8()? {
                    0x00 => false,
                    0x01 => true,
                    value => {
                        return Err(DecodeError::UnrecognizedSharedSubscriptionAvailable(value))
                    }
                };
                Property::SharedSubscriptionAvailable(available)
            }

            identifier => return Err(DecodeError::UnrecognizedPropertyIdentifier(identifier)),
        })
    }

    pub(super) fn encode_all<B, I>(properties: I, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
        P: Clone,
        I: Iterator<Item = Self> + Clone,
    {
        fn encode_all_inner<B, P, I>(properties: I, dst: &mut B) -> Result<(), EncodeError>
        where
            B: ByteBuf,
            P: Clone + BufferPool,
            I: Iterator<Item = Property<P>> + Clone,
        {
            for property in properties {
                property.encode(dst)?;
            }
            Ok(())
        }

        let properties_length = {
            let mut counter: ByteCounter = Default::default();
            encode_all_inner(properties.clone(), &mut counter)?;
            counter.0
        };

        encode_remaining_length(properties_length, dst)?;
        encode_all_inner(properties, dst)?;

        Ok(())
    }

    fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: ByteBuf,
    {
        match self {
            Property::AssignedClientIdentifier(client_id) => {
                dst.try_put_u8(0x12)?;
                client_id.encode(dst)?;
            }

            Property::AuthenticationData(authentication_data) => {
                dst.try_put_u8(0x16)?;
                dst.try_put_bytes(authentication_data)?;
            }

            Property::AuthenticationMethod(method) => {
                dst.try_put_u8(0x15)?;
                method.encode(dst)?;
            }

            Property::ContentType(content_type) => {
                dst.try_put_u8(0x03)?;
                content_type.encode(dst)?;
            }

            Property::CorrelationData(correlation_data) => {
                dst.try_put_u8(0x09)?;
                dst.try_put_bytes(correlation_data)?;
            }

            Property::MaximumPacketSize(value) => {
                if value == 0 {
                    return Err(EncodeError::InvalidMaximumPacketSize(value));
                }
                let value: u32 = value
                    .try_into()
                    .map_err(|_| EncodeError::InvalidMaximumPacketSize(value))?;
                dst.try_put_u8(0x21)?;
                dst.try_put_u32_be(value)?;
            }

            Property::MaximumQoS(qos) => {
                if let QoS::AtMostOnce | QoS::AtLeastOnce = qos {
                    dst.try_put_u8(0x24)?;
                    dst.try_put_u8(qos.into())?;
                }
            }

            Property::MessageExpiryInterval(interval) => {
                let interval: u32 = interval
                    .as_secs()
                    .try_into()
                    .map_err(|_| EncodeError::InvalidMessageExpiryInterval(interval))?;
                dst.try_put_u8(0x02)?;
                dst.try_put_u32_be(interval)?;
            }

            Property::PayloadIsUtf8(is_utf8) => {
                if is_utf8 {
                    dst.try_put_u8(0x01)?;
                    dst.try_put_u8(0x01)?;
                }
            }

            Property::ReasonString(reason_string) => {
                dst.try_put_u8(0x1F)?;
                reason_string.encode(dst)?;
            }

            Property::ReceiveMaximum(value) => {
                if value == 0 {
                    return Err(EncodeError::InvalidReceiveMaximum(value));
                }
                let value: u16 = value
                    .try_into()
                    .map_err(|_| EncodeError::InvalidReceiveMaximum(value))?;
                if value < u16::max_value() {
                    dst.try_put_u8(0x21)?;
                    dst.try_put_u16_be(value)?;
                }
            }

            Property::RequestProblemInformation(requested) => {
                if !requested {
                    dst.try_put_u8(0x17)?;
                    dst.try_put_u8(0x00)?;
                }
            }

            Property::RequestResponseInformation(requested) => {
                if requested {
                    dst.try_put_u8(0x19)?;
                    dst.try_put_u8(0x01)?;
                }
            }

            Property::ResponseInformation(response_information) => {
                dst.try_put_u8(0x1A)?;
                response_information.encode(dst)?;
            }

            Property::ResponseTopic(response_topic) => {
                dst.try_put_u8(0x08)?;
                response_topic.encode(dst)?;
            }

            Property::RetainAvailable(available) => {
                if !available {
                    dst.try_put_u8(0x25)?;
                    dst.try_put_u8(0x00)?;
                }
            }

            Property::ServerKeepAlive(keep_alive) => {
                let keep_alive: u16 = keep_alive
                    .as_secs()
                    .try_into()
                    .map_err(|_| EncodeError::InvalidServerKeepAlive(keep_alive))?;
                dst.try_put_u8(0x13)?;
                dst.try_put_u16_be(keep_alive)?;
            }

            Property::ServerReference(server_reference) => {
                dst.try_put_u8(0x1C)?;
                server_reference.encode(dst)?;
            }

            Property::SessionExpiryInterval(interval) => {
                let interval: u32 = interval
                    .as_secs()
                    .try_into()
                    .map_err(|_| EncodeError::InvalidSessionExpiryInterval(interval))?;
                if interval > 0 {
                    dst.try_put_u8(0x11)?;
                    dst.try_put_u32_be(interval)?;
                }
            }

            Property::SharedSubscriptionAvailable(available) => {
                if !available {
                    dst.try_put_u8(0x2A)?;
                    dst.try_put_u8(0x00)?;
                }
            }

            Property::SubscriptionIdentifier(remaining_length) => {
                dst.try_put_u8(0x0B)?;
                encode_remaining_length(remaining_length, dst)?;
            }

            Property::SubscriptionIdentifierAvailable(available) => {
                if !available {
                    dst.try_put_u8(0x29)?;
                    dst.try_put_u8(0x00)?;
                }
            }

            Property::TopicAlias(value) => {
                if value == 0 {
                    return Err(EncodeError::InvalidTopicAlias(value));
                }
                dst.try_put_u8(0x23)?;
                dst.try_put_u16_be(value)?;
            }

            Property::TopicAliasMaximum(value) => {
                if value > 0 {
                    dst.try_put_u8(0x22)?;
                    dst.try_put_u16_be(value)?;
                }
            }

            Property::UserProperty(name, value) => {
                dst.try_put_u8(0x26)?;
                name.encode(dst)?;
                value.encode(dst)?;
            }

            Property::WildcardSubscriptionAvailable(available) => {
                if !available {
                    dst.try_put_u8(0x28)?;
                    dst.try_put_u8(0x00)?;
                }
            }

            Property::WillDelayInterval(interval) => {
                let interval: u32 = interval
                    .as_secs()
                    .try_into()
                    .map_err(|_| EncodeError::InvalidWillDelayInterval(interval))?;
                if interval > 0 {
                    dst.try_put_u8(0x18)?;
                    dst.try_put_u32_be(interval)?;
                }
            }
        }

        Ok(())
    }
}

macro_rules! decode_properties {
    (
        @inner
        { $($bindings_decl:tt)* }
        { $($match_body:tt)* }
        { $src:ident }
        { }
    ) => {
        $($bindings_decl)*
        for property in Property::decode_all($src)? {
            match property? {
                $($match_body)*
                // TODO: Include at least the variant name of the unexpected property in the error
                _property => return Err(DecodeError::UnexpectedProperty),
            }
        }
    };

    (
        @inner
        { $($bindings_decl:tt)* }
        { $($match_body:tt)* }
        { $src:ident }
        { $binding:ident : Vec<SubscriptionIdentifier> , $($bindings:tt)* }
    ) => {
        decode_properties! {
            @inner
            {
                $($bindings_decl)*
                let mut $binding = vec![];
            }
            {
                $($match_body)*
                Property::SubscriptionIdentifier(value) => {
                    $binding.push(value);
                },
            }
            { $src }
            { $($bindings)* }
        }
    };

    (
        @inner
        { $($bindings_decl:tt)* }
        { $($match_body:tt)* }
        { $src:ident }
        { $binding:ident : Vec<UserProperty> , $($bindings:tt)* }
    ) => {
        decode_properties! {
            @inner
            {
                $($bindings_decl)*
                let mut $binding = vec![];
            }
            {
                $($match_body)*
                Property::UserProperty(name, value) => {
                    $binding.push((name, value));
                },
            }
            { $src }
            { $($bindings)* }
        }
    };

    (
        @inner
        { $($bindings_decl:tt)* }
        { $($match_body:tt)* }
        { $src:ident }
        { $binding:ident : $variant:ident , $($bindings:tt)* }
    ) => {
        decode_properties! {
            @inner
            {
                $($bindings_decl)*
                let mut $binding = None;
            }
            {
                $($match_body)*
                Property::$variant(value) => {
                    if $binding.replace(value).is_some() {
                        return Err(DecodeError::DuplicateProperty(stringify!($variant)));
                    }
                },
            }
            { $src }
            { $($bindings)* }
        }
    };

    (
        $src:ident,
        $($bindings:tt)*
    ) => {
        decode_properties! {
            @inner
            { }
            { }
            { $src }
            { $($bindings)* }
        }
    };
}

macro_rules! encode_properties {
    (
        @inner
        { $($result:tt)* }
        { $dst:ident }
        { }
    ) => {
        let properties = $($result)*;
        Property::encode_all(properties, $dst)?;
    };

    (
        @inner
        { $($result:tt)* }
        { $dst:ident }
        { $binding:ident : Vec<SubscriptionIdentifier> , $($bindings:tt)* }
    ) => {
        encode_properties! {
            @inner
            {
                $($result)*
                .chain(
                    $binding.into_iter()
                    .map(Property::SubscriptionIdentifier)
                )
            }
            { $dst }
            { $($bindings)* }
        }
    };

    (
        @inner
        { $($result:tt)* }
        { $dst:ident }
        { $binding:ident : Vec<UserProperty> , $($bindings:tt)* }
    ) => {
        encode_properties! {
            @inner
            {
                $($result)*
                .chain(
                    $binding.into_iter()
                    .map(|(name, value)| Property::UserProperty(name, value))
                )
            }
            { $dst }
            { $($bindings)* }
        }
    };

    (
        @inner
        { $($result:tt)* }
        { $dst:ident }
        { $binding:ident : Option<$variant:ident> , $($bindings:tt)* }
    ) => {
        encode_properties! {
            @inner
            {
                $($result)*
                .chain($binding.map(Property::$variant))
            }
            { $dst }
            { $($bindings)* }
        }
    };

    (
        @inner
        { $($result:tt)* }
        { $dst:ident }
        { $binding:ident : $variant:ident , $($bindings:tt)* }
    ) => {
        encode_properties! {
            @inner
            {
                $($result)*
                .chain(std::iter::once(Property::$variant($binding)))
            }
            { $dst }
            { $($bindings)* }
        }
    };

    (
        $dst:ident,
        $($bindings:tt)*
    ) => {
        encode_properties! {
            @inner
            { std::iter::empty() }
            { $dst }
            { $($bindings)* }
        }
    };
}
