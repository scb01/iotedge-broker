// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryInto;
use std::mem::size_of;

use crate::{BufferPool, EncodeError, Shared};

/// Strings are prefixed with a two-byte big-endian length and are encoded as utf-8.
///
/// Ref: 1.5.3 UTF-8 encoded strings
#[derive(Clone)]
pub struct ByteStr<P>(Shared<P>)
where
    P: BufferPool;

impl<P> ByteStr<P>
where
    P: BufferPool,
{
    pub const EMPTY: &'static [u8] = b"\x00\x00";

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[size_of::<u16>()..]
    }

    pub fn len(&self) -> usize {
        u16::from_be_bytes(self.0[..size_of::<u16>()].try_into().unwrap()).into()
    }

    pub fn is_empty(&self) -> bool {
        self.0 == b"\x00\x00"[..]
    }

    pub fn into_buffer(self) -> Shared<P> {
        self.0
    }

    pub fn decode(src: &mut Shared<P>) -> Result<Option<ByteStr<P>>, super::DecodeError>
    where
        P: Clone,
    {
        let len: usize = match src.as_ref().get(..size_of::<u16>()) {
            Some(src) => u16::from_be_bytes(src.try_into().unwrap()).into(),
            None => return Ok(None),
        };

        if src.len() < size_of::<u16>() + len {
            return Ok(None);
        }

        let s = src.split_to(size_of::<u16>() + len);
        Ok(Some(ByteStr(s)))
    }

    pub fn encode<B>(self, dst: &mut B) -> Result<(), EncodeError>
    where
        B: super::ByteBuf,
    {
        dst.try_put_bytes(self.0)
    }
}

impl<P> AsRef<str> for ByteStr<P>
where
    P: BufferPool,
{
    fn as_ref(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.as_bytes()) }
    }
}

impl<P> std::fmt::Debug for ByteStr<P>
where
    P: BufferPool,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl<P> std::fmt::Display for ByteStr<P>
where
    P: BufferPool,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl<P> PartialEq for ByteStr<P>
where
    P: BufferPool,
{
    fn eq(&self, other: &Self) -> bool {
        let s: &str = self.as_ref();
        let other: &str = other.as_ref();
        s.eq(other)
    }
}

impl<P> PartialEq<&'_ [u8]> for ByteStr<P>
where
    P: BufferPool,
{
    fn eq(&self, &other: &&[u8]) -> bool {
        self.0.eq(other)
    }
}

impl<P> Eq for ByteStr<P> where P: BufferPool {}

impl<P> PartialOrd for ByteStr<P>
where
    P: BufferPool,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let s: &str = self.as_ref();
        let other: &str = other.as_ref();
        s.partial_cmp(other)
    }
}

impl<P> Ord for ByteStr<P>
where
    P: BufferPool,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let s: &str = self.as_ref();
        let other: &str = other.as_ref();
        s.cmp(other)
    }
}

impl<'a, P> PartialEq<&'a str> for ByteStr<P>
where
    P: BufferPool,
{
    fn eq(&self, other: &&'a str) -> bool {
        self.as_ref().eq(*other)
    }
}

impl<P> std::hash::Hash for ByteStr<P>
where
    P: BufferPool,
{
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.as_ref().hash(state)
    }
}
