// Copyright (c) Microsoft. All rights reserved.

use std::cell::UnsafeCell;
use std::convert::TryInto;
use std::mem::size_of;
use std::sync::Arc;

use crate::{DecodeError, PacketIdentifier};

pub trait BufferPool {
    fn put_back(&self, backing: Arc<[u8]>);
}

impl<T> BufferPool for std::rc::Rc<T>
where
    T: BufferPool,
{
    fn put_back(&self, backing: Arc<[u8]>) {
        (&**self).put_back(backing);
    }
}

impl<T> BufferPool for Arc<T>
where
    T: BufferPool,
{
    fn put_back(&self, backing: Arc<[u8]>) {
        (&**self).put_back(backing);
    }
}

/// Owns a particular range of the backing buffer.
///
/// An `Owned` tracks what part of itself has been filled with data.
/// The filled region can be accessed with [`Owned::filled`], and bytes can be removed from the start of this region with [`Owned::drain`].
/// The unfilled region can be accessed with [`Owned::unfilled_mut`], and bytes can be moved from the start of this region
/// into the end of the filled region with [`Owned::fill`].
///
/// An `Owned` can be subdivided into smaller `Owned`s with `split_at` that each own
/// smaller splits of the backing buffer.
///
/// An `Owned` is not `Clone`. It can be converted to a [`Shared`] which is, via [`Owned::freeze`]
pub struct Owned<P>
where
    P: BufferPool,
{
    backing: Backing<P>,
    range: std::ops::Range<usize>,
    filled: usize,
}

#[derive(Clone)]
pub struct Shared<P>
where
    P: BufferPool,
{
    backing: Backing<P>,
    range: std::ops::Range<usize>,
}

#[derive(Clone)]
struct Backing<P>
where
    P: BufferPool,
{
    inner: Option<Arc<UnsafeCell<[u8]>>>,
    pool: P,
}

impl<P> Owned<P>
where
    P: BufferPool,
{
    /// The given `backing` must be the sole owner of its contents,
    /// ie its strong refcount must be 1 and its weak refcount must be 0.
    pub fn new(pool: P, mut backing: Arc<[u8]>) -> Self {
        assert!(Arc::get_mut(&mut backing).is_some());

        let len = backing.len();

        let backing = unsafe {
            // Converting Arc<T> into Arc<UnsafeCell<T>> via into_raw() -> as -> from_raw() is sound,
            // because from_raw() with a different inner type is fine as long as
            // the new type has the same size and alignment as the original type,
            // which is true for UnsafeCell<T> because it's repr(transparent).
            let backing: *const [u8] = Arc::into_raw(backing);
            let backing = backing as *const UnsafeCell<[u8]>;
            let backing = Arc::from_raw(backing);
            Backing {
                inner: Some(backing),
                pool,
            }
        };
        Owned {
            backing,
            range: 0..len,
            filled: 0,
        }
    }

    pub fn filled_len(&self) -> usize {
        self.filled - self.range.start
    }

    pub fn filled_is_empty(&self) -> bool {
        self.filled == self.range.start
    }

    /// Removes the given number of bytes from the start of the filled region.
    pub fn drain(&mut self, n: usize) {
        assert!(self.range.start + n <= self.filled);

        self.range.start += n;
    }

    /// Moves the given number of bytes from the start of the unfilled region to the end of the filled region.
    pub fn fill(&mut self, n: usize) {
        assert!(self.filled + n <= self.range.end);

        self.filled += n;
    }

    /// Retains the range i.. in self, and returns a new Owned for the range 0..i
    pub fn split_to(&mut self, i: usize) -> Owned<P>
    where
        P: Clone,
    {
        assert!(self.range.start + i <= self.range.end);

        let split = Owned {
            backing: self.backing.clone(),
            range: self.range.start..(self.range.start + i),
            filled: std::cmp::min(self.filled, self.range.start + i),
        };

        self.range.start += i;
        self.filled = std::cmp::max(self.filled, self.range.start);

        split
    }

    pub fn freeze(self) -> Shared<P> {
        Shared {
            backing: self.backing,
            range: (self.range.start..self.filled),
        }
    }

    pub fn filled(&self) -> &[u8] {
        let start = unsafe {
            // It would be unsound to convert self.backing.inner to a &[u8] directly and subslice that,
            // because we only own a part of the self.backing.inner buffer and thus the &[u8] could overlap with
            // a &mut [u8] from another Owned with the same self.backing.
            // So we need to calculate the start *mut u8 manually and construct a &[u8] from that.
            let backing: *mut [u8] = self.backing.inner.as_ref().unwrap().get();
            let ptr: *const u8 = backing.cast();
            let ptr = ptr.add(self.range.start);
            ptr
        };

        unsafe { std::slice::from_raw_parts(start, self.filled - self.range.start) }
    }

    pub fn unfilled(&self) -> &[u8] {
        let start = unsafe {
            // See Owned::filled for soundness notes.
            let backing: *mut [u8] = self.backing.inner.as_ref().unwrap().get();
            let ptr: *const u8 = backing.cast();
            let ptr = ptr.add(self.filled);
            ptr
        };

        unsafe { std::slice::from_raw_parts(start, self.range.end - self.filled) }
    }

    pub fn unfilled_mut(&mut self) -> &mut [u8] {
        let start = unsafe {
            // See Owned::filled for soundness notes.
            let backing: *mut [u8] = self.backing.inner.as_mut().unwrap().get();
            let ptr: *mut u8 = backing.cast();
            let ptr = ptr.add(self.filled);
            ptr
        };

        unsafe { std::slice::from_raw_parts_mut(start, self.range.end - self.filled) }
    }
}

// Pretty-prints Owned like bytes::Bytes, ie as a str literal instead of [u8]
impl<P> std::fmt::Debug for Owned<P>
where
    P: BufferPool,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(r#"""#)?;
        for &b in self.filled() {
            for b in std::ascii::escape_default(b) {
                write!(f, "{}", b as char)?;
            }
        }
        f.write_str(r#""+"#)?;
        write!(f, "{}", self.range.end - self.filled)?;
        Ok(())
    }
}

impl<P> Shared<P>
where
    P: BufferPool,
{
    pub fn len(&self) -> usize {
        self.range.end - self.range.start
    }

    pub fn is_empty(&self) -> bool {
        self.range.end == self.range.start
    }

    /// Retains the range i.. in self
    ///
    /// This is the same as [`Shared::split_to`] but does not require creating a new `Shared` for the range 0..i
    pub fn drain(&mut self, i: usize) {
        assert!(self.range.start + i <= self.range.end);

        self.range.start += i;
    }

    /// Retains the range i.. in self, and returns a new Shared for the range 0..i
    pub fn split_to(&mut self, i: usize) -> Shared<P>
    where
        P: Clone,
    {
        assert!(self.range.start + i <= self.range.end);

        let split = Shared {
            backing: self.backing.clone(),
            range: self.range.start..(self.range.start + i),
        };

        self.range.start += i;

        split
    }

    pub(crate) fn try_get_u8(&mut self) -> Result<u8, DecodeError> {
        let b = self
            .as_ref()
            .get(..size_of::<u8>())
            .ok_or(DecodeError::IncompletePacket)?;
        let n = u8::from_be_bytes(b.try_into().unwrap());
        self.drain(size_of::<u8>());
        Ok(n)
    }

    pub(crate) fn try_get_u16_be(&mut self) -> Result<u16, DecodeError> {
        let b = self
            .as_ref()
            .get(..size_of::<u16>())
            .ok_or(DecodeError::IncompletePacket)?;
        let n = u16::from_be_bytes(b.try_into().unwrap());
        self.drain(size_of::<u16>());
        Ok(n)
    }

    pub(crate) fn try_get_u32_be(&mut self) -> Result<u32, DecodeError> {
        let b = self
            .as_ref()
            .get(..size_of::<u32>())
            .ok_or(DecodeError::IncompletePacket)?;
        let n = u32::from_be_bytes(b.try_into().unwrap());
        self.drain(size_of::<u32>());
        Ok(n)
    }

    pub(crate) fn try_get_packet_identifier(&mut self) -> Result<PacketIdentifier, DecodeError> {
        let n = self.try_get_u16_be()?;
        PacketIdentifier::new(n).ok_or(DecodeError::ZeroPacketIdentifier)
    }
}

impl<P> AsRef<[u8]> for Shared<P>
where
    P: BufferPool,
{
    fn as_ref(&self) -> &[u8] {
        let start = unsafe {
            // See Owned::as_ref for soundness notes.
            let backing: *mut [u8] = self.backing.inner.as_ref().unwrap().get();
            let ptr: *mut u8 = backing.cast();
            let ptr = ptr.add(self.range.start);
            ptr
        };

        unsafe { std::slice::from_raw_parts(start, self.range.end - self.range.start) }
    }
}

// Pretty-prints Shared like bytes::Bytes, ie as a str literal instead of [u8]
impl<P> std::fmt::Debug for Shared<P>
where
    P: BufferPool,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(r#"""#)?;
        for &b in &self[..] {
            for b in std::ascii::escape_default(b) {
                write!(f, "{}", b as char)?;
            }
        }
        f.write_str(r#"""#)?;
        Ok(())
    }
}

impl<I, P> std::ops::Index<I> for Shared<P>
where
    [u8]: std::ops::Index<I>,
    P: BufferPool,
{
    type Output = <[u8] as std::ops::Index<I>>::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.as_ref()[index]
    }
}

impl<P> std::cmp::PartialEq for Shared<P>
where
    P: BufferPool,
{
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl<P> std::cmp::PartialEq<[u8]> for Shared<P>
where
    P: BufferPool,
{
    fn eq(&self, other: &[u8]) -> bool {
        self.as_ref() == other
    }
}

impl<P> std::cmp::Eq for Shared<P> where P: BufferPool {}

impl<P> Drop for Backing<P>
where
    P: BufferPool,
{
    fn drop(&mut self) {
        let mut inner = self.inner.take().unwrap();

        if Arc::get_mut(&mut inner).is_some() {
            // Only put_back the buffer into the buffer pool if there are no more references to it,
            // just like when we got it in Owned::new
            //
            // This is the inverse of Owned::new, so the conversion from Arc<UnsafeCell<T>> into Arc<T> is safe for the same reason.
            // The only other possibility of unsoundness would be if self.inner was still shared by other Backings,
            // but we already know that it's not shared.
            let inner = unsafe {
                let inner: *const UnsafeCell<[u8]> = Arc::into_raw(inner);
                let inner = inner as *const [u8];
                let inner = Arc::from_raw(inner);
                inner
            };

            self.pool.put_back(inner);
        }
    }
}
