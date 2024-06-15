use cxx::memory::UniquePtrTarget;
use std::marker::PhantomData;

#[doc(hidden)]
pub trait FromFFI<T: UniquePtrTarget> {
    fn from_ffi(ptr: cxx::UniquePtr<T>) -> Self;
}

#[doc(hidden)]
pub fn into_optional<T: FromFFI<U>, U: UniquePtrTarget>(raw_ffi: cxx::UniquePtr<U>) -> Option<T> {
    if raw_ffi.is_null() {
        None
    } else {
        Some(T::from_ffi(raw_ffi))
    }
}

pub struct Iterator<'a, Parent: UniquePtrTarget, It: UniquePtrTarget> {
    #[doc(hidden)]
    pub it: cxx::UniquePtr<It>,
    _owner: PhantomData<&'a Parent>,
}

impl<'a, Parent: UniquePtrTarget, It: UniquePtrTarget> Iterator<'a, Parent, It> {
    #[doc(hidden)]
    pub fn new(it: cxx::UniquePtr<It>) -> Self {
        Self {
            it,
            _owner: PhantomData,
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! declare_iterator_conv {
    ($name:ident, $from:ty, $ffi:ty, $parent:ty, $ffi_iterator:ty, $conv: expr) => {
        pub type $name<'a> = $crate::common::Iterator<'a, $parent, $ffi_iterator>;
        impl<'a> Iterator for $name<'a> {
            type Item = $from;
            fn next(&mut self) -> Option<Self::Item> {
                let next = self.it.as_mut().unwrap().next();
                if next.is_null() {
                    None
                } else {
                    Some($conv(next))
                }
            }
        }
        impl<'a> ExactSizeIterator for $name<'a> {
            fn len(&self) -> usize {
                self.it.as_ref().unwrap().size().try_into().unwrap()
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! declare_iterator {
    ($name:ident, $from:ty, $ffi:ty, $parent:ty, $ffi_iterator:ty) => {
        crate::declare_iterator_conv!($name, $from, $ffi, $parent, $ffi_iterator, |n| {
            Self::Item::from_ffi(n)
        });
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! to_slice {
    ($e:expr) => {
        let content_ptr = $e;
        unsafe {
            if content_ptr.size > 0 {
                return std::slice::from_raw_parts_mut(content_ptr.ptr, content_ptr.size as usize);
            }
            return &[];
        }
    };
}


#[doc(hidden)]
#[macro_export]
macro_rules! to_result {
    ($func: expr, $self: expr, $($arg:tt)*) => {
        let mut err: u32 = 0;
        let value = $func(&$self.ptr, $($arg),*, Pin::new(&mut err));
        if err > 0 {
            return Err(crate::Error::from(err));
        }
        return Ok(value);
    };
}
