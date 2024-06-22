//! This module contains the different structures involved in the PE's resource tree

use lief_ffi as ffi;

use std::{fmt, marker::PhantomData};

use crate::to_slice;
use crate::{common::FromFFI, declare_iterator};

#[derive(Debug)]
pub enum Node<'a> {
    /// A *data* node (i.e. a leaf)
    Data(Data<'a>),
    /// A directory node
    Directory(Directory<'a>),
}

/// Trait that is shared by both [`Node::Data`] and [`Node::Directory`].
pub trait NodeBase {
    #[doc(hidden)]
    fn get_base(&self) -> &ffi::PE_ResourceNode;

    /// Integer that identifies the Type, Name, or Language ID of the entry
    /// depending on its [`NodeBase::depth`] in the tree
    fn id(&self) -> u32 {
        self.get_base().id()
    }

    /// Current depth of the Node in the resource tree
    fn depth(&self) -> u32 {
        self.get_base().depth()
    }

    /// Iterator on node's children
    fn children(&self) -> Children {
        Children::new(self.get_base().childs())
    }
}

impl std::fmt::Debug for &dyn NodeBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeBase").field("id", &self.id()).finish()
    }
}

impl<'a> FromFFI<ffi::PE_ResourceNode> for Node<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::PE_ResourceNode>) -> Self {
        unsafe {
            let cmd_ref = ffi_entry.as_ref().unwrap();

            if ffi::PE_ResourceDirectory::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_ResourceNode>;
                    type To = cxx::UniquePtr<ffi::PE_ResourceDirectory>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Node::Directory(Directory::from_ffi(raw))
            } else {
                assert!(
                    ffi::PE_ResourceData::classof(cmd_ref),
                    "Must be a ResourceData node"
                );

                let raw = {
                    type From = cxx::UniquePtr<ffi::PE_ResourceNode>;
                    type To = cxx::UniquePtr<ffi::PE_ResourceData>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Node::Data(Data::from_ffi(raw))
            }
        }
    }
}

pub struct Data<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ResourceData>,
    _owner: PhantomData<&'a Node<'a>>,
}

impl Data<'_> {
    /// Return the code page that is used to decode code point
    /// values within the resource data. Typically, the code page is the unicode code page.
    pub fn code_page(&self) -> u32 {
        self.ptr.code_page()
    }

    /// Reserved value. Should be `0`
    pub fn reserved(&self) -> u32 {
        self.ptr.reserved()
    }

    /// Offset of the content within the resource
    ///
    /// <div class="warning">this value may change when rebuilding resource table</div>
    pub fn offset(&self) -> u32 {
        self.ptr.offset()
    }

    /// Resource content
    pub fn content(&self) -> &[u8] {
        to_slice!(self.ptr.content());
    }
}

impl NodeBase for Data<'_> {
    fn get_base(&self) -> &ffi::PE_ResourceNode {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl fmt::Debug for Data<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self as &dyn NodeBase;
        f.debug_struct("Data")
            .field("base", &base)
            .field("code_page", &self.code_page())
            .field("reserved", &self.reserved())
            .field("offset", &self.offset())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ResourceData> for Data<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourceData>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub struct Directory<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ResourceDirectory>,
    _owner: PhantomData<&'a Node<'a>>,
}

impl Directory<'_> {

    /// Resource characteristics. This field is reserved for future use.
    /// It is currently set to zero.
    pub fn characteristics(&self) -> u32 {
        self.ptr.characteristics()
    }

    /// The time that the resource data was created by the
    /// resource compiler.
    pub fn time_date_stamp(&self) -> u32 {
        self.ptr.time_date_stamp()
    }

    /// The major version number, set by the user.
    pub fn major_version(&self) -> u32 {
        self.ptr.major_version()
    }

    /// The minor version number, set by the user.
    pub fn minor_version(&self) -> u32 {
        self.ptr.minor_version()
    }

    /// The number of directory entries immediately
    /// following the table that use strings to identify Type,
    /// Name, or Language entries (depending on the level of the table).
    pub fn numberof_name_entries(&self) -> u32 {
        self.ptr.numberof_name_entries()
    }


    /// The number of directory entries immediately
    /// following the Name entries that use numeric IDs for
    /// Type, Name, or Language entries.
    pub fn numberof_id_entries(&self) -> u32 {
        self.ptr.numberof_id_entries()
    }
}

impl NodeBase for Directory<'_> {
    fn get_base(&self) -> &ffi::PE_ResourceNode {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl NodeBase for Node<'_> {
    fn get_base(&self) -> &ffi::PE_ResourceNode {
        match &self {
            Node::Data(n) => {
                n.get_base()
            }
            Node::Directory(n) => {
                n.get_base()
            }
        }
    }
}

impl fmt::Debug for Directory<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self as &dyn NodeBase;
        f.debug_struct("Directory")
            .field("base", &base)
            .field("characteristics", &self.characteristics())
            .field("time_date_stamp", &self.time_date_stamp())
            .field("major_version", &self.major_version())
            .field("minor_version", &self.minor_version())
            .field("numberof_name_entries", &self.numberof_name_entries())
            .field("numberof_id_entries", &self.numberof_id_entries())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ResourceDirectory> for Directory<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourceDirectory>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub struct Manager<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ResourcesManager>,
    _owner: PhantomData<&'a Node<'a>>,
}

impl<'a> FromFFI<ffi::PE_ResourcesManager> for Manager<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourcesManager>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

declare_iterator!(
    Children,
    Node<'a>,
    ffi::PE_ResourceNode,
    ffi::PE_Binary,
    ffi::PE_ResourceNode_it_childs
);
