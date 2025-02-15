//! This module contains the different structures involved in the PE's resource tree
//!
//! One can access this tree using either: [`crate::pe::Binary::resources`] or by parsing raw bytes
//! with [`Node::from_slice`]. The [`Manager`] provides a logical API over the resource tree
//! to access specifics parts of the tree.

use lief_ffi as ffi;

use std::pin::Pin;
use std::{fmt, marker::PhantomData};

use crate::to_slice;
use crate::{common::FromFFI, declare_iterator};
use crate::common::into_optional;

/// This enum represents a node in the resource tree which can be either: a **directory** node
/// or a data (leaf) node.
#[derive(Debug)]
pub enum Node<'a> {
    /// A *data* node (i.e. a leaf)
    Data(Data<'a>),
    /// A directory node
    Directory(Directory<'a>),
}

impl Node<'_> {
    /// Parse a resource tree from the provided slice. The original RVA must be provided
    /// to resolve the content of the data nodes.
    pub fn from_slice(content: &[u8], rva: u64) -> Option<Node> {
        unsafe {
            let ptr = ffi::PE_ResourceNode::from_slice(content.as_ptr(), content.len(), rva);
            if ptr.is_null() {
                return None
            }
            Some(Node::from_ffi(ptr))
        }
    }
}

/// Trait that is shared by both [`Node::Data`] and [`Node::Directory`].
pub trait NodeBase {
    #[doc(hidden)]
    fn get_base(&self) -> &ffi::PE_ResourceNode;

    #[doc(hidden)]
    fn base_as_pin_mut(&mut self) -> Pin<&mut ffi::PE_ResourceNode>;

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

    /// Name of the node (if any)
    fn name(&self) -> Option<String> {
        if !self.get_base().has_name() {
            return None;
        }
        Some(self.get_base().name().to_string())
    }

    /// Add a new child node to the current and return the newly-added node
    fn add_child(&mut self, node: &Node) -> Node {
        Node::from_ffi(self.base_as_pin_mut().add_child(node.get_base()))
    }

    /// Delete the child node with the given id
    fn delete_child(&mut self, id: u32) {
        self.base_as_pin_mut().delete_child(id);
    }
}

impl std::fmt::Debug for &dyn NodeBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeBase").field("id", &self.id()).finish()
    }
}


impl std::fmt::Display for &dyn NodeBase {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.get_base().print())
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
    /// Create a new Data node with the provided payload
    pub fn with_buffer(buffer: &[u8]) -> Data<'static> {
        unsafe {
            Data::from_ffi(ffi::PE_ResourceData::create_from_data(buffer.as_ptr(), buffer.len()))
        }
    }

    /// Create a new Data node
    pub fn new() -> Data<'static> {
        Data::from_ffi(ffi::PE_ResourceData::create())
    }

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

    /// Change or set the raw data associated with this node
    pub fn set_content(&mut self, content: &[u8]) -> &mut Self {
        unsafe {
            self.ptr.pin_mut().set_content(content.as_ptr(), content.len());
        }
        self
    }

    /// Change or set the code page
    pub fn set_code_page(&mut self, code_page: u32) -> &mut Self {
        self.ptr.pin_mut().set_code_page(code_page);
        self
    }

    /// Change or set the *reserved* field
    pub fn set_reserved(&mut self, reserved: u32) -> &mut Self {
        self.ptr.pin_mut().set_reserved(reserved);
        self
    }
}

impl NodeBase for Data<'_> {
    fn get_base(&self) -> &ffi::PE_ResourceNode {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn base_as_pin_mut(&mut self) -> Pin<&mut ffi::PE_ResourceNode> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref()
                    as *const ffi::PE_ResourceNode
                    as *mut ffi::PE_ResourceNode).as_mut().unwrap()
            })
        }
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
    /// Create a new Directory node with the given d
    pub fn with_id(id: u32) -> Directory<'static> {
        Directory::from_ffi(ffi::PE_ResourceDirectory::create_from_id(id))
    }

    /// Create a new Directory node
    pub fn new() -> Directory<'static> {
        Directory::from_ffi(ffi::PE_ResourceDirectory::create())
    }

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

    fn base_as_pin_mut(&mut self) -> Pin<&mut ffi::PE_ResourceNode> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref()
                    as *const ffi::PE_ResourceNode
                    as *mut ffi::PE_ResourceNode).as_mut().unwrap()
            })
        }
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

    fn base_as_pin_mut(&mut self) -> Pin<&mut ffi::PE_ResourceNode> {
        match self {
            Node::Data(n) => {
                n.base_as_pin_mut()
            }
            Node::Directory(n) => {
                n.base_as_pin_mut()
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

/// This manager abstracts the tree representation to provide a comprehensive API over
/// the information wrapped by the resources tree.
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

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Types {
    CURSOR,
    BITMAP,
    ICON,
    MENU,
    DIALOG,
    STRING,
    FONTDIR,
    FONT,
    ACCELERATOR,
    RCDATA,
    MESSAGETABLE,
    GROUP_CURSOR,
    GROUP_ICON,
    VERSION,
    DLGINCLUDE,
    PLUGPLAY,
    VXD,
    ANICURSOR,
    ANIICON,
    HTML,
    MANIFEST,
    UNKNOWN(u32),
}

impl From<u32> for Types {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Types::CURSOR,
            0x00000002 => Types::BITMAP,
            0x00000003 => Types::ICON,
            0x00000004 => Types::MENU,
            0x00000005 => Types::DIALOG,
            0x00000006 => Types::STRING,
            0x00000007 => Types::FONTDIR,
            0x00000008 => Types::FONT,
            0x00000009 => Types::ACCELERATOR,
            0x0000000a => Types::RCDATA,
            0x0000000b => Types::MESSAGETABLE,
            0x0000000c => Types::GROUP_CURSOR,
            0x0000000e => Types::GROUP_ICON,
            0x00000010 => Types::VERSION,
            0x00000011 => Types::DLGINCLUDE,
            0x00000013 => Types::PLUGPLAY,
            0x00000014 => Types::VXD,
            0x00000015 => Types::ANICURSOR,
            0x00000016 => Types::ANIICON,
            0x00000017 => Types::HTML,
            0x00000018 => Types::MANIFEST,
            _ => Types::UNKNOWN(value),

        }
    }
}
impl From<Types> for u32 {
    fn from(value: Types) -> u32 {
        match value {
            Types::CURSOR => 0x00000001,
            Types::BITMAP => 0x00000002,
            Types::ICON => 0x00000003,
            Types::MENU => 0x00000004,
            Types::DIALOG => 0x00000005,
            Types::STRING => 0x00000006,
            Types::FONTDIR => 0x00000007,
            Types::FONT => 0x00000008,
            Types::ACCELERATOR => 0x00000009,
            Types::RCDATA => 0x0000000a,
            Types::MESSAGETABLE => 0x0000000b,
            Types::GROUP_CURSOR => 0x0000000c,
            Types::GROUP_ICON => 0x0000000e,
            Types::VERSION => 0x00000010,
            Types::DLGINCLUDE => 0x00000011,
            Types::PLUGPLAY => 0x00000013,
            Types::VXD => 0x00000014,
            Types::ANICURSOR => 0x00000015,
            Types::ANIICON => 0x00000016,
            Types::HTML => 0x00000017,
            Types::MANIFEST => 0x00000018,
            Types::UNKNOWN(value) => value,

        }
    }
}

impl Manager<'_> {
    /// Return the manifest as a string. This manifest matches the node associated with
    /// the type: [`Types::MANIFEST`].
    pub fn manifest(&self) -> String {
        self.ptr.manifest().to_string()
    }

    /// Change or set the manifest. If the manifest node path does not exist,
    /// all required nodes are created.
    pub fn set_manifest(&mut self, content: &str) {
        self.ptr.pin_mut().set_manifest(content);
    }

    /// Try to find the node associated with the given [`Types`]
    ///
    /// This type corresponds to the [`Node::id`] at the **level 1** of the
    /// resource tree.
    pub fn find_by_type(&self, res_type: Types) -> Option<Node> {
        into_optional(self.ptr.find_node_type(res_type.into()))
    }

    /// Return the list of [`Types`] exposed by the resource tree.
    pub fn types(&self) -> Vec<Types> {
        self.ptr.get_types().iter().map(|v| Types::from(*v)).collect()
    }

    /// Print the current resources a tree in a pretty representation.
    ///
    /// ```text
    /// │  ├── Directory ID: 0016 (0x0010) type: VERSION
    /// │  │  └── Directory ID: 0001 (0x0001)
    /// │  │      └── Data ID: 1033 (0x0409) [...]
    /// │  │          ├── Hex: c0:03:34:00:00:00:[...]
    /// │  │          └── Str: ..4...V.S._.V.E.R.S.
    /// │  └── Directory ID: 0024 (0x0018) type: MANIFEST
    /// │      └── Directory ID: 0001 (0x0001)
    /// │          └── Data ID: 1033 (0x0409) [...]
    /// │              ├── Hex: 3c:3f:78:6d:6c:20:[...]
    /// │              └── Str: <?xml version="1.0"
    /// ```
    pub fn print_tree(&self) -> String {
        self.ptr.print_tree().to_string()
    }

    /// Same as [`Manager::print_tree`] but with a maximal depth provided in the
    /// first parameter.
    pub fn print_tree_with_depth(&self, depth: u32) -> String {
        self.ptr.print_tree_with_depth(depth).to_string()
    }
}

declare_iterator!(
    Children,
    Node<'a>,
    ffi::PE_ResourceNode,
    ffi::PE_Binary,
    ffi::PE_ResourceNode_it_childs
);
