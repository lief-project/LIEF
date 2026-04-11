//! This module contains the different structures involved in the PE's resource tree
//!
//! One can access this tree using either: [`crate::pe::Binary::resources`] or by parsing raw bytes
//! with [`Node::from_slice`]. The [`Manager`] provides a logical API over the resource tree
//! to access specifics parts of the tree.

use lief_ffi as ffi;

use std::pin::Pin;
use std::{fmt, marker::PhantomData};

use crate::common::into_optional;
use crate::to_slice;
use crate::{common::FromFFI, declare_iterator};

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
    pub fn from_slice(content: &[u8], rva: u64) -> Option<Node<'_>> {
        unsafe {
            let ptr = ffi::PE_ResourceNode::from_slice(content.as_ptr(), content.len(), rva);
            if ptr.is_null() {
                return None;
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
    fn children(&self) -> Children<'_> {
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
    fn add_child(&mut self, node: &Node) -> Node<'_> {
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
            Data::from_ffi(ffi::PE_ResourceData::create_from_data(
                buffer.as_ptr(),
                buffer.len(),
            ))
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
            self.ptr
                .pin_mut()
                .set_content(content.as_ptr(), content.len());
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
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::PE_ResourceNode
                    as *mut ffi::PE_ResourceNode)
                    .as_mut()
                    .unwrap()
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
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::PE_ResourceNode
                    as *mut ffi::PE_ResourceNode)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

impl NodeBase for Node<'_> {
    fn get_base(&self) -> &ffi::PE_ResourceNode {
        match &self {
            Node::Data(n) => n.get_base(),
            Node::Directory(n) => n.get_base(),
        }
    }

    fn base_as_pin_mut(&mut self) -> Pin<&mut ffi::PE_ResourceNode> {
        match self {
            Node::Data(n) => n.base_as_pin_mut(),
            Node::Directory(n) => n.base_as_pin_mut(),
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
    pub fn find_by_type(&self, res_type: Types) -> Option<Node<'_>> {
        into_optional(self.ptr.find_node_type(res_type.into()))
    }

    /// Return the list of [`Types`] exposed by the resource tree.
    pub fn types(&self) -> Vec<Types> {
        self.ptr
            .get_types()
            .iter()
            .map(|v| Types::from(*v))
            .collect()
    }

    /// Return the HTML resources as a list of strings
    pub fn html(&self) -> Vec<String> {
        self.ptr.html().iter().map(|s| s.to_string()).collect()
    }

    /// Return an iterator over the resource icons
    pub fn icons(&self) -> Icons<'_> {
        Icons::new(self.ptr.icons())
    }

    /// Return an iterator over the resource version entries
    pub fn version(&self) -> Versions<'_> {
        Versions::new(self.ptr.version())
    }

    /// Return an iterator over the resource accelerator entries
    pub fn accelerator(&self) -> Accelerators<'_> {
        Accelerators::new(self.ptr.accelerator())
    }

    /// Return an iterator over the string table entries
    pub fn string_table(&self) -> StringTableEntries<'_> {
        StringTableEntries::new(self.ptr.string_table())
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

/// Represents a PE icon resource
pub struct Icon<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ResourceIcon>,
    _owner: PhantomData<&'a ffi::PE_ResourcesManager>,
}

impl Icon<'_> {
    /// ID of the icon
    pub fn id(&self) -> u32 {
        self.ptr.id()
    }

    /// Language of the icon
    pub fn lang(&self) -> u32 {
        self.ptr.lang()
    }

    /// Sublanguage of the icon
    pub fn sublang(&self) -> u32 {
        self.ptr.sublang()
    }

    /// Width in pixels
    pub fn width(&self) -> u8 {
        self.ptr.width()
    }

    /// Height in pixels
    pub fn height(&self) -> u8 {
        self.ptr.height()
    }

    /// Number of colors in the palette (0 if more than 256)
    pub fn color_count(&self) -> u8 {
        self.ptr.color_count()
    }

    /// Reserved (should be 0)
    pub fn reserved(&self) -> u8 {
        self.ptr.reserved()
    }

    /// Number of color planes
    pub fn planes(&self) -> u16 {
        self.ptr.planes()
    }

    /// Bits per pixel
    pub fn bit_count(&self) -> u16 {
        self.ptr.bit_count()
    }

    /// Size of the icon pixel data
    pub fn size(&self) -> u32 {
        self.ptr.size()
    }

    /// Raw pixel data of the icon
    pub fn pixels(&self) -> &[u8] {
        to_slice!(self.ptr.pixels());
    }
}

impl fmt::Debug for Icon<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Icon")
            .field("id", &self.id())
            .field("width", &self.width())
            .field("height", &self.height())
            .field("color_count", &self.color_count())
            .field("bit_count", &self.bit_count())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ResourceIcon> for Icon<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourceIcon>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// Represents fixed file information from a version resource
#[derive(Debug, Clone)]
pub struct FixedFileInfo {
    /// Contains the value `0xFEEF04BD`. This is used with the `szKey` member of
    /// the `VS_VERSIONINFO` structure when searching a file for the
    /// `VS_FIXEDFILEINFO` structure.
    pub signature: u32,

    /// The binary version number of this structure. The high-order word of
    /// this member contains the major version number, and the low-order word
    /// contains the minor version number.
    pub struct_version: u32,

    /// The most significant 32 bits of the file's binary version number.
    /// This member is used with file_version_ls to form a 64-bit value used
    /// for numeric comparisons.
    pub file_version_ms: u32,

    /// The least significant 32 bits of the file's binary version number.
    /// This member is used with file_version_ms to form a 64-bit value used for
    /// numeric comparisons.
    pub file_version_ls: u32,

    /// The most significant 32 bits of the binary version number of the product
    /// with which this file was distributed. This member is used with
    /// product_version_ls to form a 64-bit value used for numeric comparisons.
    pub product_version_ms: u32,

    /// The least significant 32 bits of the binary version number of the product
    /// with which this file was distributed. This member is used with
    /// product_version_ms to form a 64-bit value used for numeric comparisons.
    pub product_version_ls: u32,

    /// Contains a bitmask that specifies the valid bits in file_flags.
    /// A bit is valid only if it was defined when the file was created.
    pub file_flags_mask: u32,

    /// Contains a bitmask that specifies the Boolean attributes of the file.
    /// This member can include one or more of the values specified in FILE_FLAGS
    pub file_flags: u32,

    /// The operating system for which this file was designed. This member can
    /// be one of the values specified in VERSION_OS.
    pub file_os: u32,

    /// The general type of file. This member can be one of the values specified
    /// in FILE_TYPE. All other values are reserved.
    pub file_type: u32,

    /// The function of the file. The possible values depend on the value of
    /// file_type.
    pub file_subtype: u32,

    /// The most significant 32 bits of the file's 64-bit binary creation date
    /// and time stamp.
    pub file_date_ms: u32,

    /// The least significant 32 bits of the file's 64-bit binary creation date
    /// and time stamp.
    pub file_date_ls: u32,
}

/// Represents a string table entry (key/value) from a StringFileInfo
#[derive(Debug, Clone)]
pub struct VersionStringTableEntry {
    /// Key of the entry
    pub key: String,
    /// Value of the entry
    pub value: String,
}

impl FromFFI<ffi::PE_ResourceStringTable_entry_t> for VersionStringTableEntry {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourceStringTable_entry_t>) -> Self {
        Self {
            key: ptr.key().to_string(),
            value: ptr.value().to_string(),
        }
    }
}

/// Represents a string table within a StringFileInfo
pub struct VersionStringTable<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ResourceStringTable>,
    _owner: PhantomData<&'a ffi::PE_ResourceVersion>,
}

impl VersionStringTable<'_> {
    /// Type of the string table
    pub fn get_type(&self) -> u16 {
        self.ptr.get_type()
    }

    /// Key identifying the string table (typically a language/codepage pair)
    pub fn key(&self) -> String {
        self.ptr.key().to_string()
    }

    /// Return an iterator over the key/value entries
    pub fn entries(&self) -> VersionStringTableEntries<'_> {
        VersionStringTableEntries::new(self.ptr.entries())
    }
}

impl fmt::Debug for VersionStringTable<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionStringTable")
            .field("key", &self.key())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ResourceStringTable> for VersionStringTable<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourceStringTable>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// Represents a Var entry within VarFileInfo
pub struct ResourceVar<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ResourceVar>,
    _owner: PhantomData<&'a ffi::PE_ResourceVersion>,
}

impl ResourceVar<'_> {
    /// Type of the var entry
    pub fn get_type(&self) -> u16 {
        self.ptr.get_type()
    }

    /// Key of the var entry
    pub fn key(&self) -> String {
        self.ptr.key().to_string()
    }

    /// Values of the var entry (language/codepage pairs)
    pub fn values(&self) -> Vec<u32> {
        self.ptr.values().iter().map(|&v| v as u32).collect()
    }
}

impl fmt::Debug for ResourceVar<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceVar")
            .field("key", &self.key())
            .field("values", &self.values())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ResourceVar> for ResourceVar<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourceVar>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// Represents a StringFileInfo structure from a version resource
pub struct StringFileInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ResourceStringFileInfo>,
    _owner: PhantomData<&'a ffi::PE_ResourceVersion>,
}

impl StringFileInfo<'_> {
    /// Type of the StringFileInfo
    pub fn get_type(&self) -> u16 {
        self.ptr.get_type()
    }

    /// Key of the StringFileInfo
    pub fn key(&self) -> String {
        self.ptr.key().to_string()
    }

    /// Return an iterator over the child string tables
    pub fn children(&self) -> StringFileInfoChildren<'_> {
        StringFileInfoChildren::new(self.ptr.children())
    }
}

impl fmt::Debug for StringFileInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StringFileInfo")
            .field("key", &self.key())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ResourceStringFileInfo> for StringFileInfo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourceStringFileInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// Represents a VarFileInfo structure from a version resource
pub struct VarFileInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ResourceVarFileInfo>,
    _owner: PhantomData<&'a ffi::PE_ResourceVersion>,
}

impl VarFileInfo<'_> {
    /// Type of the VarFileInfo
    pub fn get_type(&self) -> u16 {
        self.ptr.get_type()
    }

    /// Key of the VarFileInfo
    pub fn key(&self) -> String {
        self.ptr.key().to_string()
    }

    /// Return an iterator over the Var entries
    pub fn vars(&self) -> VarFileInfoVars<'_> {
        VarFileInfoVars::new(self.ptr.vars())
    }
}

impl fmt::Debug for VarFileInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VarFileInfo")
            .field("key", &self.key())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ResourceVarFileInfo> for VarFileInfo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourceVarFileInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// Represents a PE version resource
pub struct Version<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ResourceVersion>,
    _owner: PhantomData<&'a ffi::PE_ResourcesManager>,
}

impl Version<'_> {
    /// Type of the version resource
    pub fn get_type(&self) -> u16 {
        self.ptr.get_type()
    }

    /// Key of the version resource
    pub fn key(&self) -> String {
        self.ptr.key().to_string()
    }

    /// Return the fixed file information if present
    pub fn file_info(&self) -> FixedFileInfo {
        FixedFileInfo {
            signature: self.ptr.file_info_signature(),
            struct_version: self.ptr.file_info_struct_version(),
            file_version_ms: self.ptr.file_info_file_version_ms(),
            file_version_ls: self.ptr.file_info_file_version_ls(),
            product_version_ms: self.ptr.file_info_product_version_ms(),
            product_version_ls: self.ptr.file_info_product_version_ls(),
            file_flags_mask: self.ptr.file_info_file_flags_mask(),
            file_flags: self.ptr.file_info_file_flags(),
            file_os: self.ptr.file_info_file_os(),
            file_type: self.ptr.file_info_file_type(),
            file_subtype: self.ptr.file_info_file_subtype(),
            file_date_ms: self.ptr.file_info_file_date_ms(),
            file_date_ls: self.ptr.file_info_file_date_ls(),
        }
    }

    /// Return the StringFileInfo if present
    pub fn string_file_info(&self) -> Option<StringFileInfo<'_>> {
        into_optional(self.ptr.string_file_info())
    }

    /// Return the VarFileInfo if present
    pub fn var_file_info(&self) -> Option<VarFileInfo<'_>> {
        into_optional(self.ptr.var_file_info())
    }
}

impl fmt::Debug for Version<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Version").field("key", &self.key()).finish()
    }
}

impl<'a> FromFFI<ffi::PE_ResourceVersion> for Version<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourceVersion>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// Represents a PE accelerator resource entry
pub struct Accelerator<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ResourceAccelerator>,
    _owner: PhantomData<&'a ffi::PE_ResourcesManager>,
}

impl Accelerator<'_> {
    /// Flags for the accelerator
    pub fn flags(&self) -> i16 {
        self.ptr.flags()
    }

    /// ANSI code of the accelerator key
    pub fn ansi(&self) -> i16 {
        self.ptr.ansi()
    }

    /// ID of the accelerator
    pub fn id(&self) -> u16 {
        self.ptr.id()
    }

    /// Padding value
    pub fn padding(&self) -> i16 {
        self.ptr.padding()
    }

    /// Return the ANSI string representation of the accelerator key
    pub fn ansi_str(&self) -> String {
        self.ptr.ansi_str().to_string()
    }
}

impl fmt::Debug for Accelerator<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accelerator")
            .field("id", &self.id())
            .field("flags", &self.flags())
            .field("ansi", &self.ansi())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ResourceAccelerator> for Accelerator<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourceAccelerator>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

/// Represents a string table entry from the ResourcesManager
pub struct StringEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ResourcesManager_string_entry_t>,
    _owner: PhantomData<&'a ffi::PE_ResourcesManager>,
}

impl StringEntry<'_> {
    /// The string value
    pub fn string(&self) -> String {
        self.ptr.string().to_string()
    }

    /// The ID associated with this string
    pub fn id(&self) -> u32 {
        self.ptr.id()
    }
}

impl fmt::Debug for StringEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StringEntry")
            .field("id", &self.id())
            .field("string", &self.string())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ResourcesManager_string_entry_t> for StringEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ResourcesManager_string_entry_t>) -> Self {
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

declare_iterator!(
    Icons,
    Icon<'a>,
    ffi::PE_ResourceIcon,
    ffi::PE_ResourcesManager,
    ffi::PE_ResourcesManager_it_icons
);

declare_iterator!(
    Versions,
    Version<'a>,
    ffi::PE_ResourceVersion,
    ffi::PE_ResourcesManager,
    ffi::PE_ResourcesManager_it_version
);

declare_iterator!(
    Accelerators,
    Accelerator<'a>,
    ffi::PE_ResourceAccelerator,
    ffi::PE_ResourcesManager,
    ffi::PE_ResourcesManager_it_accelerator
);

declare_iterator!(
    StringTableEntries,
    StringEntry<'a>,
    ffi::PE_ResourcesManager_string_entry_t,
    ffi::PE_ResourcesManager,
    ffi::PE_ResourcesManager_it_string_table_entry
);

declare_iterator!(
    VersionStringTableEntries,
    VersionStringTableEntry,
    ffi::PE_ResourceStringTable_entry_t,
    ffi::PE_ResourceStringTable,
    ffi::PE_ResourceStringTable_it_entries
);

declare_iterator!(
    StringFileInfoChildren,
    VersionStringTable<'a>,
    ffi::PE_ResourceStringTable,
    ffi::PE_ResourceStringFileInfo,
    ffi::PE_ResourceStringFileInfo_it_children
);

declare_iterator!(
    VarFileInfoVars,
    ResourceVar<'a>,
    ffi::PE_ResourceVar,
    ffi::PE_ResourceVarFileInfo,
    ffi::PE_ResourceVarFileInfo_it_vars
);
