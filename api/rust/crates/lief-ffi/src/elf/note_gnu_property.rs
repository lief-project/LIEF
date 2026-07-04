#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/ELF/NoteGnuProperty.hpp");

        type ELF_Note = crate::elf::note::ffi::ELF_Note;

        type ELF_NoteGnuProperty;

        #[Self = "ELF_NoteGnuProperty"]
        fn classof(note: &ELF_Note) -> bool;
        fn properties(self: &ELF_NoteGnuProperty) -> UniquePtr<ELF_NoteGnuProperty_it_properties>;
        fn find(self: &ELF_NoteGnuProperty, type_: u32) -> UniquePtr<ELF_NoteGnuProperty_Property>;

        type ELF_NoteGnuProperty_AArch64Feature;

        #[Self = "ELF_NoteGnuProperty_AArch64Feature"]
        fn classof(prop: &ELF_NoteGnuProperty_Property) -> bool;
        fn features(self: &ELF_NoteGnuProperty_AArch64Feature) -> UniquePtr<CxxVector<u64>>;

        type ELF_NoteGnuProperty_AArch64PAuth;

        #[Self = "ELF_NoteGnuProperty_AArch64PAuth"]
        fn classof(prop: &ELF_NoteGnuProperty_Property) -> bool;
        fn platform(self: &ELF_NoteGnuProperty_AArch64PAuth) -> u64;
        fn version(self: &ELF_NoteGnuProperty_AArch64PAuth) -> u64;

        type ELF_NoteGnuProperty_Generic;

        #[Self = "ELF_NoteGnuProperty_Generic"]
        fn classof(prop: &ELF_NoteGnuProperty_Property) -> bool;
        fn raw_type(self: &ELF_NoteGnuProperty_Generic) -> u32;

        type ELF_NoteGnuProperty_Needed;

        #[Self = "ELF_NoteGnuProperty_Needed"]
        fn classof(prop: &ELF_NoteGnuProperty_Property) -> bool;
        fn needs(self: &ELF_NoteGnuProperty_Needed) -> UniquePtr<CxxVector<u64>>;

        type ELF_NoteGnuProperty_NoteNoCopyOnProtected;

        #[Self = "ELF_NoteGnuProperty_NoteNoCopyOnProtected"]
        fn classof(prop: &ELF_NoteGnuProperty_Property) -> bool;

        type ELF_NoteGnuProperty_Property;

        fn get_type(self: &ELF_NoteGnuProperty_Property) -> u32;

        type ELF_NoteGnuProperty_StackSize;

        #[Self = "ELF_NoteGnuProperty_StackSize"]
        fn classof(prop: &ELF_NoteGnuProperty_Property) -> bool;
        fn stack_size(self: &ELF_NoteGnuProperty_StackSize) -> u64;

        type ELF_NoteGnuProperty_X86Features;

        #[Self = "ELF_NoteGnuProperty_X86Features"]
        fn classof(prop: &ELF_NoteGnuProperty_Property) -> bool;
        fn features(self: &ELF_NoteGnuProperty_X86Features) -> UniquePtr<CxxVector<u64>>;

        type ELF_NoteGnuProperty_X86ISA;

        #[Self = "ELF_NoteGnuProperty_X86ISA"]
        fn classof(prop: &ELF_NoteGnuProperty_Property) -> bool;
        fn values(self: &ELF_NoteGnuProperty_X86ISA) -> UniquePtr<CxxVector<u64>>;

        type ELF_NoteGnuProperty_it_properties;

        fn next(
            self: Pin<&mut ELF_NoteGnuProperty_it_properties>,
        ) -> UniquePtr<ELF_NoteGnuProperty_Property>;
        fn size(self: &ELF_NoteGnuProperty_it_properties) -> u64;
    }
    impl UniquePtr<ELF_NoteGnuProperty> {}
    impl UniquePtr<ELF_NoteGnuProperty_AArch64Feature> {}
    impl UniquePtr<ELF_NoteGnuProperty_AArch64PAuth> {}
    impl UniquePtr<ELF_NoteGnuProperty_Generic> {}
    impl UniquePtr<ELF_NoteGnuProperty_it_properties> {}
    impl UniquePtr<ELF_NoteGnuProperty_Needed> {}
    impl UniquePtr<ELF_NoteGnuProperty_NoteNoCopyOnProtected> {}
    impl UniquePtr<ELF_NoteGnuProperty_Property> {}
    impl UniquePtr<ELF_NoteGnuProperty_StackSize> {}
    impl UniquePtr<ELF_NoteGnuProperty_X86Features> {}
    impl UniquePtr<ELF_NoteGnuProperty_X86ISA> {}
}
