mod utils;
use lief;
use std::path::Path;

fn explore_method(meth: &lief::objc::Method) {
    println!(
        "{}{}{}{}{}",
        meth.name(),
        meth.mangled_type(),
        meth.address(),
        meth.address(),
        meth.is_instance()
    );
}

fn explore_proptocol(prot: &lief::objc::Protocol) {
    println!("{}", prot.mangled_name());

    for meth in prot.optional_methods() {
        explore_method(&meth);
    }

    for meth in prot.required_methods() {
        explore_method(&meth);
    }

    for prop in prot.properties() {
        explore_property(&prop);
    }
}

fn explore_property(prop: &lief::objc::Property) {
    println!("{}{}", prop.name(), prop.attribute());
}

fn explore_ivar(ivar: &lief::objc::IVar) {
    println!("{}{}", ivar.name(), ivar.mangled_type());
}

fn explore_class(class: &lief::objc::Class) {
    println!(
        "{}{}{:?}",
        class.name(),
        class.demangled_name(),
        class.is_meta()
    );
    if let Some(parent) = class.super_class() {
        explore_class(&parent);
    }

    for meth in class.methods() {
        explore_method(&meth);
    }

    for prot in class.protocols() {
        explore_proptocol(&prot);
    }

    for prop in class.properties() {
        explore_property(&prop);
    }

    for ivar in class.ivars() {
        explore_ivar(&ivar);
    }
}

fn explore_metadata(name: &str, metadata: &lief::objc::Metadata) {
    for cls in metadata.classes() {
        explore_class(&cls);
    }

    for prot in metadata.protocols() {
        explore_proptocol(&prot);
    }

    println!("{}", metadata.to_decl());

    if name == "Module_Framework" {
        assert!(metadata.class_by_name("GADGestureRecognizer").is_some());
        assert!(metadata.class_by_name("GADGestureRecognizer_xxxx").is_none());

        assert!(metadata.protocol_by_name("PINCaching").is_some());
        assert!(metadata.protocol_by_name("PINCaching_xxx").is_none());
    }
}

fn test_with_str(name: &str, path_str: &str) {
    if let Some(lief::Binary::MachO(fat)) = lief::Binary::parse(path_str) {
        for bin in fat.iter() {
            if let Some(metadata) = bin.objc_metadata() {
                explore_metadata(name, &metadata);
            }
        }
    }
}

fn test_with_fullpath(name: &str, suffix: &str) {
    let path = utils::get_sample(Path::new(suffix)).unwrap();
    let path_str = path.to_str().unwrap();
    test_with_str(name, path_str);
}

#[test]
fn test_api() {
    if !lief::is_extended() {
        return;
    }

    test_with_fullpath("DebugHierarchyKit", "MachO/ios17/DebugHierarchyKit");
    test_with_fullpath(
        "NTKPrideWeaveFaceBundleCompanion",
        "MachO/ios17/NTKPrideWeaveFaceBundleCompanion",
    );
    test_with_fullpath("RNCryptor.bin", "MachO/RNCryptor.bin");
    test_with_fullpath("SingPass", "private/MachO/SingPass");
    test_with_fullpath("Module_Framework", "private/MachO/Module_Framework");
}
