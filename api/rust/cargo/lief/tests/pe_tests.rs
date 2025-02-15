mod utils;
use std::fmt::format;
use std::io::Cursor;
use std::env;
use lief::logging;
use lief::pe::ParserConfig;
use lief::pe::debug::Entries as DebugEntries;
use lief::pe::load_configuration::LoadConfiguration;
use lief::pe::resources::{Node, NodeBase};
use lief::pe::signature::content_info::Content;
use lief::pe::{data_directory, signature, Algorithms};
use lief::pe::signature::attributes::Attribute;
use lief::pe::signature::Signature;
use lief::generic::Symbol;
use lief::generic::Binary as GenericBinary;
use lief::Binary;

fn get_leaf<'a>(node: &'a Node) -> Option<&'a Node<'a>> {
    match node {
        Node::Data(_) => {
            return Some(node);
        }

        Node::Directory(dir) => {
            for child in dir.children() {
                if let Some(Node::Data(data)) = get_leaf(&child) {
                    format!("{}", data.content().len());
                    format!("{data:?}");
                }
            }
        }
    }
    None
}

fn explore_sig_attribute(attr: &Attribute) {
    match attr {
        Attribute::ContentType(item) => {
            format!("{item:?}");
        }
        Attribute::GenericType(item) => {
            format!("{item:?}");
        }
        Attribute::MsSpcNestedSignature(item) => {
            format!("{item:?}");
            explore_signature(&item.signature());
        }
        Attribute::MsSpcStatementType(item) => {
            format!("{item:?}");
        }
        Attribute::PKCS9AtSequenceNumber(item) => {
            format!("{item:?}");
        }
        Attribute::PKCS9CounterSignature(item) => {
            format!("{item:?}");
            let signer = item.signer();
            println!("{}", signer.raw_auth_data().len());
            for attr in signer.authenticated_attributes() {
                explore_sig_attribute(&attr);
            }

            for attr in signer.unauthenticated_attributes() {
                explore_sig_attribute(&attr);
            }
        }
        Attribute::PKCS9MessageDigest(item) => {
            format!("{item:?}");
            format!("{}", item.digest().len());
        }
        Attribute::PKCS9SigningTime(item) => {
            format!("{item:?}");
        }
        Attribute::SpcSpOpusInfo(item) => {
            format!("{item:?}");
        }
        Attribute::MsManifestBinaryID(item) => {
            format!("{}", item.manifest_id());
        }
        Attribute::MsCounterSign(item) => {
            let content_info = item.content_info();
            format!("{content_info:?}");
            for crt in item.certificates() {
                format!("{crt:?}");
                format!("{}", crt.serial_number().len());
                format!("{}", crt.raw().len());
                format!("{}", crt.signature().len());

                if let Some(rsa_info) = crt.rsa_info() {
                    format!("{rsa_info:?}");
                    format!("{}", rsa_info.N().bits());
                    format!("{}", rsa_info.E().bits());
                    format!("{}", rsa_info.D().bits());
                    format!("{}", rsa_info.P().bits());
                    format!("{}", rsa_info.Q().bits());
                }
            }
            for signer in item.signers() {
                format!("{signer:?}");
                if let Some(crt) = signer.cert() {
                    format!("{crt:?}");
                }
                format!("{}", signer.encrypted_digest().len());
                format!("{}", signer.serial_number().len());

                for attr in signer.authenticated_attributes() {
                    explore_sig_attribute(&attr);
                }

                for attr in signer.unauthenticated_attributes() {
                    explore_sig_attribute(&attr);
                }
            }
            let info = item.content_info();
            if let Some(value) = info.value() {
                format!("{:?}", value);
                match value {
                    Content::SpcIndirectData(data) => {
                        format!("{:?}", data);
                        format!("{}", data.digest().len());
                    },
                    Content::PKCS9TSTInfo(data) => {
                        println!("PKCS9TSTInfo");
                    },
                    Content::Generic(generic) => {
                        println!("{}", generic.oid());
                        format!("{}", generic.raw().len());
                    }
                }
            }
        }
        Attribute::SigningCertificateV2(item) => {
            println!("SigningCertificateV2");
        }
        Attribute::SpcRelaxedPeMarkerCheck(item) => {
            println!("SpcRelaxedPeMarkerCheck");
        }
    }
}

fn explore_signature(signature: &Signature) {
    format!("{signature:?}");
    let content_info = signature.content_info();
    format!("{content_info:?}");
    for crt in signature.certificates() {
        format!("{crt:?}");
        format!("{}", crt.serial_number().len());
        format!("{}", crt.raw().len());
        format!("{}", crt.signature().len());

        if let Some(rsa_info) = crt.rsa_info() {
            format!("{rsa_info:?}");
            format!("{}", rsa_info.N().bits());
            format!("{}", rsa_info.E().bits());
            format!("{}", rsa_info.D().bits());
            format!("{}", rsa_info.P().bits());
            format!("{}", rsa_info.Q().bits());
        }
    }
    for signer in signature.signers() {
        format!("{signer:?}");
        if let Some(crt) = signer.cert() {
            format!("{crt:?}");
        }
        format!("{}", signer.encrypted_digest().len());
        format!("{}", signer.serial_number().len());

        for attr in signer.authenticated_attributes() {
            explore_sig_attribute(&attr);
        }

        for attr in signer.unauthenticated_attributes() {
            explore_sig_attribute(&attr);
        }
    }

    let info = signature.content_info();
    if let Some(value) = info.value() {
        format!("{:?}", value);
        match value {
            Content::SpcIndirectData(data) => {
                format!("{:?}", data);
                format!("{}", data.digest().len());
            },
            Content::PKCS9TSTInfo(data) => {
                println!("PKCS9TSTInfo");
            },
            Content::Generic(generic) => {
                println!("{}", generic.oid());
                format!("{}", generic.raw().len());
            }
        }
    }
}

fn explore_pe(bin_name: &str, pe: &lief::pe::Binary) {
    format!("{pe:?}");

    let dos_header = pe.dos_header();
    format!("{dos_header:?}");

    let optional_header = pe.optional_header();
    format!("{optional_header:?}");
    format!("checksum: {}, computed: {}", optional_header.checksum(), pe.compute_checksum());

    let header = pe.header();
    format!("{header:?}");

    format!("{} {}", pe.virtual_size(), pe.sizeof_headers());

    if let Some(dir) = pe.data_directory_by_type(data_directory::Type::RESOURCE_TABLE) {
        if !dir.content().is_empty() {
            let tree = lief::pe::ResourceNode::from_slice(dir.content(), dir.rva() as u64);
            assert!(tree.is_some());
        }
    }

    if let Some(tls) = pe.tls() {
        format!("{tls:?}");
        format!("{}", tls.data_template().len());
        format!("{:?}", tls.addressof_raw_data());
    }

    if let Some(export) = pe.export() {
        format!("{export:?}");
        for entry in export.entries() {
            format!("{entry:?}");
            if lief::is_extended() {
                format!("{}", entry.demangled_name());
            }
        }
    }

    if let Some(resources) = pe.resources() {
        format!("{resources:?}");
        match resources {
            Node::Data(_) => {}

            Node::Directory(dir) => {
                for child in dir.children() {
                    format!("{}", dir.depth());
                    format!("{child:?}");
                }
            }
        }
    }

    if let Some(resources) = pe.resources() {
        if let Some(leaf) = get_leaf(&resources) {
            format!("{leaf:?}");
        }
    }

    for coff_str in pe.coff_string_table() {
        format!("{}:{}", coff_str.str(), coff_str.offset());
    }

    if let Some(config) = pe.load_configuration() {
        format!("{config:?}");

        if let Some(enclave_config) = config.enclave_config() {
            format!("{enclave_config:?} {enclave_config}");
            for entry in enclave_config.imports() {
                format!("{entry:?} {entry}");
            }
        }

        if let Some(volatile) = config.volatile_metadata() {
            format!("{volatile:?} {volatile}");
            for range in volatile.info_ranges() {
                format!("{range:?}");
            }
        }
    }

    if let Some(header) = pe.rich_header() {
        format!("{header:?}");
        for entry in header.entries() {
            format!("{entry:?}");
        }
    }

    let _ = pe.resources_manager();

    for imp in pe.imports() {
        format!("{imp:?}");
        for entry in imp.entries() {
            format!("{entry:?}");
            if lief::is_extended() {
                format!("{}", entry.demangled_name());
            }
        }
    }

    for dir in pe.data_directories() {
        format!("{dir:?}");
    }

    for sym in pe.symbols() {
        format!("{sym:?}");
        for aux in sym.auxiliary_symbols() {
            format!("{aux:?}");
        }
    }

    for section in pe.sections() {
        format!("{section:?}");
        format!("{}", section.padding().len());
        if let Some(coff_str) = section.coff_string() {
            format!("{}", coff_str.str());
        }
    }

    for relocation in pe.relocations() {
        format!("{relocation:?}");
        for entry in relocation.entries() {
            format!("{entry:?}");
        }
    }

    for delay_import in pe.delay_imports() {
        format!("{delay_import:?}");
        for entry in delay_import.entries() {
            format!("{entry:?}");
            if lief::is_extended() {
                format!("{}", entry.demangled_name());
            }
        }
    }

    for signature in pe.signatures() {
        explore_signature(&signature);
    }

    for debug in pe.debug() {
        format!("{debug:?}");
        match debug {
            DebugEntries::Pogo(pogo) => {
                for entry in pogo.entries() {
                    format!("{entry:?}");
                }
            }
            DebugEntries::Repro(repro) => {
                assert!(!repro.hash().is_empty());
            }
            _ => {}
        }
    }

    for func in pe.functions() {
        format!("{func:?}");
    }

    for exception in pe.exceptions() {
        format!("{exception:?}");
    }

    if let Some(nested) = pe.nested_pe_binary() {
        explore_pe(bin_name, &nested);
    }

    format!("overlay: {}, len: {}", pe.overlay_offset(), pe.overlay().len());

    assert!(pe.entrypoint() > 0);

    assert!(!pe.dos_stub().is_empty());
    assert!(!pe.authentihash(Algorithms::SHA_256).is_empty());

    if bin_name == "ntoskrnl.exe" {
        assert_eq!(pe.rva_to_offset(0xA85000), 0x9f3000);
        assert_eq!(pe.va_to_offset(0x140000000 + 0xA85000), 0x9f3000);
        assert!(pe.section_from_offset(0x9f3000).is_some());
        assert!(pe.section_from_offset(0x10009f3000).is_none());

        assert!(pe.section_from_rva(0xA85000).is_some());
        assert!(pe.section_from_rva(0x100A85000).is_none());

        assert!(!pe.content_from_virtual_address(0x140000000 + 0xA85000, 0x10).is_empty());
        assert!(!pe.content_from_virtual_address(0xA85000, 0x10).is_empty());
        assert!(pe.content_from_virtual_address(0xaaaaaaaaaaaa, 0x10).is_empty());

        assert!(pe.section_by_name(".data").is_some());
        assert!(pe.section_by_name(".xdata").is_none());

        assert!(pe.data_directory_by_type(data_directory::Type::IMPORT_TABLE).is_some());

        assert!(pe.import_by_name("BOOTVID.dll").is_some());
        assert!(pe.import_by_name("foo.dll").is_none());
    }

    if bin_name == "PE32_x86-64_binary_avast-free-antivirus-setup-online.exe" {
        assert_eq!(pe.verify_signature(signature::VerificationChecks::DEFAULT),  signature::VerificationFlags::OK);
        let signature = pe.signatures().last().expect("Error");
        let raw_sig = signature.raw_der();
        let mut cursor = Cursor::new(raw_sig);

        let detached = Signature::from(&mut cursor).expect("Error");
        assert_eq!(pe.verify_with_signature(&detached, signature::VerificationChecks::DEFAULT),
                   signature::VerificationFlags::OK);
    }


    if bin_name == "PE64_x86-64_binary_cmd.exe" {
        assert!(pe.delay_import_by_name("foo.dll").is_none());
        assert!(pe.delay_import_by_name("SHELL32.dll").is_some());
    }

}

fn test_with(bin_name: &str) {
    let path = utils::get_pe_sample(bin_name).unwrap();
    let path_str = path.to_str();
    if let Some(pe) = lief::pe::Binary::parse_with_config(path_str.unwrap(), ParserConfig::with_all_options()) {
        explore_pe(bin_name, &pe);
    }

    // Test Read + Seek interface
    let mut file = std::fs::File::open(path).expect("Can't open the file");
    let binary = Binary::from(&mut file);
    assert!(matches!(binary, Some(Binary::PE(_))));
}

fn test_signature(name: &str) {
    let path = utils::get_pkcs7_sample(name).unwrap();
    let path_str = path.to_str();
    if let Some(sig) = Signature::from_file(path_str.unwrap()) {
        explore_signature(&sig);
    }
}

#[test]
fn test_api() {
    let mut dir = env::temp_dir();
    dir.push("lief_pe_test.log");
    logging::set_path(dir.as_path());

    test_with("ntoskrnl.exe");
    test_with("steam.exe");
    test_with("test.debug.repro.exe");
    test_with("PE64_x86-64_library_libLIEF.dll");
    test_with("PE32_x86-64_binary_avast-free-antivirus-setup-online.exe");
    test_with("PE32_x86-64_binary_self-signed.exe");
    test_with("PE64_x86-64_binary_winhello64-mingw.exe");
    test_with("PE64_x86-64_binary_cmd.exe");
    test_with("steam.exe");
    test_with("SFAPE.dll");
    test_with("LIEF-win64.dll");
    test_with("win11_arm64x_Windows.Media.Protection.PlayReady.dll");

    test_signature("cert0.p7b");
    test_signature("cert3.p7b");
    test_signature("cert11.p7b");
    test_signature("cert9.p7b");
    test_signature("cert10.p7b");
}
