mod utils;
use lief::dwarf::location::{CompositeLocation, Piece, PieceKind};
use lief::dwarf::{Location, Parameter};
use std::path::Path;

fn load(path: &str) -> lief::dwarf::DebugInfo<'static> {
    let path = utils::get_sample(Path::new(path)).unwrap();
    lief::dwarf::load(path).unwrap()
}

fn register(piece: &Piece) -> u64 {
    match piece.location() {
        Some(Location::Register(reg)) => reg.id(),
        _ => panic!("expecting a register location"),
    }
}

fn composite<'a>(loc: Option<Location<'a>>) -> CompositeLocation<'a> {
    match loc {
        Some(Location::Composite(composite)) => composite,
        _ => panic!("expecting a composite location"),
    }
}

fn variable<'a>(func: &'a lief::dwarf::Function, name: &str) -> lief::dwarf::Variable<'a> {
    func.variables().find(|v| v.name() == name).unwrap()
}

#[test]
fn test_parameter_pieces() {
    if !lief::is_extended() {
        return;
    }

    let dbg = load("DWARF/main_DW_OP_piece.elf");
    let func = dbg.function_by_name("process_pair").unwrap();
    let param = func.parameters().next().unwrap();

    let loc = composite(param.location());
    let pieces: Vec<Piece> = loc.pieces().collect();
    assert_eq!(pieces.len(), 2);
    assert_eq!(pieces.iter().map(register).collect::<Vec<_>>(), vec![5, 4]);
    assert_eq!(pieces[1].bit_offset(), 64);
    assert_eq!(pieces[1].bit_size(), 64);
    assert_eq!(pieces[0].kind(), PieceKind::Byte);
    assert_eq!(pieces[0].source_bit_offset(), None);

    let address = func.address().unwrap();
    assert!(param.location_at(address).is_some());
    assert!(param.location_at(address + func.size()).is_none());

    let entries: Vec<_> = param.locations().collect();
    assert_eq!(entries.len(), 1);
    let range = entries[0].range().unwrap();
    assert_eq!((range.low, range.high), (0x1120, 0x1127));
    assert_eq!(entries[0].section_index(), None);
    assert_eq!(
        entries[0].to_string(),
        "[0x1120, 0x1127): pieces {bits [0, 64): register 5 (8 bytes), \
         bits [64, 128): register 4 (8 bytes)}"
    );
}

#[test]
fn test_location_list() {
    if !lief::is_extended() {
        return;
    }

    let dbg = load("DWARF/main_DW_OP_piece.elf");
    let func = dbg.function_by_name("process_mixed").unwrap();
    let param = func.parameters().next().unwrap();
    assert!(param.location().is_none());

    let entries: Vec<_> = param.locations().collect();
    assert_eq!(entries.len(), 2);
    let second = composite(entries[1].location());
    let pieces: Vec<Piece> = second.pieces().collect();
    assert_eq!(pieces.len(), 3);
    assert!(matches!(
        pieces[1].location(),
        Some(Location::Unavailable(_))
    ));
    assert_eq!(pieces[2].bit_offset(), 96);
    match pieces[2].location() {
        Some(Location::Expression(expr)) => {
            assert!(expr.description().contains("DW_OP_stack_value"));
            assert_eq!(expr.expression()[0], 0x74); // DW_OP_breg4
        }
        _ => panic!("expecting an expression"),
    }

    assert_eq!(composite(param.location_at(0x1135)).pieces().count(), 2);
    assert_eq!(composite(param.location_at(0x1136)).pieces().count(), 3);

    let main = dbg.function_by_name("main").unwrap();
    let pair = variable(&main, "pair");
    assert_eq!(pair.locations().count(), 3);
    assert!(pair.location().is_none());
    assert!(!pair.is_stack_based());

    let mixed_var = variable(&main, "mixed");
    let mixed = composite(mixed_var.location_at(0x117c));
    assert_eq!(
        mixed.pieces().map(|p| register(&p)).collect::<Vec<_>>(),
        vec![5, 0, 4]
    );

    match variable(&main, "r1").location() {
        Some(Location::Register(reg)) => assert_eq!(reg.id(), 14),
        _ => panic!("expecting a register"),
    }
}

#[test]
fn test_memory_locations() {
    if !lief::is_extended() {
        return;
    }

    let dbg = load("DWARF/vars_1.elf");
    let g_map = dbg.variable_by_name("g_map").unwrap();
    let loc = g_map.location().unwrap();
    assert_eq!(loc.to_string(), "memory 0x40e0");
    match loc {
        Location::Address(addr) => assert_eq!(addr.address(), 0x40e0),
        _ => panic!("expecting an address"),
    }
    let entries: Vec<_> = g_map.locations().collect();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].range().is_none());

    let main = dbg.function_by_name("main").unwrap();
    let local = variable(&main, "local_var_1");
    assert!(local.is_stack_based());
    match local.location() {
        Some(Location::FrameBase(frame)) => assert_eq!(frame.offset(), -72),
        _ => panic!("expecting a frame-base location"),
    }
}
