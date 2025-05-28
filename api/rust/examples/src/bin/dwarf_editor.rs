/// This example shows how to create a DWARF file by using LIEF's API

use std::process::ExitCode;
use lief::dwarf::editor::types::EditorType;

fn main() -> ExitCode {
    if !lief::is_extended() {
        println!("This example requires the extended version of LIEF")
    }
    let mut args = std::env::args();
    if args.len() != 2 {
        println!("Usage: {} <binary>", args.next().unwrap());
        return ExitCode::FAILURE;
    }

    let path = std::env::args().last().unwrap();

    let mut bin = lief::pe::Binary::parse(&path).unwrap();
    let mut editor = lief::dwarf::Editor::from_binary(&mut bin).unwrap();

    let mut unit = editor.create_compile_unit().unwrap();
    unit.set_producer("LIEF");

    let mut func = unit.create_function("hello").unwrap();
    func.set_address(0x123);
    func.set_return_type(
        &unit.create_structure("my_struct_t").pointer_to()
    );

    let mut var = func.create_stack_variable("local_var");
    var.set_stack_offset(8);

    editor.write("/tmp/out.debug");
    ExitCode::SUCCESS
}
