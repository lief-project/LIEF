mod utils;
use lief;
use lief::dwarf::editor::types::EditorType;

use std::env;
use std::path::Path;

fn test_with_str(_: &str, path_str: &str) {
    if let Some(lief::Binary::PE(mut bin)) = lief::Binary::parse(path_str) {
        let mut editor = lief::dwarf::Editor::from_binary(&mut bin).expect("Can't load editor");
        {
            let mut unit = editor.create_compile_unit().unwrap();
            unit.set_producer("LIEF Rust test (CU#1)");

            {
                let mut func_1 = unit.create_function("func_1").unwrap();
                func_1.set_address(0x1000);
                func_1.set_return_type(&unit.create_void_type().pointer_to());

                func_1.add_parameter("A", &unit.create_generic_type("generic"));
                {
                    let mut enum_ty = unit.create_enum("enum_ty");
                    enum_ty.add_value("V", 0);
                    enum_ty.set_size(8);
                    func_1.add_parameter("B", &enum_ty);
                }
                {
                    let mut func_ty = unit.create_function_type("my_func_ty");
                    func_ty.set_return_type(&unit.create_void_type().pointer_to());
                    let typedef = unit.create_typedef("my_func_alia", &func_ty);
                    func_1.add_parameter("C", &typedef);
                }
                {
                    let mut struct_ty = unit.create_structure("struct_t");
                    struct_ty.set_size(42);
                    struct_ty.add_member("field_0", &mut unit.create_void_type().pointer_to());
                    struct_ty.add_member_at_offset(
                        "field_0", &mut unit.create_void_type().pointer_to(), 64);
                    func_1.add_parameter("D", &struct_ty);
                }
                {
                    let element_ty = unit.create_base_type("int", 4, lief::dwarf::editor::types::base::Encoding::SIGNED);
                    func_1.set_return_type(&unit.create_array_type("array_t", &element_ty, 8));
                }
                let mut var = func_1.create_stack_variable("my_local_var");
                var.set_stack_offset(8);
                var.set_type(&unit.create_void_type());
                let mut gvar = unit.create_variable("g_var").unwrap();
                gvar.set_addr(0x40000);
            }
        }
        {
            let mut unit = editor.create_compile_unit().unwrap();
            unit.set_producer("LIEF Rust test (CU#2)");
        }

        let mut tempfile = env::temp_dir();
        tempfile.push("out.debug");
        editor.write(tempfile.to_str().unwrap());
    }
}

fn test_with(name: &str, suffix: &str) {
    let path = utils::get_sample(Path::new(suffix)).unwrap();
    let path_str = path.to_str().unwrap();
    test_with_str(name, path_str);
}

#[test]
fn test_api() {
    if !lief::is_extended() {
        return;
    }

    println!("{}", lief::extended_version_info());
    test_with("user32.dll", "PE/user32.dll");
}
