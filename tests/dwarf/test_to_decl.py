import lief
import pytest
from utils import get_sample

from textwrap import dedent

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_annotations():
    libdexprotector = lief.dwarf.load(get_sample("private/DWARF/binaryninja/libdexprotector.so.dwarf"))
    func = libdexprotector.find_function("JNI_OnLoad")
    assert func is not None

    assert func.to_decl() == dedent("""\
    /*
     * Address: 0x1ed4
     */
    jint JNI_OnLoad(JavaVM *vm, void *reserved) {
        /* Start: 0x001eec */ {
            /* Start: 0x001ef8 */ {
              Call the JNI_OnLoad from the payload loaded by the first DT_INIT_ARRAY constructor
            } /* End: 0x001efc */
        } /* End: 0x001f10 */
    }""")

    var = libdexprotector.find_variable("linker64_r_debug")
    assert var is not None
    config = lief.DeclOpt()
    config.is_cpp = True
    assert var.to_decl(config) == dedent("""\
    /*
     * pointer to the r_debug structure defined in the linker(64)
     * Addr: 0xabc8
     * size: 0x0008
     */
    static r_debug_t *linker64_r_debug;""")

    func = libdexprotector.find_function("dp_derive_key")
    assert func is not None

    assert func.to_decl(config) == dedent("""\
    /*
     * Address: 0x063c
     */
    r_debug_t *dp_derive_key(key_t *key) {
        /*
         * Stack addr: -0x00d0
         * size: 0x0080
         */
        struct_4 var_d0;
        /* Start: 0x000988 */ {
            /* Start: 0x00098c */ {
              This block derives the key based on the assembly of r_debug.r_brk.

              Frida hooks this function such as the regular "ret" is transformed by a trampoline
            } /* End: 0x000990 */
        } /* End: 0x0009a4 */
    }""")

def test_anonymous_enum():
    libdexprotector = lief.dwarf.load(get_sample("private/DWARF/binaryninja/libdexprotector.so.dwarf"))
    r_debug = libdexprotector.find_type("r_debug_t")

    assert r_debug.to_decl() == dedent("""\
    struct r_debug_t {
        int r_version;
        char __padding1__[4];
        struct link_map *r_map;
        Elf64_Addr r_brk;
        enum {
            RT_CONSISTENT = 0U,
            RT_ADD = 1U,
            RT_DELETE = 2U
        } r_state;
        char __padding4__[4];
        Elf64_Addr r_ldbase;
    }""")
