use lief_ffi as ffi;

use crate::common::FromFFI;
use super::Type;

use std::marker::PhantomData;
use crate::common::into_optional;

pub trait Parameter {
    #[doc(hidden)]
    fn get_base(&self) -> &ffi::DWARF_Parameter;

    /// The name of the parameter
    fn name(&self) -> String {
        self.get_base().name().to_string()
    }

    /// Return the type of the parameter
    fn get_type(&self) -> Option<Type> {
        into_optional(self.get_base().get_type())
    }
}

pub enum Parameters<'a> {
    Formal(Formal<'a>),
    TemplateValue(TemplateValue<'a>),
    TemplateType(TemplateType<'a>),
}

impl FromFFI<ffi::DWARF_Parameter> for Parameters<'_> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::DWARF_Parameter>) -> Self {
        unsafe {
            let param_ref = ffi_entry.as_ref().unwrap();

            if ffi::DWARF_parameters_Formal::classof(param_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Parameter>;
                    type To = cxx::UniquePtr<ffi::DWARF_parameters_Formal>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Parameters::Formal(Formal::from_ffi(raw))
            } else if ffi::DWARF_parameters_TemplateValue::classof(param_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Parameter>;
                    type To = cxx::UniquePtr<ffi::DWARF_parameters_TemplateValue>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Parameters::TemplateValue(TemplateValue::from_ffi(raw))
            } else if ffi::DWARF_parameters_TemplateType::classof(param_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::DWARF_Parameter>;
                    type To = cxx::UniquePtr<ffi::DWARF_parameters_TemplateType>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                Parameters::TemplateType(TemplateType::from_ffi(raw))
            } else {
                panic!("Unknown Parameter");
            }
        }
    }
}


impl Parameter for Parameters<'_> {
    fn get_base(&self) -> &ffi::DWARF_Parameter {
        match &self {
            Parameters::Formal(p) => {
                p.get_base()
            }
            Parameters::TemplateValue(p) => {
                p.get_base()
            }
            Parameters::TemplateType(p) => {
                p.get_base()
            }
        }
    }
}

pub struct Formal<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_parameters_Formal>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_parameters_Formal> for Formal<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_parameters_Formal>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Parameter for Formal<'_> {
    fn get_base(&self) -> &ffi::DWARF_Parameter {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

pub struct TemplateValue<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_parameters_TemplateValue>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_parameters_TemplateValue> for TemplateValue<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_parameters_TemplateValue>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Parameter for TemplateValue<'_> {
    fn get_base(&self) -> &ffi::DWARF_Parameter {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

pub struct TemplateType<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_parameters_TemplateType>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_parameters_TemplateType> for TemplateType<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_parameters_TemplateType>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Parameter for TemplateType<'_> {
    fn get_base(&self) -> &ffi::DWARF_Parameter {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
