use {
    noirc_abi::{Abi, AbiType, AbiVisibility, Sign},
    std::fmt::{Display, Formatter, Result},
};

pub struct PrintAbi<'a>(pub &'a Abi);

pub struct PrintType<'a>(pub &'a AbiType);

impl Display for PrintAbi<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "(")?;
        for (i, param) in self.0.parameters.iter().enumerate() {
            print!("{}: ", param.name);
            match param.visibility {
                AbiVisibility::Public => print!("pub "),
                AbiVisibility::Private => {}
                AbiVisibility::DataBus => print!("data_bus "),
            }
            print!("{}", PrintType(&param.typ));
            if i < self.0.parameters.len() - 1 {
                print!(", ");
            }
        }
        write!(f, ")")
    }
}

impl Display for PrintType<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self.0 {
            AbiType::Field => write!(f, "Field"),
            AbiType::Boolean => write!(f, "bool"),
            AbiType::Integer { sign, width } => match sign {
                Sign::Signed => write!(f, "i{width}"),
                Sign::Unsigned => write!(f, "u{width}"),
            },
            AbiType::String { length } => write!(f, "str<{length}>"),
            AbiType::Array { length, typ } => write!(f, "[{}; {length}]", PrintType(typ)),
            AbiType::Tuple { fields } => {
                write!(f, "(")?;
                for (idx, typ) in fields.iter().enumerate() {
                    write!(f, "{}", PrintType(typ))?;
                    if idx < fields.len() - 1 {
                        write!(f, ", ")?;
                    }
                }
                write!(f, ")")
            }
            AbiType::Struct { path, fields } => {
                write!(f, "{path} {{")?;
                for (idx, (name, typ)) in fields.iter().enumerate() {
                    write!(f, "{}: {}", name, PrintType(typ))?;
                    if idx < fields.len() - 1 {
                        write!(f, ", ")?;
                    }
                }
                write!(f, "}}")
            }
        }
    }
}
