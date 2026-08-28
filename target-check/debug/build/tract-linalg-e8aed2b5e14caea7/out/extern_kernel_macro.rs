
    macro_rules! extern_kernel {
        (fn $name: ident($($par_name:ident : $par_type: ty ),*) -> $rv: ty) => {
            paste! {
                extern "C" { pub fn [<$name _ 0_21_10>]($(par_name: $par_type),*) -> $rv; }
                pub use [<$name _ 0_21_10>] as $name;
            }
        }
    }