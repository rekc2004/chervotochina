//! `Debug` без содержимого для типов, которые несут вставленные тексты, токены, приглашения,
//! пути и имена (команды, намерения, строки форм). Печатается только имя типа и, у перечислений,
//! номер варианта. В программе ничего не печатается и не пишется в журнал; это страховка на
//! случай отладочного вывода и сообщений об ошибках тестов.

/// Перечисление: `Имя(Discriminant(n))`.
macro_rules! redacted_debug_enum {
    ($($t:ty),+ $(,)?) => {$(
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({:?})", stringify!($t), std::mem::discriminant(self))
            }
        }
    )+};
}

/// Структура: `Имя(..)`.
macro_rules! redacted_debug_struct {
    ($($t:ty),+ $(,)?) => {$(
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($t), "(..)"))
            }
        }
    )+};
}

pub(crate) use redacted_debug_enum;
pub(crate) use redacted_debug_struct;
