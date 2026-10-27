//! Мелкие функции показа: размеры и проценты (целочисленная арифметика, без чисел с плавающей
//! точкой).

/// «512 Б», «1,5 ГБ»: основание 1024, одна цифра после запятой (как в текстах приёма).
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut whole = bytes;
    let mut tenth = 0;
    let mut i = 0;
    while whole >= 1024 && i + 1 < UNITS.len() {
        tenth = (whole % 1024) * 10 / 1024;
        whole /= 1024;
        i += 1;
    }
    let unit = UNITS.get(i).copied().unwrap_or("ТБ");
    if i == 0 {
        format!("{bytes} {unit}")
    } else {
        format!("{whole},{tenth} {unit}")
    }
}

/// Целые проценты; пустой итог даёт 0.
pub fn percent(done: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    let p = u128::from(done.min(total)) * 100 / u128::from(total);
    u64::try_from(p).unwrap_or(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(human_size(0), "0 Б");
        assert_eq!(human_size(512), "512 Б");
        assert_eq!(human_size(1536), "1,5 КБ");
        assert_eq!(human_size(3 * 1024 * 1024), "3,0 МБ");
        assert!(human_size(u64::MAX).ends_with("ТБ"));
    }

    #[test]
    fn percents() {
        assert_eq!(percent(0, 0), 0);
        assert_eq!(percent(50, 200), 25);
        assert_eq!(percent(300, 200), 100);
    }
}
