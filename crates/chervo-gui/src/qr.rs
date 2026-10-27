//! QR-код для показа токена приглашения (только кодирование; ничего не считывается). Экран
//! «Добавить друга» подключает его на следующем шаге этапа 18.

/// Матрица модулей: `true` тёмный. `None`, если текст не помещается в QR.
pub struct QrMatrix {
    pub width: usize,
    pub dark: Vec<bool>,
}

pub fn encode(text: &str) -> Option<QrMatrix> {
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let width = code.width();
    let dark = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();
    Some(QrMatrix { width, dark })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_square_matrix() {
        let m = encode("CHERVO1-test").expect("fits");
        assert_eq!(m.dark.len(), m.width * m.width);
    }

    #[test]
    fn too_long_text_is_none() {
        assert!(encode(&"x".repeat(10_000)).is_none());
    }
}
