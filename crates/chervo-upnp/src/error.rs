//! Ошибки разборщиков: перечисления без текста (текст роутера в ошибки не попадает).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanError {
    /// Тело длиннее `BODY_MAX`.
    TooLarge,
    /// Управляющий байт (кроме табуляции, LF и CR).
    Control,
    /// `<!` (DTD, комментарий, CDATA) или недопустимая инструкция `<?`.
    Markup,
    /// `&` не начинает одну из пяти разрешённых сущностей.
    Entity,
    /// Нарушение синтаксиса подмножества.
    Syntax,
    /// Закрывающий тег не совпал с открытым.
    Mismatch,
    Depth,
    Elements,
    NameTooLong,
    /// Значение не прошло проверку (не ASCII, длина).
    Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UrlError {
    Scheme,
    Authority,
    Host,
    Port,
    HostMismatch,
    NoPath,
    TooLong,
    /// Символ вне разрешённого набора.
    PathChar,
    /// Неверная или запрещённая процентная последовательность.
    Percent,
    /// Сегмент `.` или `..` (в том числе в виде `%2e`).
    DotSegment,
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SsdpError {
    Oversize,
    NonAscii,
    BadStatus,
    TooManyHeaders,
    ObsFold,
    BadHeader,
    MissingLocation,
    DuplicateLocation,
    MissingSt,
    DuplicateSt,
    StMismatch,
    /// Источник не из частной сети (или loopback вне тестовой политики).
    BadSource,
    /// Ответил сам хост.
    SelfSource,
    /// Данные после пустой строки.
    Trailing,
    Location(UrlError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpError {
    HeadTooLarge,
    /// Конец данных до конца заголовков.
    Truncated,
    NonAscii,
    BadStatusLine,
    TooManyHeaders,
    ObsFold,
    BadHeader,
    /// Любой `Transfer-Encoding`.
    Chunked,
    BadContentLength,
    TooLarge,
    ShortBody,
    Redirect,
    Status(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DescError {
    Scan(ScanError),
    Url(UrlError),
    NotRoot,
    NotIgd,
    MissingUdn,
    BadUdn,
    Duplicate,
    /// Лист ожидался, а у элемента есть дочерние, либо вложенный `service`.
    Malformed,
    MissingControl,
    NoService,
}

impl From<ScanError> for DescError {
    fn from(e: ScanError) -> Self {
        DescError::Scan(e)
    }
}

impl From<UrlError> for DescError {
    fn from(e: UrlError) -> Self {
        DescError::Url(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SoapError {
    Scan(ScanError),
    /// Корень не `Envelope`.
    WrongRoot,
    /// Нет элемента `<Действие>Response`.
    NoResponse,
    Duplicate,
    Missing,
    /// Поле не прошло проверку формата или предела.
    BadValue,
    /// Ожидаемое поле не лист.
    Malformed,
}

impl From<ScanError> for SoapError {
    fn from(e: ScanError) -> Self {
        SoapError::Scan(e)
    }
}

/// Ошибка публичного API. Без текста роутера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpnpError {
    NoGateway,
    Ambiguous,
    Timeout,
    Io,
    Protocol,
    Rejected,
}

/// Ошибка сетевого слоя (`net.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetError {
    Timeout,
    Io,
    /// Принято больше, чем голова и тело вместе допускают.
    TooLarge,
}

impl From<NetError> for UpnpError {
    fn from(e: NetError) -> Self {
        match e {
            NetError::Timeout => UpnpError::Timeout,
            NetError::Io => UpnpError::Io,
            NetError::TooLarge => UpnpError::Protocol,
        }
    }
}
