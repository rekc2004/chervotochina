//! Тексты для пользователя (по-русски, без подстановок). Тексты роутера сюда не попадают.

use chervo_addr::MapStatus;

pub const NEED_PERMANENT_TEXT: &str = "Роутер умеет открывать порт только бессрочно. Разрешить? Порт закрывается при выходе из программы; если программа аварийно завершится, порт останется открытым до её следующего запуска в этой сети.";

pub const ENABLE_ON_ROUTER_TEXT: &str = "Открывать порт автоматически на этом роутере? Включайте только в своей сети: в чужой сети (гостиница, офис) устройство, выдающее себя за роутер, может подменить адрес.";

pub const AMBIGUOUS_TEXT: &str = "В сети отвечают несколько устройств, похожих на роутер. Порт автоматически не открыт: настройте проброс вручную.";

pub const REFUSED_TEXT: &str =
    "Роутер отказался открывать порт. Порт автоматически не открыт: настройте проброс вручную.";

pub const NOT_HOME_TEXT: &str = "Это не тот роутер, которому вы разрешили открывать порт. В этой сети порт автоматически не открывается.";

pub const DOUBLE_NAT_UPNP_TEXT: &str = "Внешний адрес роутера частный: роутер стоит за другим роутером. Открытый порт снаружи недоступен, автоматический проброс не поможет.";

pub const CGNAT_UPNP_TEXT: &str = "Внешний адрес роутера из диапазона провайдерского NAT (CGNAT). Открытый порт снаружи недоступен, автоматический проброс не поможет.";

const OFF_TEXT: &str = "Автоматическое открытие порта выключено.";
const NO_GATEWAY_TEXT: &str = "Роутер с поддержкой автоматического проброса в сети не найден.";
const WAN_UNKNOWN_TEXT: &str =
    "Роутер не сообщил свой внешний адрес. Порт автоматически не открыт.";
const FAILED_TEXT: &str = "Не удалось открыть порт на роутере. Попробуем позже.";
const MAPPED_TEXT: &str = "Порт открыт на роутере.";
const MAPPED_PERMANENT_TEXT: &str =
    "Порт открыт на роутере бессрочно; он закроется при выходе из программы.";

/// Текст состояния проброса. Для новых состояний (перечисление открыто) общий текст сбоя.
pub fn status_text(s: MapStatus) -> &'static str {
    match s {
        MapStatus::Off => OFF_TEXT,
        MapStatus::NotHomeNetwork => NOT_HOME_TEXT,
        MapStatus::NoGateway => NO_GATEWAY_TEXT,
        MapStatus::Ambiguous => AMBIGUOUS_TEXT,
        MapStatus::WanUnknown => WAN_UNKNOWN_TEXT,
        MapStatus::BehindCgnat => CGNAT_UPNP_TEXT,
        MapStatus::DoubleNat => DOUBLE_NAT_UPNP_TEXT,
        MapStatus::NeedPermanentConsent => NEED_PERMANENT_TEXT,
        MapStatus::Refused(_) => REFUSED_TEXT,
        MapStatus::Failed => FAILED_TEXT,
        MapStatus::Mapped => MAPPED_TEXT,
        MapStatus::MappedPermanent => MAPPED_PERMANENT_TEXT,
        _ => FAILED_TEXT,
    }
}
