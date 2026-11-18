//! Тексты для пользователя (по-русски, без подстановок). Тексты роутера сюда не попадают.

use chervo_addr::MapStatus;

pub const NEED_PERMANENT_TEXT: &str = "Роутер может открыть порт только «навсегда». Программа закроет его при выходе. Если программа аварийно завершится, порт останется открытым до её следующего запуска в этой сети. Разрешить?";

pub const ENABLE_ON_ROUTER_TEXT: &str = "Разрешить программе настроить этот роутер, чтобы друзья могли к вам подключаться? Отвечайте «Да» только дома: в гостинице или офисе так делать нельзя, чужое устройство может выдать себя за роутер.";

pub const AMBIGUOUS_TEXT: &str = "В сети отвечают несколько устройств, похожих на роутер, и программа не стала выбирать сама. Можно настроить роутер вручную или попросить друга, у которого порт открыт, подключиться к вам.";

pub const REFUSED_TEXT: &str = "Роутер отказался открывать порт. Можно настроить роутер вручную или попросить друга, у которого порт открыт, подключиться к вам.";

pub const NOT_HOME_TEXT: &str = "Это не тот роутер, которому вы разрешили открывать порт. В этой сети порт автоматически не открывается.";

pub const DOUBLE_NAT_UPNP_TEXT: &str =
    "Ваш роутер стоит за роутером провайдера: открывать порт бесполезно.";

pub const CGNAT_UPNP_TEXT: &str =
    "Ваш роутер стоит за роутером провайдера: открывать порт бесполезно.";

const OFF_TEXT: &str = "Автоматическое открытие порта выключено.";
const NO_GATEWAY_TEXT: &str = "Роутер не отвечает на просьбу открыть порт. Возможно, в его настройках выключено автоматическое открытие портов.";
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
