//! Names, signatures and limits of the Secret Service subset (spec 17a, section 3).

/// Well-known bus name of the Secret Service.
pub(super) const BUS_NAME: &str = "org.freedesktop.secrets";
/// Object path of the service object.
pub(super) const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub(super) const IFACE_SERVICE: &str = "org.freedesktop.Secret.Service";
pub(super) const IFACE_COLLECTION: &str = "org.freedesktop.Secret.Collection";
pub(super) const IFACE_ITEM: &str = "org.freedesktop.Secret.Item";
pub(super) const IFACE_PROPERTIES: &str = "org.freedesktop.DBus.Properties";

pub(super) const M_OPEN_SESSION: &str = "OpenSession";
pub(super) const M_SEARCH_ITEMS: &str = "SearchItems";
pub(super) const M_READ_ALIAS: &str = "ReadAlias";
pub(super) const M_PROP_GET: &str = "Get";
pub(super) const M_CREATE_ITEM: &str = "CreateItem";
pub(super) const M_GET_SECRET: &str = "GetSecret";
pub(super) const M_SET_SECRET: &str = "SetSecret";
pub(super) const M_DELETE: &str = "Delete";
pub(super) const M_DISMISS: &str = "Dismiss";
pub(super) const IFACE_PROMPT: &str = "org.freedesktop.Secret.Prompt";

/// Session algorithm (spec D1).
pub(super) const ALGO_PLAIN: &str = "plain";
/// Alias of the default collection.
pub(super) const ALIAS_DEFAULT: &str = "default";
/// Property of the collection interface.
pub(super) const PROP_LOCKED: &str = "Locked";
/// Full property keys of `CreateItem` (short names are wrong).
pub(super) const PROP_ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
pub(super) const PROP_ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

/// Attribute schema of the old client (spec D4): exactly these two keys.
pub(super) const ATTR_SERVICE: &str = "service";
pub(super) const ATTR_USERNAME: &str = "username";
/// Label prefix: `keyring:{account}@{service}`.
pub(super) const LABEL_PREFIX: &str = "keyring:";
pub(super) const CONTENT_TYPE: &str = "application/octet-stream";

/// Object path meaning "nothing / no prompt needed".
pub(super) const NO_OBJECT: &str = "/";

/// Error names (spec section 3).
pub(super) const ERR_IS_LOCKED: &str = "org.freedesktop.Secret.Error.IsLocked";
pub(super) const ERR_NO_SESSION: &str = "org.freedesktop.Secret.Error.NoSession";
pub(super) const ERR_NO_SUCH_OBJECT: &str = "org.freedesktop.Secret.Error.NoSuchObject";

/// Body signatures (D-Bus wire strings). The Secret struct is a single argument.
/// The "in" strings are checked by the fake service in the tests; the "out" strings by the client.
#[cfg(test)]
pub(super) const SIG_OPEN_SESSION_IN: &str = "sv";
pub(super) const SIG_OPEN_SESSION_OUT: &str = "vo";
#[cfg(test)]
pub(super) const SIG_SEARCH_IN: &str = "a{ss}";
pub(super) const SIG_SEARCH_OUT: &str = "aoao";
#[cfg(test)]
pub(super) const SIG_READ_ALIAS_IN: &str = "s";
pub(super) const SIG_OBJECT: &str = "o";
#[cfg(test)]
pub(super) const SIG_PROP_GET_IN: &str = "ss";
pub(super) const SIG_VARIANT: &str = "v";
#[cfg(test)]
pub(super) const SIG_CREATE_ITEM_IN: &str = "a{sv}(oayays)b";
pub(super) const SIG_CREATE_ITEM_OUT: &str = "oo";
pub(super) const SIG_SECRET: &str = "(oayays)";
pub(super) const SIG_EMPTY: &str = "";

/// Largest accepted secret, bytes (our records are at most 129 bytes).
pub(crate) const MAX_SECRET_LEN: usize = 4096;
/// Capacity of the job queue.
pub(super) const QUEUE: usize = 8;
