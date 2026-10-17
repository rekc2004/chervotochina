//! Связь с движком соединений: живое соединение пары, удержание, права и события.
//! Свойства `Links` вынесены в трейт, чтобы тесты могли подставить свою реализацию.

use chervo_connect::{ConnHold, Engine, EngineEvents};
use chervo_friends::{FriendState, Permission};
use chervo_identity::{ListKeyStore, PairId, SecretStore};
use chervo_transport::{Connection, ManagedTransport};

pub trait Links: Send + Sync + 'static {
    type Conn: Connection + Clone + 'static;
    fn connection(&self, pair: &PairId) -> Option<Self::Conn>;
    fn hold(&self, pair: &PairId) -> Option<ConnHold>;
    /// `None`: пара не `Active` (удалена, заблокирована, отозвана).
    fn permission(&self, pair: &PairId) -> Option<Permission>;
    fn subscribe(&self) -> EngineEvents;
}

impl<T, S> Links for Engine<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone + 'static,
    S: SecretStore + ListKeyStore + 'static,
{
    type Conn = T::Conn;

    fn connection(&self, pair: &PairId) -> Option<T::Conn> {
        Engine::connection(self, pair)
    }

    fn hold(&self, pair: &PairId) -> Option<ConnHold> {
        Engine::hold(self, pair)
    }

    fn permission(&self, pair: &PairId) -> Option<Permission> {
        self.read_book(|b| {
            b.get(pair)
                .filter(|f| f.state == FriendState::Active)
                .map(|f| f.permission)
        })
    }

    fn subscribe(&self) -> EngineEvents {
        Engine::subscribe(self)
    }
}
