use chervo_friends::{FriendStore, FriendsError, Permission, UnavailableFriendStore};

#[test]
fn default_permission_is_ask() {
    assert_eq!(Permission::default(), Permission::Ask);
    assert!(matches!(
        UnavailableFriendStore.list(),
        Err(FriendsError::NotImplemented)
    ));
}
