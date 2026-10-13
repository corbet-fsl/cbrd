//! Room ordering and presence need a current anonymous pass; without one nothing
//! is sent and nothing is invented.
use cbrd::{Board, RoomOrdering, clnk};
use ctnd::{Error, Link, OrderRequest};

struct Offline;
impl clnk::Transport for Offline {
    async fn post(&self, _: &str, _: Vec<u8>) -> Result<Vec<u8>, clnk::ErrorCode> {
        Err(clnk::ErrorCode::Transport)
    }
}
struct Time;
impl clnk::Clock for Time {
    fn now(&self) -> Result<u64, cgth::cmmr::Error> {
        Ok(1_900_000_000_000)
    }
}
fn board() -> Board<Offline, clnk::AnonymousRooms<Offline>> {
    Board::new(
        "garden".into(),
        clnk::Link::at(
            Offline,
            "garden".into(),
            "https://forum.example.test".into(),
            Time,
        )
        .unwrap()
        .with_anonymous_rooms(Offline),
    )
    .unwrap()
}

#[tokio::test]
async fn without_a_room_pass_neither_presence_nor_ordering_is_sent() {
    let board = board();
    assert_eq!(
        board.here_now([1; 16], [2; 16]).await.err(),
        Some(clnk::ErrorCode::ResetRequired)
    );
    let request = OrderRequest {
        room: [1; 16],
        ordering: [3; 16],
        expected: 0,
        encrypted_commit: vec![1, 2, 3],
        companion: vec![],
    };
    assert_eq!(
        RoomOrdering::new(&board).order(&request).await.err(),
        Some(Error::Unavailable)
    );
}

struct Never;
impl cbrd::Pause for Never {
    fn pause(&mut self) -> ctnd::PortFuture<'_, ()> {
        Box::pin(async { panic!("no pass means no second read") })
    }
}

#[tokio::test]
async fn without_a_room_pass_the_context_feed_reads_nothing() {
    use cthr::ContextFeed;
    let board = board();
    let mut feed = cbrd::RoomFeed::new(&board, [1; 16], [3; 16], 1, Never);
    assert_eq!(feed.context_commit(7).await.err(), Some(Error::Unavailable));
}
