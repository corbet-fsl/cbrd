#![cfg(not(target_arch = "wasm32"))]
//! The transport carries bytes through the real Axum controller. All admission,
//! currentness, signing, matching and storage below are the actual owner objects.
//! This is an in-process HTTP seam; separate TLS/browser execution is required.
mod forum;
use cbrd::{Board, Input, Verification, ViewLimits, clnk};
use cfrm::*;
use cgth::{cmmr, cswb, cthl};
use cmmr::{Clock, Store};
use ed25519_dalek::Signer as _;
use forum::*;
use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tower::ServiceExt;

#[derive(Clone)]
struct Time(Arc<AtomicU64>);
impl Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
#[derive(Clone)]
struct Random;
impl cswb::Tokens for Random {
    fn next(&self) -> Result<[u8; 16], cswb::Error> {
        use ckmg::Entropy;
        let mut bytes = [0; 16];
        ckmg::SystemEntropy
            .fill(&mut bytes)
            .map_err(|_| cswb::Error::Invalid)?;
        Ok(bytes)
    }
}
#[derive(Clone)]
struct Http(axum::Router);
impl clnk::Transport for Http {
    async fn post(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
        let response = self
            .0
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("Host", "forum.example.test")
                    .header("Origin", ORIGIN)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["access-control-allow-origin"], ORIGIN);
        axum::body::to_bytes(response.into_body(), 1_048_576)
            .await
            .map(|body| body.to_vec())
            .map_err(|_| ErrorCode::Transport)
    }
}
struct AnonymousHttp(Http);
impl clnk::Transport for AnonymousHttp {
    async fn post(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
        let call = cfrm::Call::decode(&body, 1_048_576).unwrap();
        assert_eq!(
            call.request.info().requirement,
            cfrm::Requirement::AnonymousRoomPass
        );
        assert!(call.request.possession().is_none());
        self.0.post(path, body).await
    }
}
fn board(app: &axum::Router, clock: Time) -> Board<Http> {
    Board::new(
        "garden".into(),
        clnk::Link::at(Http(app.clone()), "garden".into(), ORIGIN.into(), clock).unwrap(),
    )
    .unwrap()
    .with_search(ViewLimits {
        candidates: 3,
        publication_bytes: cpfl::MAX_PROFILE_BYTES * 4,
    })
    .unwrap()
}
async fn enter(board: &mut Board<Http>, fixture: &Fixture) {
    let challenge = board
        .connect(ChallengeInput {
            publication: fixture.publication.signed.clone(),
        })
        .await
        .unwrap();
    assert_eq!(board.status().connection, clnk::State::Connecting);
    board
        .enter(
            fixture.device.sign(challenge.message()).to_bytes().to_vec(),
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(board.status().connection, clnk::State::Present);
}
fn proof() -> Possession {
    Possession {
        session: vec![],
        request_nonce: vec![],
        signature: vec![],
    }
}
fn input<'a>(fixture: &'a Fixture, member: &'a str, revision: u64) -> Input<'a> {
    Input {
        member,
        minimum_revision: revision,
        bytes: &fixture.publication.signed,
    }
}
fn read_context<'a>(
    fixture: &'a Fixture,
    charter: &'a cchr::VerifiedCharter,
) -> cbrd::ReadContext<'a, cwst::backend::Memory> {
    cbrd::ReadContext {
        store: &fixture.store,
        binding: &fixture.binding,
        charter,
        policy: cbrd::ReadPolicy {
            admission_action: ACTION,
            maximum_snapshot_age: 300,
        },
        contact: &clean,
    }
}
fn search_request() -> Request {
    Request::Search(SearchInput {
        possession: proof(),
        cursor: None,
        page_size: 3,
    })
}
fn prepared(
    board: &Board<Http>,
    request: Request,
    fixture: &Fixture,
    nonce: u8,
) -> (clnk::Prepared, Vec<u8>) {
    let prepared = board.prepare(request, [nonce; 16]).unwrap();
    let signature = fixture.device.sign(prepared.message()).to_bytes().to_vec();
    (prepared, signature)
}

#[tokio::test]
async fn board_uses_real_forum_and_current_local_owner_checks() {
    let clock = Time(Arc::new(AtomicU64::new(2_000_000_000_000)));
    let now = clock.now().unwrap() / 1000;
    let issuer = issuer(now);
    let assurance = csrn::Assurance::new(
        cchr::Configuration {
            origin: "https://identity.example.test".into(),
            community: "garden".into(),
            key_ring: issuer.key_ring().to_cbor(),
            minimum_revision: 1,
            ring_revision: 0,
        },
        csrn::feed::Config {
            retry_entropy: 15,
            refresh_seconds: 30,
            poll_seconds: 1,
            request_seconds: 30,
            initial_backoff_seconds: 1,
            maximum_backoff_seconds: 10,
            maximum_staleness_seconds: 60,
        },
    )
    .unwrap();
    let storage: cvtl::Volatile<_> = cvtl::Volatile::memory(
        cmmr::Scope::new("garden", "boot").unwrap(),
        cmmr::Limits {
            records: 128,
            value_bytes: 262144,
            batch: 4,
            indexes_per_record: 4,
            page: 8,
            ttl_ms: 600000,
        },
        clock.clone(),
    )
    .unwrap();
    let throttle = cthl::Throttle::new(
        "garden",
        actions().into_iter().map(|action| {
            (
                action.name,
                cthl::Limit::new(100, Duration::from_secs(1)).unwrap(),
            )
        }),
        cthl::MemoryStore::new(NonZeroUsize::new(32).unwrap()),
    )
    .unwrap();
    let service = runtime::Service::new(
        assurance,
        runtime::Parts {
            storage: storage.clone(),
            clock: clock.clone(),
            tokens: Random,
            throttle,
        },
        runtime::Configuration {
            community: "garden".into(),
            incarnation: "boot".into(),
            admission_action: ACTION.into(),
            origins: vec![ORIGIN.into()],
            maximum_snapshot_age: 300,
            request_bytes: 1_048_576,
            presence: cswb::Limits {
                lease_ms: 60000,
                publication_bytes: cpfl::MAX_PROFILE_BYTES,
                ciphertext_bytes: cpfl::MAX_PROFILE_BYTES,
            },
            lookup: cgth::clkp::LookupLimits {
                candidates: 3,
                publication_bytes: cpfl::MAX_PROFILE_BYTES * 3,
            },
            room_epoch: runtime::RoomEpochConfiguration {
                epoch: 1,
                valid_from_ms: now * 1000,
                valid_until_ms: (now + 60) * 1000,
            },
            rooms: cgth::cmbl::Limits {
                connections: 4,
                relay_messages: 4,
                message_bytes: 1024,
                lifetime_ms: 10000,
                proof_bytes: cgth::cmbl::passes::MAX_PROOF_BYTES,
                operation_receipts: 16,
            },
        },
        clean,
    )
    .unwrap();
    let (handle, worker) = service.spawn(16, Duration::from_millis(10)).unwrap();
    let app = http::router_with(
        http::Limits {
            hosts: vec!["forum.example.test".into()],
            origins: vec![ORIGIN.into()],
            body_bytes: 1_048_576,
            concurrent: 4,
            anonymous_concurrent: 2,
            body_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            source: cfrm::bucket::Bucket {
                burst: 1_000,
                replenish: Duration::from_millis(1),
                keys: 16,
            },
            session: cfrm::bucket::Bucket {
                burst: 1_000,
                replenish: Duration::from_millis(1),
                keys: 16,
            },
        },
        handle.clone(),
    )
    .unwrap();
    let alice = Fixture::new("alice", 1, now).await;
    let bob = Fixture::new("bob", 1, now).await;
    let mut a = board(&app, clock.clone());
    let mut b = board(&app, clock.clone());
    assert!(
        a.connect(ChallengeInput {
            publication: alice.publication.signed.clone()
        })
        .await
        .is_err()
    );
    assert_eq!(a.status().connection, clnk::State::Unavailable);
    let fetch = handle.start_feed().await.unwrap();
    handle
        .complete_feed(
            fetch.id(),
            serde_json::to_vec(&feed(
                now,
                1,
                serde_json::json!({"members":[],"devices":[]}),
            ))
            .unwrap(),
            false,
        )
        .await
        .unwrap();
    let settings = a.settings().await.unwrap();
    assert_eq!(
        settings.minimum_client_version,
        crbk::FORUM_MINIMUM_CLIENT_VERSION
    );
    assert_eq!(
        (settings.heartbeat_ms, settings.lease_ms),
        (crbk::FORUM_HEARTBEAT_MS, crbk::FORUM_LEASE_MS)
    );
    assert_eq!(
        settings.room_passes_per_epoch,
        crbk::FORUM_ROOM_PASSES_PER_EPOCH
    );
    assert_eq!(settings.revision, 1);
    assert!(!settings.publication.is_empty());
    enter(&mut a, &alice).await;
    enter(&mut b, &bob).await;

    let mut charter = cchr::Charter::new(cchr::Configuration {
        origin: "https://identity.example.test".into(),
        community: "garden".into(),
        key_ring: issuer.key_ring().to_cbor(),
        minimum_revision: 1,
        ring_revision: 0,
    })
    .unwrap();
    charter
        .install(
            &serde_json::to_vec(&feed(
                now,
                1,
                serde_json::json!({"members":[],"devices":[]}),
            ))
            .unwrap(),
            now,
        )
        .unwrap();
    let current = charter.current(now).unwrap();
    let policy = current.admission_policy(ACTION, now, 300).unwrap();
    let verification = Verification {
        policy: &policy,
        signed_schema: current.publication(cchr::Kind::Schema).signed_bytes(),
    };
    let (request, signature) = prepared(&a, search_request(), &alice, 1);
    let pending = a.receive_search(request, signature).await.unwrap();
    let page = a
        .finish_search_committed(pending, &read_context(&alice, current))
        .unwrap();
    assert_eq!(page.pairs.len(), 1);
    assert_eq!(page.discovery().entries[0].member, "bob");
    assert_eq!(
        a.read_discovery_committed(&read_context(&alice, current))
            .unwrap()[0]
            .member,
        "bob"
    );
    assert!(page.pairs[0].decision().is_match());
    let (watch_request, watch_signature) = prepared(
        &a,
        Request::Watch(WatchInput {
            possession: proof(),
            cursor: page.watch.clone(),
        }),
        &alice,
        12,
    );
    let pending = a
        .receive_watch(watch_request, watch_signature)
        .await
        .unwrap();
    let watched = a
        .finish_watch_committed(pending, &read_context(&alice, current))
        .unwrap();
    assert_eq!(watched.pairs.len(), 1);
    assert_eq!(watched.discovery().entries[0].member, "bob");
    assert_ne!(watched.watch, page.watch);
    let aaron = Fixture::new("aaron", 1, now).await;
    let mut newcomer = board(&app, clock.clone());
    enter(&mut newcomer, &aaron).await;
    let (watch_request, watch_signature) = prepared(
        &a,
        Request::Watch(WatchInput {
            possession: proof(),
            cursor: watched.watch,
        }),
        &alice,
        13,
    );
    let pending = a
        .receive_watch(watch_request, watch_signature)
        .await
        .unwrap();
    let joined = a
        .finish_watch_committed(pending, &read_context(&alice, current))
        .unwrap();
    assert_eq!(
        joined
            .discovery()
            .entries
            .iter()
            .map(|entry| entry.member.as_str())
            .collect::<Vec<_>>(),
        ["aaron", "bob"]
    );
    let (departure, signature) = prepared(
        &newcomer,
        Request::Depart(DepartInput {
            possession: proof(),
        }),
        &aaron,
        14,
    );
    newcomer.execute(departure, signature).await.unwrap();
    let (watch_request, watch_signature) = prepared(
        &a,
        Request::Watch(WatchInput {
            possession: proof(),
            cursor: joined.watch,
        }),
        &alice,
        15,
    );
    let pending = a
        .receive_watch(watch_request, watch_signature)
        .await
        .unwrap();
    let left = a
        .finish_watch_committed(pending, &read_context(&alice, current))
        .unwrap();
    assert_eq!(
        left.discovery()
            .entries
            .iter()
            .map(|entry| entry.member.as_str())
            .collect::<Vec<_>>(),
        ["bob"]
    );
    drop(newcomer);
    assert_eq!(
        a.read_search(input(&alice, "alice", 1), &verification, &clean)
            .unwrap()
            .len(),
        1
    );

    let (request, signature) = prepared(
        &a,
        Request::Ciphertext(CiphertextInput {
            possession: proof(),
            owner: b"bob".to_vec(),
            revision: 1u64.to_be_bytes().to_vec(),
        }),
        &alice,
        2,
    );
    let pending = a.receive_ciphertext(request, signature).await.unwrap();
    assert_eq!(
        a.finish_ciphertext_committed(
            pending,
            input(&bob, "bob", 1),
            &read_context(&alice, current),
        )
        .unwrap(),
        bob.publication.ciphertext
    );
    a.remove("bob");
    assert!(
        a.read_search(input(&alice, "alice", 1), &verification, &clean)
            .unwrap()
            .is_empty()
    );
    let (request, signature) = prepared(&a, search_request(), &alice, 3);
    a.search(
        request,
        signature,
        input(&alice, "alice", 1),
        &verification,
        &clean,
    )
    .await
    .unwrap();

    // A response remains opaque across the await. A stale policy clock cannot
    // authorize disclosure, even when the network response itself was valid.
    let (request, signature) = prepared(&a, search_request(), &alice, 9);
    let pending = a.receive_search(request, signature).await.unwrap();
    clock.0.fetch_add(1000, Ordering::SeqCst);
    assert!(
        a.finish_search(pending, input(&alice, "alice", 1), &verification, &clean)
            .is_err()
    );
    let (request, signature) = prepared(&a, search_request(), &alice, 10);
    let pending = a.receive_search(request, signature).await.unwrap();
    let now = clock.now().unwrap() / 1000;
    let current = charter.current(now).unwrap();
    assert_eq!(
        a.finish_search_committed(pending, &read_context(&alice, current))
            .unwrap()
            .pairs
            .len(),
        1
    );
    assert!(
        a.read_discovery_committed(&read_context(&bob, current))
            .is_err()
    );
    assert!(
        a.read_discovery_committed(&read_context(&alice, current))
            .is_err()
    );
    let mut wrong_action = read_context(&alice, current);
    wrong_action.policy.admission_action = "different.admission";
    let (request, signature) = prepared(&a, search_request(), &alice, 16);
    let pending = a.receive_search(request, signature).await.unwrap();
    assert!(a.finish_search_committed(pending, &wrong_action).is_err());
    // A real locked Store cannot be substituted by cached publication bytes.
    let mut locked = Fixture::new("alice", 1, now).await;
    locked.store.lock_in_place();
    let (request, signature) = prepared(&a, search_request(), &alice, 17);
    let pending = a.receive_search(request, signature).await.unwrap();
    assert!(
        a.finish_search_committed(pending, &read_context(&locked, current))
            .is_err()
    );
    // Retain another opaque reply, then change the actual signed authority
    // before finishing. The newly revoked pair must never become a DTO.
    let (request, signature) = prepared(&a, search_request(), &alice, 11);
    let pending = a.receive_search(request, signature).await.unwrap();
    // Signed authority changes are observed locally before a remote refresh.
    let revoked = feed(now, 2, serde_json::json!({"members":["bob"],"devices":[]}));
    charter
        .install(&serde_json::to_vec(&revoked).unwrap(), now)
        .unwrap();
    let current = charter.current(now).unwrap();
    let policy = current.admission_policy(ACTION, now, 300).unwrap();
    let verification = Verification {
        policy: &policy,
        signed_schema: current.publication(cchr::Kind::Schema).signed_bytes(),
    };
    assert!(
        a.finish_search_committed(pending, &read_context(&alice, current))
            .is_err()
    );
    assert!(
        a.read_search(input(&alice, "alice", 1), &verification, &clean)
            .is_err()
    );
    clock.0.fetch_add(1000, Ordering::SeqCst);
    let poll = handle.next_feed().await.unwrap().unwrap();
    handle
        .complete_feed(
            poll.id(),
            serde_json::to_vec(&serde_json::json!({
                "changed": true, "revision": 2, "policy_epoch": 2
            }))
            .unwrap(),
            true,
        )
        .await
        .unwrap();
    let fetch = handle.next_feed().await.unwrap().unwrap();
    handle
        .complete_feed(fetch.id(), serde_json::to_vec(&revoked).unwrap(), false)
        .await
        .unwrap();
    let current = charter.current(now + 1).unwrap();
    let policy = current.admission_policy(ACTION, now + 1, 300).unwrap();
    let verification = Verification {
        policy: &policy,
        signed_schema: current.publication(cchr::Kind::Schema).signed_bytes(),
    };
    let (request, signature) = prepared(&a, search_request(), &alice, 4);
    assert!(
        a.search(
            request,
            signature,
            input(&alice, "alice", 1),
            &verification,
            &clean
        )
        .await
        .unwrap()
        .pairs
        .is_empty()
    );

    let replacement = Fixture::new("alice", 2, now).await;
    let (request, signature) = prepared(
        &a,
        Request::Replace(ReplaceInput {
            possession: proof(),
            expected_revision: vec![],
            publication: replacement.publication.signed.clone(),
            record_proof: vec![],
        }),
        &alice,
        5,
    );
    a.execute(request, signature).await.unwrap();
    assert!(
        a.read_search(input(&alice, "alice", 1), &verification, &clean)
            .is_err()
    );
    let before = storage.get("swb_alice").await.unwrap().unwrap().revision;
    let (request, signature) = prepared(
        &a,
        Request::Heartbeat(HeartbeatInput {
            possession: proof(),
            expected_revision: vec![],
        }),
        &replacement,
        6,
    );
    a.execute(request, signature).await.unwrap();
    assert_ne!(
        storage.get("swb_alice").await.unwrap().unwrap().revision,
        before
    );
    let (request, signature) = prepared(
        &a,
        Request::Depart(DepartInput {
            possession: proof(),
        }),
        &replacement,
        7,
    );
    a.execute(request, signature).await.unwrap();
    assert_eq!(a.status().connection, clnk::State::Disconnected);
    assert!(storage.get("swb_alice").await.unwrap().is_none());
    let (request, signature) = prepared(
        &b,
        Request::Heartbeat(HeartbeatInput {
            possession: proof(),
            expected_revision: vec![],
        }),
        &bob,
        8,
    );
    assert!(b.execute(request, signature).await.is_err());
    assert_eq!(b.status().connection, clnk::State::Unavailable);
    // The same actual service now exercises Link's private original room pass,
    // with a distinct anonymous byte transport and no device/session on it.
    let rooms = clnk::Link::at(
        Http(app.clone()),
        "garden".into(),
        ORIGIN.into(),
        clock.clone(),
    )
    .unwrap()
    .with_anonymous_rooms(AnonymousHttp(Http(app.clone())));
    let mut rooms = Board::new("garden".into(), rooms).unwrap();
    let challenge = rooms
        .connect(ChallengeInput {
            publication: replacement.publication.signed.clone(),
        })
        .await
        .unwrap();
    rooms
        .enter(
            replacement
                .device
                .sign(challenge.message())
                .to_bytes()
                .to_vec(),
            vec![],
        )
        .await
        .unwrap();
    let request = rooms.prepare_room_epoch([31; 16]).unwrap();
    let signature = replacement
        .device
        .sign(request.message())
        .to_bytes()
        .to_vec();
    rooms.receive_room_epoch(request, signature).await.unwrap();
    let room = [71; 16];
    let request = rooms.prepare_room_pass(room, [32; 16], [33; 16]).unwrap();
    assert!(matches!(
        rooms.prepare_room_pass([72; 16], [32; 16], [34; 16]),
        Err(ErrorCode::InvalidRequest)
    ));
    let signature = replacement
        .device
        .sign(request.message())
        .to_bytes()
        .to_vec();
    let connection = rooms.receive_room_pass(request, signature).await.unwrap();
    assert_eq!(rooms.room_connection(room).unwrap(), connection);
    let resumed = rooms
        .execute_room(clnk::cmbl::Request {
            room,
            operation: [35; 16],
            action: clnk::cmbl::Action::Resume { connection },
        })
        .await
        .unwrap();
    assert_eq!(resumed.counter, 0);
    let ordered = rooms
        .execute_room(clnk::cmbl::Request {
            room,
            operation: [36; 16],
            action: clnk::cmbl::Action::Order {
                expected: 0,
                ciphertext: vec![1, 2, 3],
            },
        })
        .await
        .unwrap();
    assert_eq!(ordered.ordering, resumed.ordering);
    assert_eq!(ordered.counter, 1);
    let read = rooms
        .execute_room(clnk::cmbl::Request {
            room,
            operation: [37; 16],
            action: clnk::cmbl::Action::Read { after: 0 },
        })
        .await
        .unwrap();
    assert_eq!(read.frames[0].ciphertext, [1, 2, 3]);
    rooms.close_rooms();
    assert_eq!(rooms.room_connection(room), Err(ErrorCode::ResetRequired));
    drop(rooms);
    drop(a);
    drop(b);
    drop(app);
    drop(handle);
    worker.await.unwrap();
    assert_eq!(storage.state(), cmmr::State::Closed);
}
