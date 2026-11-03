use futures_util::StreamExt as _;

#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
enum Streams {
    Requests,
    Timer,
}

#[derive(Debug)]
enum Action {
    Set(std::time::Duration),
    Clear,
}

pub struct Timeout {
    req_w: tokio::sync::mpsc::UnboundedSender<Action>,
}

impl Timeout {
    pub fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let (req_w, req_r) = tokio::sync::mpsc::unbounded_channel();
        let (timer_w, timer_r) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            enum Event {
                Request(Action),
                Timer,
            }
            let mut stream = tokio_stream::StreamMap::new();
            stream.insert(
                Streams::Requests,
                tokio_stream::wrappers::UnboundedReceiverStream::new(req_r)
                    .map(Event::Request)
                    .boxed(),
            );
            while let Some(event) = stream.next().await {
                match event {
                    (_, Event::Request(Action::Set(dur))) => {
                        stream.insert(
                            Streams::Timer,
                            futures_util::stream::once(
                                sleep_including_suspend(dur),
                            )
                            .map(|()| Event::Timer)
                            .boxed(),
                        );
                    }
                    (_, Event::Request(Action::Clear)) => {
                        stream.remove(&Streams::Timer);
                    }
                    (_, Event::Timer) => {
                        timer_w.send(()).unwrap();
                    }
                }
            }
        });
        (Self { req_w }, timer_r)
    }

    pub fn set(&self, dur: std::time::Duration) {
        self.req_w.send(Action::Set(dur)).unwrap();
    }

    pub fn clear(&self) {
        self.req_w.send(Action::Clear).unwrap();
    }
}

// tokio's timers (like std::time::Instant) don't advance while the system is
// suspended, so a lock timeout would be extended by however long the system
// was asleep. measure the deadline against a clock which keeps running
// during suspend instead, and check it regularly so that the timer fires
// soon after resuming.
async fn sleep_including_suspend(dur: std::time::Duration) {
    let deadline = clock_including_suspend().saturating_add(dur);
    while let Some(remaining) =
        deadline.checked_sub(clock_including_suspend())
    {
        if remaining.is_zero() {
            break;
        }
        tokio::time::sleep(remaining.min(std::time::Duration::from_secs(1)))
            .await;
    }
}

fn clock_including_suspend() -> std::time::Duration {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let clock = rustix::time::ClockId::Boottime;
    // CLOCK_MONOTONIC includes time spent asleep on macos
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let clock = rustix::time::ClockId::Monotonic;
    let ts = rustix::time::clock_gettime(clock);
    std::time::Duration::new(
        u64::try_from(ts.tv_sec).unwrap_or(0),
        u32::try_from(ts.tv_nsec).unwrap_or(0),
    )
}

#[cfg(test)]
mod test {
    #[tokio::test]
    async fn test_sleep_including_suspend() {
        let dur = std::time::Duration::from_millis(1500);
        let start = std::time::Instant::now();
        super::sleep_including_suspend(dur).await;
        let elapsed = start.elapsed();
        assert!(elapsed >= dur, "{elapsed:?}");
        assert!(elapsed < dur + std::time::Duration::from_millis(500));
    }
}
