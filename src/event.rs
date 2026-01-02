//! Terminal event handling for the TUI.
//!
//! This module provides an event loop that handles keyboard input, terminal resize
//! events, and periodic tick events for UI updates. Events are processed in a
//! background thread and delivered through a channel.

use color_eyre::Result;
use crossterm::event::{self, Event as CrosstermEvent, KeyEvent};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Terminal events that drive the application.
#[derive(Debug)]
pub enum Event {
    /// Keyboard input event.
    Key(KeyEvent),
    /// Terminal window resize event.
    Resize(u16, u16),
    /// Periodic tick for UI updates.
    Tick,
}

/// Handles terminal events in a background thread.
///
/// Spawns a thread that polls for terminal events and sends them through
/// a channel. Also generates periodic tick events for time-based updates.
pub struct EventHandler {
    receiver: mpsc::Receiver<Event>,
    #[allow(dead_code)]
    handler: thread::JoinHandle<()>,
}

impl EventHandler {
    /// Creates a new event handler with the specified tick rate.
    ///
    /// # Arguments
    ///
    /// * `tick_rate_ms` - Milliseconds between tick events
    pub fn new(tick_rate_ms: u64) -> Self {
        let tick_rate = Duration::from_millis(tick_rate_ms);
        let (sender, receiver) = mpsc::channel();

        let handler = thread::spawn(move || {
            let mut last_tick = Instant::now();
            loop {
                let timeout = tick_rate
                    .checked_sub(last_tick.elapsed())
                    .unwrap_or(Duration::ZERO);

                if event::poll(timeout).unwrap_or(false) {
                    if let Ok(evt) = event::read() {
                        match evt {
                            CrosstermEvent::Key(key) => {
                                if sender.send(Event::Key(key)).is_err() {
                                    return;
                                }
                            }
                            CrosstermEvent::Resize(w, h) => {
                                if sender.send(Event::Resize(w, h)).is_err() {
                                    return;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                if last_tick.elapsed() >= tick_rate {
                    if sender.send(Event::Tick).is_err() {
                        return;
                    }
                    last_tick = Instant::now();
                }
            }
        });

        Self { receiver, handler }
    }

    /// Blocks until the next event is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the event channel is disconnected.
    pub fn next(&self) -> Result<Event> {
        Ok(self.receiver.recv()?)
    }
}
