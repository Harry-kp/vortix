//! Bounded, redacted `OpenVPN` management authentication protocol.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use base64::engine::{general_purpose::STANDARD as BASE64, Engine as _};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::vortix_core::privileged::OpenVpnChallengeKind;

const MAX_MANAGEMENT_EVENT_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ManagementAuthError {
    #[error("OpenVPN management I/O failed")]
    Io,
    #[error("OpenVPN management socket closed before connection was authenticated")]
    Closed,
    #[error("OpenVPN rejected authentication")]
    AuthenticationRejected,
    #[error("OpenVPN requested an unsupported interactive challenge")]
    UnsupportedChallenge,
    #[error("OpenVPN exited during authentication")]
    DaemonExited,
    #[error("OpenVPN management event exceeded its protocol bound")]
    InvalidEvent,
    #[error("OpenVPN authentication timed out")]
    Timeout,
    #[error("OpenVPN credentials are invalid for the management line protocol")]
    InvalidCredentials,
}

pub(crate) fn authenticate(
    stream: UnixStream,
    username: &str,
    password: &str,
    answer: &[u8],
    challenge: Option<OpenVpnChallengeKind>,
    timeout: Duration,
) -> Result<(), ManagementAuthError> {
    if challenge == Some(OpenVpnChallengeKind::Remote) {
        return Err(ManagementAuthError::UnsupportedChallenge);
    }
    if !valid_quoted_value(username)
        || !valid_quoted_value(password)
        || answer.iter().any(u8::is_ascii_control)
        || (challenge == Some(OpenVpnChallengeKind::Static)) == answer.is_empty()
    {
        return Err(ManagementAuthError::InvalidCredentials);
    }
    let deadline = Instant::now() + timeout;
    let mut writer = stream.try_clone().map_err(|_| ManagementAuthError::Io)?;
    let mut reader = BufReader::new(stream);
    let mut event = String::new();
    loop {
        read_event(&mut reader, &mut event, deadline)?;
        let event = event.trim_end_matches(['\r', '\n']);
        if event.starts_with(">HOLD:") {
            send(&mut writer, "state on", deadline)?;
            send(&mut writer, "hold release", deadline)?;
        } else if event.starts_with(">PASSWORD:Need 'Auth'") && event.contains(" SC:") {
            if challenge != Some(OpenVpnChallengeKind::Static) {
                return Err(ManagementAuthError::UnsupportedChallenge);
            }
            send_credentials(&mut writer, username, password, Some(answer), deadline)?;
        } else if event.starts_with(">PASSWORD:Need 'Auth'") {
            if challenge.is_some() {
                return Err(ManagementAuthError::UnsupportedChallenge);
            }
            send_credentials(&mut writer, username, password, None, deadline)?;
        } else if event.starts_with(">PASSWORD:Verification Failed") {
            return Err(ManagementAuthError::AuthenticationRejected);
        } else if event.starts_with(">PASSWORD:Need '") || event.starts_with(">NEED-STR:") {
            return Err(ManagementAuthError::UnsupportedChallenge);
        } else if event.starts_with(">FATAL:") {
            return Err(ManagementAuthError::DaemonExited);
        } else if let Some(state) = event.strip_prefix(">STATE:") {
            let mut fields = state.splitn(3, ',');
            let _timestamp = fields.next();
            match fields.next() {
                Some("CONNECTED") => return Ok(()),
                Some("EXITING") => return Err(ManagementAuthError::DaemonExited),
                _ => {}
            }
        }
    }
}

fn read_event(
    reader: &mut BufReader<UnixStream>,
    event: &mut String,
    deadline: Instant,
) -> Result<(), ManagementAuthError> {
    event.clear();
    reader
        .get_ref()
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(|_| ManagementAuthError::Io)?;
    let read = reader
        .by_ref()
        .take((MAX_MANAGEMENT_EVENT_BYTES + 1) as u64)
        .read_line(event)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                ManagementAuthError::Timeout
            }
            _ => ManagementAuthError::Io,
        })?;
    if read == 0 {
        return Err(ManagementAuthError::Closed);
    }
    if read > MAX_MANAGEMENT_EVENT_BYTES || !event.ends_with('\n') {
        return Err(ManagementAuthError::InvalidEvent);
    }
    Ok(())
}

fn send_credentials(
    writer: &mut UnixStream,
    username: &str,
    password: &str,
    answer: Option<&[u8]>,
    deadline: Instant,
) -> Result<(), ManagementAuthError> {
    let username_command = Zeroizing::new(format!(
        "username \"Auth\" \"{}\"",
        escape_quoted_value(username)
    ));
    send(writer, username_command.as_str(), deadline)?;
    let password_command = match answer {
        Some(answer) => {
            let encoded_password = Zeroizing::new(BASE64.encode(password));
            let encoded_answer = Zeroizing::new(BASE64.encode(answer));
            Zeroizing::new(format!(
                "password \"Auth\" \"SCRV1:{}:{}\"",
                encoded_password.as_str(),
                encoded_answer.as_str()
            ))
        }
        None => Zeroizing::new(format!(
            "password \"Auth\" \"{}\"",
            escape_quoted_value(password)
        )),
    };
    send(writer, password_command.as_str(), deadline)
}

fn send(writer: &mut UnixStream, line: &str, deadline: Instant) -> Result<(), ManagementAuthError> {
    writer
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|_| ManagementAuthError::Io)?;
    writer
        .write_all(line.as_bytes())
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                ManagementAuthError::Timeout
            }
            _ => ManagementAuthError::Io,
        })
}

fn remaining(deadline: Instant) -> Result<Duration, ManagementAuthError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(ManagementAuthError::Timeout)
}

fn valid_quoted_value(value: &str) -> bool {
    !value.is_empty() && !value.as_bytes().iter().any(u8::is_ascii_control)
}

fn escape_quoted_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::Duration;

    use crate::vortix_core::privileged::OpenVpnChallengeKind;

    use super::{authenticate, ManagementAuthError};

    #[test]
    fn plain_credentials_are_sent_only_after_the_auth_prompt() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let (release_peer, keep_peer_alive) = std::sync::mpsc::channel();
        let peer = thread::spawn(move || {
            server
                .write_all(b">HOLD:Waiting for hold release\n")
                .unwrap();
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let mut commands = Vec::new();
            for _ in 0..2 {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                commands.push(line);
            }
            server
                .write_all(b">PASSWORD:Need 'Auth' username/password\n")
                .unwrap();
            for _ in 0..2 {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                commands.push(line);
            }
            server.write_all(b">STATE:1,CONNECTED,SUCCESS\n").unwrap();
            keep_peer_alive.recv().unwrap();
            commands
        });

        authenticate(
            client,
            "alice",
            "correct horse",
            &[],
            None,
            Duration::from_secs(1),
        )
        .unwrap();
        release_peer.send(()).unwrap();
        assert_eq!(
            peer.join().unwrap(),
            [
                "state on\n",
                "hold release\n",
                "username \"Auth\" \"alice\"\n",
                "password \"Auth\" \"correct horse\"\n",
            ]
        );
    }

    #[test]
    fn remote_challenge_is_rejected_without_exposing_credentials() {
        let (client, _server) = UnixStream::pair().unwrap();
        let error = authenticate(
            client,
            "alice",
            "correct horse",
            b"answer",
            Some(OpenVpnChallengeKind::Remote),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error, ManagementAuthError::UnsupportedChallenge);
        let debug = format!("{error:?}");
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("correct horse"));
        assert!(!debug.contains("answer"));
    }

    #[test]
    fn static_challenge_uses_scrv1_and_redacts_rejection_details() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let (release_peer, keep_peer_alive) = std::sync::mpsc::channel();
        let peer = thread::spawn(move || {
            server.write_all(b">HOLD:Waiting\n").unwrap();
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let mut commands = Vec::new();
            for _ in 0..2 {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                commands.push(line);
            }
            server
                .write_all(b">PASSWORD:Need 'Auth' username/password SC:1,Token\n")
                .unwrap();
            for _ in 0..2 {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                commands.push(line);
            }
            server
                .write_all(b">PASSWORD:Verification Failed: alice secret detail\n")
                .unwrap();
            keep_peer_alive.recv().unwrap();
            commands
        });

        let error = authenticate(
            client,
            "alice",
            "correct horse",
            b"123456",
            Some(OpenVpnChallengeKind::Static),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error, ManagementAuthError::AuthenticationRejected);
        release_peer.send(()).unwrap();
        assert_eq!(
            peer.join().unwrap(),
            [
                "state on\n",
                "hold release\n",
                "username \"Auth\" \"alice\"\n",
                "password \"Auth\" \"SCRV1:Y29ycmVjdCBob3JzZQ==:MTIzNDU2\"\n",
            ]
        );
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("alice"));
        assert!(!rendered.contains("secret detail"));
    }

    #[test]
    fn silent_management_peer_is_bounded_by_one_wall_clock_deadline() {
        let (client, _server) = UnixStream::pair().unwrap();
        let started = std::time::Instant::now();
        let error = authenticate(
            client,
            "alice",
            "correct horse",
            &[],
            None,
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert_eq!(error, ManagementAuthError::Timeout);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
