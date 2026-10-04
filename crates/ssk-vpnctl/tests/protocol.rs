use ssk_vpnctl::{CredentialKind, Decoder, Event, ProtocolError, VpnState, MAX_LINE_BYTES};

fn decode(bytes: &[u8]) -> Result<Vec<Event>, ProtocolError> {
    let mut decoder = Decoder::default();
    let events = bytes
        .iter()
        .filter_map(|b| decoder.push(*b).transpose())
        .collect::<Result<_, _>>()?;
    decoder.finish()?;
    Ok(events)
}

#[test]
fn transcript_decodes_independently_of_every_possible_read_boundary() {
    let transcript = b"ENTER PASSWORD:SUCCESS: password is correct\r\n>INFO:welcome\r\n>HOLD:Waiting for hold release:1\r\nSUCCESS: pid=123\r\nSUCCESS: real-time state notification set to ON\r\nSUCCESS: hold release succeeded\r\n>STATE:1724000000,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1,1194,192.0.2.2,49000,fd00::2\r\n";
    let expected = vec![
        Event::PasswordPrompt,
        Event::Authenticated,
        Event::Ignored,
        Event::Hold {
            retry_after_secs: 1,
        },
        Event::Pid(123),
        Event::StateSubscribed,
        Event::HoldReleased,
        Event::State(VpnState::Connected),
    ];
    for boundary in 0..=transcript.len() {
        let mut decoder = Decoder::default();
        let mut events = Vec::new();
        for part in [&transcript[..boundary], &transcript[boundary..]] {
            for byte in part {
                if let Some(event) = decoder.push(*byte).unwrap() {
                    events.push(event);
                }
            }
        }
        decoder.finish().unwrap();
        assert_eq!(events, expected, "split at {boundary}");
    }
}

#[test]
fn state_rows_cover_ipv6_only_and_reconnect_without_inventing_connectivity() {
    for (row, state) in [
        (
            ">STATE:1724000000,CONNECTED,SUCCESS,,2001:db8::1,1194,2001:db8::2,49100,fd00::2\n",
            VpnState::Connected,
        ),
        (
            ">STATE:1724000000,RECONNECTING,ping-restart,,,,,\n",
            VpnState::Reconnecting,
        ),
        (
            ">STATE:1724000000,AUTH_PENDING,timeout 60,,,,,\n",
            VpnState::AuthPending,
        ),
        (">STATE:1724000000,RESOLVE,,,,,,\n", VpnState::Resolving),
        (
            ">STATE:1724000000,EXITING,SIGTERM,,,,,\n",
            VpnState::Exiting,
        ),
    ] {
        assert_eq!(decode(row.as_bytes()).unwrap(), vec![Event::State(state)]);
    }
}

#[test]
fn malformed_unknown_and_oversized_input_poison_the_decoder() {
    for bytes in [
        b">STATE:abc,CONNECTED,SUCCESS,10.8.0.2\n".as_slice(),
        b">STATE:1,CONNECTED,not-success,10.8.0.2\n",
        b">STATE:1,CONNECTED,SUCCESS,\n",
        b">STATE:1,CONNECTED,SUCCESS,not-an-ip\n",
        b">STATE:1,NEW_STATE,,,,,,\n",
        b">STATE:1,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1,65536,,,\n",
        b">STATE:1,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1,1194,,,fd00::2,extra\n",
        b">HOLD:Waiting for hold release:301\n",
        b">NEED-OK:Need 'token' confirmation MSG:approve me\n",
        b">REMOTE:attacker.example,1194,udp\n",
        b">INFO:bad\rINJECTED\n",
        b">INFO:\0bad\n",
        b">INFO:\xff\n",
        b"END\n",
        b"SUCCESS: made up acknowledgement\n",
    ] {
        let mut decoder = Decoder::default();
        assert!(
            bytes.iter().any(|b| decoder.push(*b).is_err()),
            "accepted {bytes:?}"
        );
        assert_eq!(decoder.push(b'\n'), Err(ProtocolError::Closed));
    }
    let mut decoder = Decoder::default();
    for _ in 0..MAX_LINE_BYTES {
        assert!(decoder.push(b'x').unwrap().is_none());
    }
    assert_eq!(decoder.push(b'x'), Err(ProtocolError::TooLong));
    assert_eq!(decoder.push(b'\n'), Err(ProtocolError::Closed));
}

#[test]
fn eof_mid_prompt_or_line_is_not_a_successful_message() {
    for truncated in [
        b"ENTER PASS".as_slice(),
        b">STATE:1,CONNECTED,SUCCESS,10.8.0.2",
        b">INFO:notice\r",
    ] {
        assert_eq!(decode(truncated), Err(ProtocolError::Truncated));
    }
    assert_eq!(decode(b"ENTER PASSWORD:").unwrap(), [Event::PasswordPrompt]);
}

#[test]
fn diagnostic_events_and_errors_do_not_retain_server_secrets() {
    for (line, expected) in [
        (
            ">PASSWORD:Need 'Auth' username/password\n",
            Event::CredentialsRequired(CredentialKind::Auth),
        ),
        (
            ">PASSWORD:Need 'Private Key' password\n",
            Event::CredentialsRequired(CredentialKind::PrivateKey),
        ),
        (
            ">PASSWORD:Need 'Auth' SC:0,SECRET_MARKER:secret challenge\n",
            Event::CredentialsRequired(CredentialKind::Other),
        ),
        (
            ">PASSWORD:Verification Failed: 'SECRET_MARKER'\n",
            Event::VpnAuthenticationFailed,
        ),
        (">FATAL:SECRET_MARKER\n", Event::Fatal),
        (">LOG:123,F,SECRET_MARKER\n", Event::Ignored),
        ("ERROR: SECRET_MARKER\n", Event::CommandRejected),
    ] {
        let events = decode(line.as_bytes()).unwrap();
        assert_eq!(events, [expected]);
        assert!(!format!("{events:?}").contains("SECRET_MARKER"));
    }
    let error = decode(b">UNKNOWN:SECRET_MARKER\n").unwrap_err();
    assert!(!format!("{error:?} {error}").contains("SECRET_MARKER"));
}
