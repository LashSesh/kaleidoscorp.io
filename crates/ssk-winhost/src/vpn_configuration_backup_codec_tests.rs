use super::*;

fn document() -> &'static [u8] {
    br#"{"schema":1,"policy":{"schema":1,"grants":[]},"profiles":[]}"#
}
fn test_key() -> [u8; KEY_BYTES] {
    let mut key = [7; KEY_BYTES];
    key[..8].copy_from_slice(KEY_MAGIC);
    key
}

#[test]
fn backup_codec_round_trip_and_fresh_nonce_without_cleartext() {
    let doc = document();
    let expected = sha(doc);
    let first = seal(doc, expected, &test_key()).unwrap();
    let second = seal(doc, expected, &test_key()).unwrap();
    assert_ne!(&first[40..64], &second[40..64]);
    assert_eq!(first.len(), doc.len() + HEADER + TAG);
    assert!(!first.windows(doc.len()).any(|w| w == doc));
    assert_eq!(open(&first, expected, &test_key()).unwrap().as_slice(), doc);
    assert_eq!(
        open(&second, expected, &test_key()).unwrap().as_slice(),
        doc
    );
}

#[test]
fn backup_codec_accepts_exact_maximum_document_without_unbounded_allocation() {
    let mut doc = document().to_vec();
    doc.resize(configuration::MAX_BYTES, b' ');
    let archive = seal(&doc, sha(&doc), &test_key()).unwrap();
    assert_eq!(archive.len(), MAX_ARCHIVE);
    assert_eq!(
        open(&archive, sha(&doc), &test_key()).unwrap().as_slice(),
        doc
    );
}

#[test]
fn backup_codec_rejects_every_tampered_byte_wrong_key_and_digest() {
    let expected = sha(document());
    let archive = seal(document(), expected, &test_key()).unwrap();
    for i in 0..archive.len() {
        let mut changed = archive.clone();
        changed[i] ^= 1;
        assert!(open(&changed, expected, &test_key()).is_err(), "byte {i}");
    }
    let mut wrong = test_key();
    wrong[8] ^= 1;
    assert!(matches!(
        open(&archive, expected, &wrong),
        Err(DeploymentError::BackupAuthentication)
    ));
    assert!(open(&archive, [4; 32], &test_key()).is_err());
}

#[test]
fn backup_codec_rejects_truncation_trailing_bytes_unknown_versions_and_oversize() {
    let expected = sha(document());
    let archive = seal(document(), expected, &test_key()).unwrap();
    for len in 0..archive.len() {
        assert!(open(&archive[..len], expected, &test_key()).is_err());
    }
    let mut appended = archive.clone();
    appended.push(0);
    assert!(open(&appended, expected, &test_key()).is_err());
    assert!(open(&vec![0; MAX_ARCHIVE + 1], expected, &test_key()).is_err());
    let mut future = archive;
    future[7] = b'2';
    assert!(matches!(
        open(&future, expected, &test_key()),
        Err(DeploymentError::BackupFormat)
    ));
    assert!(seal(
        &vec![0; configuration::MAX_BYTES + 1],
        expected,
        &test_key()
    )
    .is_err());
}

#[test]
fn backup_codec_validates_document_and_key_format_before_export() {
    for doc in [
        &b"bad"[..],
        &br#"{"schema":1,"schema":1,"policy":{"schema":1,"grants":[]},"profiles":[]}"#[..],
    ] {
        assert!(seal(doc, sha(doc), &test_key()).is_err());
    }
    assert!(seal(document(), [0; 32], &test_key()).is_err());
    for key in [vec![], vec![0; KEY_BYTES], vec![0; KEY_BYTES + 1]] {
        assert!(seal(document(), sha(document()), &key).is_err());
    }
}

#[test]
fn backup_codec_authentication_alone_cannot_override_document_hash_or_schema() {
    // Construct authenticated but semantically invalid input independently of seal.
    for body in [&b"malformed"[..], document()] {
        let expected = if body == document() {
            [8; 32]
        } else {
            sha(body)
        };
        let mut header = [0; HEADER];
        header[..8].copy_from_slice(MAGIC);
        header[8..40].copy_from_slice(&expected);
        let mut payload = body.to_vec();
        let tag = cipher(&test_key())
            .unwrap()
            .encrypt_in_place_detached(XNonce::from_slice(&header[40..]), &header, &mut payload)
            .unwrap();
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&tag);
        assert!(open(&bytes, expected, &test_key()).is_err());
    }
}
