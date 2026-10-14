//! Universal Quick Share — Android Quick Share core protocol implementation.

pub mod ble;
pub mod d2d;
pub mod framing;
pub mod mdns;
pub mod qrcode_flow;
pub mod transfer;
pub mod ukey2;

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::d2d::SecureChannel;
    use crate::mdns::{
        build_endpoint_info, build_service_instance_name, parse_endpoint_info,
        parse_service_instance_name, ShareTargetType, INSTANCE_SERVICE_ID_HASH, SERVICE_ID,
        SERVICE_TYPE,
    };
    use crate::qrcode_flow::QuickShareQrCode;
    use crate::transfer::sanitize_offered_name;
    use crate::ukey2::{
        decode_point_unsigned, encode_point_signed, run_client_handshake, run_server_handshake,
        to_four_digit_pin, D2D_SALT,
    };

    #[test]
    fn verify_service_type_and_d2d_salt_constants() {
        let digest = Sha256::digest(SERVICE_ID);
        let computed_type = format!("_{}._tcp.local.", hex::encode_upper(&digest[..6]));
        assert_eq!(computed_type, SERVICE_TYPE);
        assert_eq!(&digest[..3], &INSTANCE_SERVICE_ID_HASH);

        let d2d_digest: [u8; 32] = Sha256::digest(b"D2D").into();
        assert_eq!(d2d_digest, D2D_SALT);
    }

    #[test]
    fn roundtrip_mdns_service_instance_and_endpoint_info() {
        let ep = *b"AB12";
        let name = build_service_instance_name(&ep);
        assert_eq!(name.len(), 14);
        assert!(name.ends_with("AAA"));
        let (parsed_ep, parsed_hash) = parse_service_instance_name(&name).unwrap();
        assert_eq!(parsed_ep, ep);
        assert_eq!(parsed_hash, INSTANCE_SERVICE_ID_HASH);

        let info = build_endpoint_info(Some("Purvansh-Linux"), ShareTargetType::Laptop).unwrap();
        let parsed = parse_endpoint_info(&info).unwrap();
        assert!(parsed.visible);
        assert_eq!(parsed.device_name.as_deref(), Some("Purvansh-Linux"));
        assert_eq!(parsed.device_type, ShareTargetType::Laptop);
    }

    #[test]
    fn roundtrip_signed_p256_point_encoding() {
        let mut coord = [0u8; 32];
        coord[0] = 0x89;
        coord[31] = 0x42;
        let enc = encode_point_signed(&coord);
        assert_eq!(enc.len(), 33);
        assert_eq!(enc[0], 0x00);
        let dec = decode_point_unsigned(&enc).unwrap();
        assert_eq!(dec, coord);
    }

    #[test]
    fn verify_pin_derivation_and_path_sanitization() {
        let pin = to_four_digit_pin(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x99]);
        assert_eq!(pin.len(), 4);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));

        assert_eq!(
            sanitize_offered_name("../../etc/passwd"),
            "passwd"
        );
        assert_eq!(
            sanitize_offered_name("..\\..\\Windows\\System32\\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(sanitize_offered_name("..."), "unnamed_file");
    }

    #[tokio::test]
    async fn full_ukey2_handshake_and_d2d_encryption_roundtrip() {
        let (mut client_io, mut server_io) = tokio::io::duplex(65536);

        let server_task = tokio::spawn(async move {
            run_server_handshake(&mut server_io).await.unwrap()
        });
        let client_task = tokio::spawn(async move {
            run_client_handshake(&mut client_io).await.unwrap()
        });

        let (server_keys, client_keys) = tokio::join!(server_task, client_task);
        let server_keys = server_keys.unwrap();
        let client_keys = client_keys.unwrap();

        assert_eq!(server_keys.pin, client_keys.pin);
        assert_eq!(server_keys.auth_string, client_keys.auth_string);

        let mut server_chan = SecureChannel::new(server_keys);
        let mut client_chan = SecureChannel::new(client_keys);

        let ct = client_chan.encrypt(b"hello quickshare from linux");
        let pt = server_chan.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello quickshare from linux");

        let ct2 = server_chan.encrypt(b"ack from server");
        let pt2 = client_chan.decrypt(&ct2).unwrap();
        assert_eq!(pt2, b"ack from server");
    }

    #[test]
    fn qrcode_generation_and_signing() {
        let qr = QuickShareQrCode::generate();
        assert!(qr.url.starts_with("https://quickshare.google/qrcode#key="));
        assert_eq!(qr.key_payload.len(), 35);
        let sig = qr.sign_auth_string(&[0x55u8; 32]);
        assert_eq!(sig.len(), 64);
    }

    #[tokio::test]
    async fn end_to_end_tcp_file_transfer_roundtrip() {
        use tokio::net::TcpListener;
        use crate::transfer::{handle_incoming_connection, send_files_to_peer, ReceivedItem};

        let tmp_root = std::env::temp_dir().join(format!("uqs_test_{}", std::process::id()));
        let src_dir = tmp_root.join("src");
        let dst_dir = tmp_root.join("dst");
        tokio::fs::create_dir_all(&src_dir).await.unwrap();
        tokio::fs::create_dir_all(&dst_dir).await.unwrap();

        let src_file = src_dir.join("sample_payload.bin");
        let payload_data: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
        tokio::fs::write(&src_file, &payload_data).await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dst_dir_clone = dst_dir.clone();
        let receiver_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handle_incoming_connection(&mut stream, &dst_dir_clone, |offer| {
                assert_eq!(offer.peer_name, "Linux-Sender");
                assert_eq!(offer.files.len(), 1);
                assert_eq!(offer.files[0].name, "sample_payload.bin");
                assert_eq!(offer.files[0].size, 150_000);
                true
            })
            .await
            .unwrap()
        });

        let qr = QuickShareQrCode::generate();
        let sender_file = src_file.clone();
        let sender_task = tokio::spawn(async move {
            send_files_to_peer(
                addr,
                "Linux-Sender",
                b"SND1",
                &[sender_file],
                Some(|auth: &[u8]| qr.sign_auth_string(auth)),
                |pin| assert_eq!(pin.len(), 4),
            )
            .await
            .unwrap();
        });

        let (received, _) = tokio::join!(receiver_task, sender_task);
        let items = received.unwrap();
        assert_eq!(items.len(), 1);
        match &items[0] {
            ReceivedItem::File { name, path, size } => {
                assert_eq!(name, "sample_payload.bin");
                assert_eq!(*size, 150_000);
                let disk_bytes = tokio::fs::read(path).await.unwrap();
                assert_eq!(disk_bytes, payload_data);
            }
            other => panic!("unexpected received item: {other:?}"),
        }

        let _ = tokio::fs::remove_dir_all(&tmp_root).await;
    }
}
