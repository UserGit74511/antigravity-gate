//! RFC 6066 TLS ClientHello SNI parser.

pub fn is_tls_handshake(buf: &[u8]) -> bool {
    buf.len() >= 5 && buf[0] == 0x16 && buf[1] == 0x03
}

pub fn parse_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5 + record_len;
    let data = if buf.len() < record_end {
        &buf[5..]
    } else {
        &buf[5..record_end]
    };

    if data.len() < 4 || data[0] != 0x01 {
        return None;
    }

    let handshake_len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
    let body_end = (4 + handshake_len).min(data.len());
    let body = &data[4..body_end];

    if body.len() < 35 {
        return None;
    }

    let session_id_len = body[34] as usize;
    let mut cursor = 35 + session_id_len;
    if body.len() < cursor + 2 {
        return None;
    }

    let cipher_suites_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor += 2 + cipher_suites_len;
    if body.len() < cursor + 1 {
        return None;
    }

    let compression_methods_len = body[cursor] as usize;
    cursor += 1 + compression_methods_len;
    if body.len() < cursor + 2 {
        return None;
    }

    let extensions_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor += 2;
    let extensions_end = (cursor + extensions_len).min(body.len());

    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
        let ext_len = u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]) as usize;
        cursor += 4;

        let ext_data_end = cursor + ext_len;
        if ext_data_end > extensions_end {
            break;
        }

        if ext_type == 0x0000 {
            let ext_data = &body[cursor..ext_data_end];
            if ext_data.len() < 2 {
                return None;
            }

            let server_name_list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            let mut list_cursor = 2;
            let list_end = (2 + server_name_list_len).min(ext_data.len());

            while list_cursor + 3 <= list_end {
                let name_type = ext_data[list_cursor];
                let name_len =
                    u16::from_be_bytes([ext_data[list_cursor + 1], ext_data[list_cursor + 2]])
                        as usize;
                list_cursor += 3;

                if list_cursor + name_len > list_end {
                    break;
                }

                if name_type == 0 {
                    let host_bytes = &ext_data[list_cursor..list_cursor + name_len];
                    if let Ok(hostname) = std::str::from_utf8(host_bytes) {
                        let trimmed = hostname.trim().trim_end_matches('.');
                        let lower = trimmed.to_ascii_lowercase();
                        if is_valid_hostname(&lower) {
                            return Some(lower);
                        }
                    }
                }

                list_cursor += name_len;
            }
        }

        cursor = ext_data_end;
    }

    None
}

pub fn is_valid_hostname(host: &str) -> bool {
    let clean = host.trim_end_matches('.');
    if clean.is_empty() || clean.len() > 253 {
        return false;
    }
    for label in clean.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn build_client_hello(hostname: &str) -> Vec<u8> {
        let host_bytes = hostname.as_bytes();
        let host_len = host_bytes.len() as u16;

        let mut server_name_entry = Vec::new();
        server_name_entry.push(0x00);
        server_name_entry.extend_from_slice(&host_len.to_be_bytes());
        server_name_entry.extend_from_slice(host_bytes);

        let list_len = server_name_entry.len() as u16;
        let mut ext_server_name = Vec::new();
        ext_server_name.extend_from_slice(&list_len.to_be_bytes());
        ext_server_name.extend_from_slice(&server_name_entry);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(ext_server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ext_server_name);

        extensions.extend_from_slice(&0x0010u16.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes());
        extensions.extend_from_slice(&[2, b'h', b'2']);

        let extensions_total_len = extensions.len() as u16;

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xaa; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&extensions_total_len.to_be_bytes());
        body.extend_from_slice(&extensions);

        let body_len = body.len();
        let mut handshake = vec![
            0x01,
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);

        let handshake_len = handshake.len() as u16;
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&handshake_len.to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn test_valid_sni_parsing() {
        let packet = build_client_hello("daily-cloudcode-pa.googleapis.com");
        assert!(is_tls_handshake(&packet));
        let sni = parse_sni(&packet);
        assert_eq!(sni, Some("daily-cloudcode-pa.googleapis.com".to_string()));
    }

    #[test]
    fn test_case_insensitivity() {
        let packet = build_client_hello("GenerativeLanguage.GoogleAPIs.Com");
        let sni = parse_sni(&packet);
        assert_eq!(sni, Some("generativelanguage.googleapis.com".to_string()));
    }

    #[test]
    fn test_truncated_buffer() {
        let packet = build_client_hello("example.com");
        assert_eq!(parse_sni(&packet[..3]), None);
        assert_eq!(parse_sni(&packet[..15]), None);
    }

    #[test]
    fn test_non_tls_data() {
        let http_data = b"CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1\r\n\r\n";
        assert!(!is_tls_handshake(http_data));
        assert_eq!(parse_sni(http_data), None);
    }

    #[test]
    fn test_client_hello_without_extensions() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xbb; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);

        let body_len = body.len();
        let mut handshake = vec![
            0x01,
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);

        let handshake_len = handshake.len() as u16;
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&handshake_len.to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(parse_sni(&record), None);
    }

    #[test]
    fn test_empty_sni_hostname() {
        let packet = build_client_hello("");
        assert_eq!(parse_sni(&packet), None);
    }

    #[test]
    fn test_large_client_hello_with_sni() {
        let host_bytes = b"daily-cloudcode-pa.googleapis.com";
        let host_len = host_bytes.len() as u16;

        let mut server_name_entry = Vec::new();
        server_name_entry.push(0x00);
        server_name_entry.extend_from_slice(&host_len.to_be_bytes());
        server_name_entry.extend_from_slice(host_bytes);

        let list_len = server_name_entry.len() as u16;
        let mut ext_server_name = Vec::new();
        ext_server_name.extend_from_slice(&list_len.to_be_bytes());
        ext_server_name.extend_from_slice(&server_name_entry);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(ext_server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ext_server_name);

        let pad_len = 4500u16;
        extensions.extend_from_slice(&0x0015u16.to_be_bytes());
        extensions.extend_from_slice(&pad_len.to_be_bytes());
        extensions.extend_from_slice(&vec![0u8; pad_len as usize]);

        let extensions_total_len = extensions.len() as u16;

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xaa; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&extensions_total_len.to_be_bytes());
        body.extend_from_slice(&extensions);

        let body_len = body.len();
        let mut handshake = vec![
            0x01,
            ((body_len >> 16) & 0xff) as u8,
            ((body_len >> 8) & 0xff) as u8,
            (body_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);

        let handshake_len = handshake.len() as u16;
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&handshake_len.to_be_bytes());
        record.extend_from_slice(&handshake);

        assert!(record.len() > 4500);
        let sni = parse_sni(&record);
        assert_eq!(sni, Some("daily-cloudcode-pa.googleapis.com".to_string()));
    }

    #[test]
    fn test_invalid_hostname_characters() {
        assert_eq!(parse_sni(&build_client_hello("foo\0bar.com")), None);
        assert_eq!(parse_sni(&build_client_hello("foo\r\nbar.com")), None);
        assert_eq!(parse_sni(&build_client_hello("foo bar.com")), None);
        assert_eq!(parse_sni(&build_client_hello("../etc/passwd")), None);
        assert_eq!(parse_sni(&build_client_hello("-invalid.com")), None);
        assert_eq!(parse_sni(&build_client_hello("invalid-.com")), None);
        assert_eq!(parse_sni(&build_client_hello("foo..bar.com")), None);
    }

    #[test]
    fn test_truncation_fuzzing_all_byte_offsets() {
        let packet = build_client_hello("daily-cloudcode-pa.googleapis.com");
        for i in 0..packet.len() {
            let _ = parse_sni(&packet[..i]);
            let _ = is_tls_handshake(&packet[..i]);
        }
    }

    #[test]
    fn test_corrupted_extension_lengths() {
        let mut packet = build_client_hello("example.com");
        packet[3] = 0xff;
        packet[4] = 0xff;
        let _ = parse_sni(&packet);

        let mut packet2 = build_client_hello("example.com");
        packet2[6] = 0xff;
        packet2[7] = 0xff;
        let _ = parse_sni(&packet2);
    }

    #[test]
    fn test_fqdn_trailing_dot() {
        assert!(is_valid_hostname("example.com."));
        assert!(is_valid_hostname("daily-cloudcode-pa.googleapis.com."));
        assert!(!is_valid_hostname("."));
        assert!(!is_valid_hostname(".."));
    }
}
