// just enough uuid support to generate device ids and to match entry ids

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uuid([u8; 16]);

impl Uuid {
    pub fn new_v4() -> Self {
        let mut bytes: [u8; 16] = rand::random();
        // version 4
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        // rfc 9562 variant
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(bytes)
    }

    // accepts the simple (32 hex digits), hyphenated, braced ("{...}") and
    // urn ("urn:uuid:...") formats, like the uuid crate did
    pub fn parse(s: &str) -> Option<Self> {
        let s = match s.len() {
            38 => s.strip_prefix('{')?.strip_suffix('}')?,
            45 => s.strip_prefix("urn:uuid:")?,
            _ => s,
        };
        let hex: std::vec::Vec<u8> = match s.len() {
            32 => s.bytes().collect(),
            36 => {
                let mut hex = vec![];
                for (i, c) in s.bytes().enumerate() {
                    if [8, 13, 18, 23].contains(&i) {
                        if c != b'-' {
                            return None;
                        }
                    } else {
                        hex.push(c);
                    }
                }
                hex
            }
            _ => return None,
        };

        let mut bytes = [0; 16];
        for (byte, digits) in bytes.iter_mut().zip(hex.chunks(2)) {
            let [hi, lo] = digits else { unreachable!() };
            *byte = (hex_value(*hi)? << 4) | hex_value(*lo)?;
        }
        Some(Self(bytes))
    }
}

fn hex_value(c: u8) -> Option<u8> {
    char::from(c).to_digit(16).map(|d| u8::try_from(d).unwrap())
}

impl std::fmt::Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if [4, 6, 8, 10].contains(&i) {
                write!(f, "-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse() {
        let expected = Uuid([
            0x67, 0xe5, 0x50, 0x44, 0x10, 0xb1, 0x42, 0x6f, 0x92, 0x47, 0xbb,
            0x68, 0x0e, 0x5f, 0xe0, 0xc8,
        ]);
        for s in [
            "67e5504410b1426f9247bb680e5fe0c8",
            "67e55044-10b1-426f-9247-bb680e5fe0c8",
            "67E55044-10B1-426F-9247-BB680E5FE0C8",
            "{67e55044-10b1-426f-9247-bb680e5fe0c8}",
            "urn:uuid:67e55044-10b1-426f-9247-bb680e5fe0c8",
        ] {
            assert_eq!(Uuid::parse(s), Some(expected), "{s}");
        }
        assert_eq!(
            expected.to_string(),
            "67e55044-10b1-426f-9247-bb680e5fe0c8"
        );

        for s in [
            "",
            "67e55044-10b1-426f-9247-bb680e5fe0c",
            "67e55044-10b1-426f-9247-bb680e5fe0cg",
            "67e55044-10b1-426f-9247+bb680e5fe0c8",
            "67e5504410b1426f9247bb680e5fe0c+",
            "{67e5504410b1426f9247bb680e5fe0c8}",
            "github",
        ] {
            assert_eq!(Uuid::parse(s), None, "{s}");
        }
    }

    #[test]
    fn test_new_v4() {
        let uuid = Uuid::new_v4();
        let s = uuid.to_string();
        assert_eq!(Uuid::parse(&s), Some(uuid));
        assert_eq!(&s[14..15], "4");
        assert!(["8", "9", "a", "b"].contains(&&s[19..20]));
    }
}
