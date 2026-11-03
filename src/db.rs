use crate::prelude::*;

use std::io::{Read as _, Write as _};

use tokio::io::AsyncReadExt as _;

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Entry {
    pub id: String,
    pub org_id: Option<String>,
    pub folder: Option<String>,
    pub folder_id: Option<String>,
    pub name: String,
    pub data: EntryData,
    pub fields: Vec<Field>,
    pub notes: Option<String>,
    pub history: Vec<HistoryEntry>,
    pub key: Option<String>,
    pub master_password_reprompt: crate::api::CipherRepromptType,
}

impl Entry {
    pub fn master_password_reprompt(&self) -> bool {
        self.master_password_reprompt != crate::api::CipherRepromptType::None
    }
}

#[derive(serde::Serialize, Debug, Clone, Eq, PartialEq)]
pub struct Uri {
    pub uri: String,
    pub match_type: Option<crate::api::UriMatchType>,
}

// backwards compatibility
impl<'de> serde::Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StringOrUri;
        impl<'de> serde::de::Visitor<'de> for StringOrUri {
            type Value = Uri;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("uri")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Uri {
                    uri: value.to_string(),
                    match_type: None,
                })
            }

            fn visit_map<M>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut uri = None;
                let mut match_type = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "uri" => {
                            if uri.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field("uri"),
                                );
                            }
                            uri = Some(map.next_value()?);
                        }
                        "match_type" => {
                            if match_type.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field(
                                        "match_type",
                                    ),
                                );
                            }
                            match_type = map.next_value()?;
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["uri", "match_type"],
                            ))
                        }
                    }
                }

                uri.map_or_else(
                    || Err(serde::de::Error::missing_field("uri")),
                    |uri| Ok(Self::Value { uri, match_type }),
                )
            }
        }

        deserializer.deserialize_any(StringOrUri)
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub enum EntryData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Vec<Uri>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        private_key: Option<String>,
        public_key: Option<String>,
        fingerprint: Option<String>,
    },
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Field {
    pub ty: Option<crate::api::FieldType>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub linked_id: Option<crate::api::LinkedIdType>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct HistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Db {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    // set when the server rejected the refresh token. syncing then fails
    // until the next explicit `rbw login`, but the cached entries stay
    // usable, so that this doesn't require network access to read them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub refresh_token_rejected: bool,

    pub kdf: Option<crate::api::KdfType>,
    pub iterations: Option<u32>,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
    pub protected_key: Option<String>,
    pub protected_private_key: Option<String>,
    pub protected_org_keys: std::collections::HashMap<String, String>,

    pub entries: Vec<Entry>,
    // entries which were deleted, but can still be restored. these are kept
    // separately, so that nothing which looks at the entries sees them by
    // accident.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trash: Vec<Entry>,
}

impl Db {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            std::fs::File::open(&file).map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub async fn load_async(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadDbAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadDbAsync {
                source,
                file: file.clone(),
            }
        })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub fn save(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let json = serde_json::to_string(self).map_err(|source| {
            Error::SaveDbJson {
                source,
                file: file.clone(),
            }
        })?;
        write_atomic(&file, json.as_bytes())
            .map_err(|source| Error::SaveDb { source, file })?;
        Ok(())
    }

    pub async fn save_async(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let json = serde_json::to_string(self).map_err(|source| {
            Error::SaveDbJson {
                source,
                file: file.clone(),
            }
        })?;
        let tmp = file.clone();
        tokio::task::spawn_blocking(move || {
            write_atomic(&tmp, json.as_bytes())
        })
        .await
        .map_err(std::io::Error::other)
        .and_then(|res| res)
        .map_err(|source| Error::SaveDbAsync { source, file })?;
        Ok(())
    }

    pub fn remove(server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let res = std::fs::remove_file(&file);
        if let Err(e) = &res {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
        }
        res.map_err(|source| Error::RemoveDb { source, file })?;
        Ok(())
    }

    pub fn needs_login(&self) -> bool {
        self.access_token.is_none()
            || self.refresh_token.is_none()
            || self.iterations.is_none()
            || self.kdf.is_none()
            || self.protected_key.is_none()
    }
}

// written to a temporary file in the same directory and renamed over the
// old one, so a concurrent load never sees a truncated or partial file
fn write_atomic(file: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    // unwrap is safe here because the db file is explicitly constructed as
    // a filename in a directory
    let dir = file.parent().unwrap();
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(file).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_refresh_token_rejected_serialization() {
        // dbs written before the flag existed must still load, and the flag
        // shouldn't show up in the file unless it is set
        let db: Db = serde_json::from_str(
            r#"{"access_token":"a","refresh_token":"r","kdf":null,"iterations":null,"memory":null,"parallelism":null,"protected_key":null,"protected_private_key":null,"protected_org_keys":{},"entries":[]}"#,
        )
        .unwrap();
        assert!(!db.refresh_token_rejected);
        let json = serde_json::to_string(&db).unwrap();
        assert!(!json.contains("refresh_token_rejected"));

        let db = Db {
            refresh_token_rejected: true,
            ..db
        };
        let json = serde_json::to_string(&db).unwrap();
        let db: Db = serde_json::from_str(&json).unwrap();
        assert!(db.refresh_token_rejected);
    }
}
