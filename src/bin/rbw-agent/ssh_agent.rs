use signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _};
use ssh_encoding::{Decode as _, Encode as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

// same limit as openssh's ssh-agent
const MAX_MESSAGE_LEN: u32 = 256 * 1024;

#[derive(Clone)]
pub struct SshAgent {
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
}

impl SshAgent {
    pub fn new(
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    ) -> Self {
        Self { state }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let socket = rbw::dirs::ssh_agent_socket_file();

        let _ = std::fs::remove_file(&socket); // Ignore error if it doesn't exist

        let listener = tokio::net::UnixListener::bind(socket)?;
        loop {
            let (stream, _) = listener.accept().await?;
            let agent = self.clone();
            tokio::spawn(async move {
                if let Err(e) = agent.handle_connection(stream).await {
                    log::warn!("ssh agent connection error: {e:#}");
                }
            });
        }
    }

    async fn handle_connection(
        &self,
        mut stream: tokio::net::UnixStream,
    ) -> anyhow::Result<()> {
        loop {
            let mut len = [0; 4];
            match stream.read_exact(&mut len).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            }
            let len = u32::from_be_bytes(len);
            if len == 0 || len > MAX_MESSAGE_LEN {
                return Err(anyhow::anyhow!("invalid message length {len}"));
            }

            let mut msg = vec![0; usize::try_from(len)?];
            stream.read_exact(&mut msg).await?;

            let response =
                self.handle_message(&msg).await.unwrap_or_else(|e| {
                    log::warn!("ssh agent request failed: {e:#}");
                    vec![SSH_AGENT_FAILURE]
                });

            stream
                .write_all(&u32::try_from(response.len())?.to_be_bytes())
                .await?;
            stream.write_all(&response).await?;
        }
    }

    async fn handle_message(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let Some((&msg_type, mut body)) = msg.split_first() else {
            return Err(anyhow::anyhow!("empty message"));
        };
        match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => self.request_identities().await,
            SSH_AGENTC_SIGN_REQUEST => {
                let key_blob = Vec::<u8>::decode(&mut body)?;
                let data = Vec::<u8>::decode(&mut body)?;
                let flags = u32::decode(&mut body)?;
                self.sign(&key_blob, &data, flags).await
            }
            // this includes extension messages like session-bind@openssh.com,
            // for which failure is the expected response if unsupported
            _ => Ok(vec![SSH_AGENT_FAILURE]),
        }
    }

    async fn request_identities(&self) -> anyhow::Result<Vec<u8>> {
        identities_answer(
            &crate::actions::get_ssh_public_keys(self.state.clone()).await?,
        )
    }

    async fn sign(
        &self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> anyhow::Result<Vec<u8>> {
        let private_key = crate::actions::find_ssh_private_key(
            self.state.clone(),
            key_blob,
        )
        .await?;
        sign_response(&private_key, data, flags)
    }
}

fn identities_answer(public_keys: &[String]) -> anyhow::Result<Vec<u8>> {
    let blobs: Vec<_> = public_keys
        .iter()
        .filter_map(|p| {
            match ssh_key::PublicKey::from_openssh(p)
                .and_then(|pk| pk.to_bytes())
            {
                Ok(blob) => Some(blob),
                Err(e) => {
                    log::warn!("skipping unsupported ssh key: {e}");
                    None
                }
            }
        })
        .collect();

    let mut response = vec![SSH_AGENT_IDENTITIES_ANSWER];
    u32::try_from(blobs.len())?.encode(&mut response)?;
    for blob in blobs {
        blob.encode(&mut response)?;
        // comment
        "".encode(&mut response)?;
    }
    Ok(response)
}

fn sign_response(
    private_key: &ssh_key::PrivateKey,
    data: &[u8],
    flags: u32,
) -> anyhow::Result<Vec<u8>> {
    let signature = match private_key.key_data() {
        ssh_key::private::KeypairData::Ed25519(key) => key.try_sign(data)?,

        ssh_key::private::KeypairData::Rsa(key) => {
            let p = rsa::BigUint::from_bytes_be(key.private.p.as_bytes());
            let q = rsa::BigUint::from_bytes_be(key.private.q.as_bytes());
            let e = rsa::BigUint::from_bytes_be(key.public.e.as_bytes());
            let rsa_key = rsa::RsaPrivateKey::from_p_q(p, q, e)?;

            let mut rng = rsa::rand_core::OsRng;

            let (algorithm, sig_bytes) = if flags & SSH_AGENT_RSA_SHA2_512
                != 0
            {
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(rsa_key);
                let signature =
                    signing_key.try_sign_with_rng(&mut rng, data)?;

                ("rsa-sha2-512", signature.to_bytes())
            } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key);
                let signature =
                    signing_key.try_sign_with_rng(&mut rng, data)?;

                ("rsa-sha2-256", signature.to_bytes())
            } else {
                // ssh-key can't represent ssh-rsa (sha1) signatures, and
                // openssh hasn't requested them by default since 8.8
                return Err(anyhow::anyhow!(
                    "ssh-rsa (sha1) signatures are not supported"
                ));
            };

            ssh_key::Signature::new(
                ssh_key::Algorithm::new(algorithm)?,
                sig_bytes,
            )?
        }

        // TODO: Check which other key types are supported by bitwarden
        other => {
            return Err(anyhow::anyhow!("Unsupported key type: {other:?}"));
        }
    };

    let mut response = vec![SSH_AGENT_SIGN_RESPONSE];
    signature.encode_prefixed(&mut response)?;
    Ok(response)
}

#[cfg(test)]
mod test {
    use super::*;
    use signature::Verifier as _;

    // throwaway keys, generated only for these tests
    const ED25519_PRIVATE: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACB2gkJeLOG74LfjZYE//5JIO63QY+SwIPjVq6SEHX6B3QAAAIj9OKno/Tip\n\
6AAAAAtzc2gtZWQyNTUxOQAAACB2gkJeLOG74LfjZYE//5JIO63QY+SwIPjVq6SEHX6B3Q\n\
AAAEAFn3O2UobcNvFHayUCzJN7sgys/2X549tCyzuQOBwuh3aCQl4s4bvgt+NlgT//kkg7\n\
rdBj5LAg+NWrpIQdfoHdAAAAAAECAwQF\n\
-----END OPENSSH PRIVATE KEY-----";
    const ED25519_PUBLIC: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHaCQl4s4bvgt+NlgT//kkg7rdBj5LAg+NWrpIQdfoHd";
    const RSA_PRIVATE: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n\
NhAAAAAwEAAQAAAQEAqHp5waOJgZSUKSyBYK2KDLFXXKEhfsFBZ1MHS+lG+3DkCcXhbPKZ\n\
E5EGbQXb2u5fkydqaTSuzH8NEjXx7EPpIROKOH3uM788BWST6rD19qUSDCcQo8YwaGwqVm\n\
7BgrhsakYtKTeEOy5yoTpIg07j6mfeyObfi0xMLd5XTAv+WQbELp4GxGo7rYLNVEQm7ZZ7\n\
G3eyOmV11/qm4nP4AaYAbN5kz4K6VLFyhdPwTlPj69o3GiLnJ5POJnowNQ/0iJrF51HAIf\n\
QzOEWMI0hlBxmZG5Bg3Ptg9AvuujuD8ymp8I11McabdT9/2Vu78FdeEeITQVeu5XODnYEY\n\
bUUREYDCrwAAA7jmW/fh5lv34QAAAAdzc2gtcnNhAAABAQCoennBo4mBlJQpLIFgrYoMsV\n\
dcoSF+wUFnUwdL6Ub7cOQJxeFs8pkTkQZtBdva7l+TJ2ppNK7Mfw0SNfHsQ+khE4o4fe4z\n\
vzwFZJPqsPX2pRIMJxCjxjBobCpWbsGCuGxqRi0pN4Q7LnKhOkiDTuPqZ97I5t+LTEwt3l\n\
dMC/5ZBsQungbEajutgs1URCbtlnsbd7I6ZXXX+qbic/gBpgBs3mTPgrpUsXKF0/BOU+Pr\n\
2jcaIucnk84mejA1D/SImsXnUcAh9DM4RYwjSGUHGZkbkGDc+2D0C+66O4PzKanwjXUxxp\n\
t1P3/ZW7vwV14R4hNBV67lc4OdgRhtRRERgMKvAAAAAwEAAQAAAQARSsTNbaIS5TORyEod\n\
KKKnK9qKHNWpw18Zokl47qAE9bDKGf/JpVq1yehNb1EB9v5jRaPj2W7peU7XpCbI961pYi\n\
6JHs/Aiuu3p/uQloogPxALpETOcmyMgzGTPnnpF1G1VK+U7+hIBLvqNWe05nd5GyEgIKYo\n\
D3QwLwZpvT9lVqQcUHiFF9SgX9XgbHsgpkR0pCF3qLo2gAaspUMwWzsMVaSmbcRYMHrGU0\n\
VHsnKqRcL6BSTSg6ctFumGkHwIPFsaFjCD6uRm5Np3KoxjpXUtwVBEL0CUf2O3Ko422yVP\n\
e/HIlxJKr+BPNSc9UyrJkfs8rcM2D0NHXXoEU068WVtBAAAAgQCbG73bg3yJU449obGd0e\n\
uW0nYMCU0er7grRLnkJrAcoDRaEgUT7IpGPlg8TWHI1bKAgVHwQxeHXKdF2+AV1srcMOja\n\
Ah5Qa3ntMUzgGXVbMtIfU4xY2bnCvE/T1tbWqxS+mlqVyKxDlvX3hDoyhiCVh8YQ1otBsb\n\
b+tLuVVUZyawAAAIEA5TSqwQRwyKq2muh+Oua+xUjerrndjSUaGHjewZUIOZhovzinFeLn\n\
upnT5hkWNSXdke4T0vrhoHLT6DIYOoW+eXPyYfwg5pFRRmGpCVGzourszMUrv08Z5wJ6Rf\n\
Fe+Pmx2a4db/9crMpCV9i9cm5ryjN7yjokMT6gdcTv+WbviG8AAACBALwsc2IoeDHKPoiw\n\
h/X+OfQ98C6v9ptWGcU/gv0pLgpwL/ZidGYC5HSy98b1wDWWQ7DYZuK2LtnGEQMDNvT+TD\n\
wRlt9Bw4f0kIu0/I+rgkinjYXXF41BKEsZHfUDqXW9jRoOp9x6u2pDDOQLoqtsx+i0AMaq\n\
uI84nnmtGKwgUQnBAAAAAAEC\n\
-----END OPENSSH PRIVATE KEY-----";
    const RSA_PUBLIC: &str =
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCoennBo4mBlJQpLIFgrYoMsVdcoSF+wUFnUwdL6Ub7cOQJxeFs8pkTkQZtBdva7l+TJ2ppNK7Mfw0SNfHsQ+khE4o4fe4zvzwFZJPqsPX2pRIMJxCjxjBobCpWbsGCuGxqRi0pN4Q7LnKhOkiDTuPqZ97I5t+LTEwt3ldMC/5ZBsQungbEajutgs1URCbtlnsbd7I6ZXXX+qbic/gBpgBs3mTPgrpUsXKF0/BOU+Pr2jcaIucnk84mejA1D/SImsXnUcAh9DM4RYwjSGUHGZkbkGDc+2D0C+66O4PzKanwjXUxxpt1P3/ZW7vwV14R4hNBV67lc4OdgRhtRRERgMKv";
    const ECDSA_PUBLIC: &str =
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKJvCFzFOGVDKD2nmdFXYnZhcAZTVNzJnh4NtDjojXSfcCJsJQdPg1p13Gk62E8Cu48nOoypNgx5y40PpNW38iI=";

    const DATA: &[u8] = b"data to be signed";

    fn parse_sign_response(response: &[u8]) -> ssh_key::Signature {
        let (&msg_type, mut body) = response.split_first().unwrap();
        assert_eq!(msg_type, SSH_AGENT_SIGN_RESPONSE);
        let blob = Vec::<u8>::decode(&mut body).unwrap();
        assert!(body.is_empty());
        ssh_key::Signature::decode(&mut blob.as_slice()).unwrap()
    }

    #[test]
    fn identities() {
        let response = identities_answer(&[
            ED25519_PUBLIC.to_string(),
            ECDSA_PUBLIC.to_string(),
            RSA_PUBLIC.to_string(),
        ])
        .unwrap();
        let (&msg_type, mut body) = response.split_first().unwrap();
        assert_eq!(msg_type, SSH_AGENT_IDENTITIES_ANSWER);
        // the unsupported ecdsa key is skipped
        assert_eq!(u32::decode(&mut body).unwrap(), 2);
        for public_key in [ED25519_PUBLIC, RSA_PUBLIC] {
            let blob = Vec::<u8>::decode(&mut body).unwrap();
            assert_eq!(
                blob,
                ssh_key::PublicKey::from_openssh(public_key)
                    .unwrap()
                    .to_bytes()
                    .unwrap()
            );
            assert_eq!(String::decode(&mut body).unwrap(), "");
        }
        assert!(body.is_empty());
    }

    #[test]
    fn sign_rsa_sha1_unsupported() {
        let key = ssh_key::PrivateKey::from_openssh(RSA_PRIVATE).unwrap();
        assert!(sign_response(&key, DATA, 0).is_err());
    }

    #[test]
    fn sign_ed25519() {
        let key = ssh_key::PrivateKey::from_openssh(ED25519_PRIVATE).unwrap();
        let signature =
            parse_sign_response(&sign_response(&key, DATA, 0).unwrap());
        assert_eq!(signature.algorithm().as_str(), "ssh-ed25519");
        key.public_key()
            .key_data()
            .verify(DATA, &signature)
            .unwrap();
    }

    #[test]
    fn sign_rsa_sha2() {
        let key = ssh_key::PrivateKey::from_openssh(RSA_PRIVATE).unwrap();
        for (flags, algorithm) in [
            (SSH_AGENT_RSA_SHA2_256, "rsa-sha2-256"),
            (SSH_AGENT_RSA_SHA2_512, "rsa-sha2-512"),
        ] {
            let signature = parse_sign_response(
                &sign_response(&key, DATA, flags).unwrap(),
            );
            assert_eq!(signature.algorithm().as_str(), algorithm);
            key.public_key()
                .key_data()
                .verify(DATA, &signature)
                .unwrap();
        }
    }
}
