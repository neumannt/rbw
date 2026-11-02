use zeroize::Zeroize as _;

const LEN: usize = 4096;

static REGION_LOCK_WORKS: std::sync::OnceLock<bool> =
    std::sync::OnceLock::new();

pub struct Vec {
    data: Box<arrayvec::ArrayVec<u8, LEN>>,
    _lock: Option<MemoryLock>,
}

impl Default for Vec {
    fn default() -> Self {
        let data = Box::new(arrayvec::ArrayVec::<_, LEN>::new());
        let lock = match REGION_LOCK_WORKS.get() {
            Some(true) => {
                Some(MemoryLock::new(data.as_ptr(), data.capacity()).unwrap())
            }
            Some(false) => None,
            None => match MemoryLock::new(data.as_ptr(), data.capacity()) {
                Ok(lock) => {
                    let _ = REGION_LOCK_WORKS.set(true);
                    Some(lock)
                }
                Err(e) => {
                    if REGION_LOCK_WORKS.set(false).is_ok() {
                        eprintln!("failed to lock memory region: {e}");
                    }
                    None
                }
            },
        };
        Self { data, _lock: lock }
    }
}

// a range of memory locked into ram, which is unlocked again when dropped
struct MemoryLock {
    ptr: *mut std::ffi::c_void,
    len: usize,
}

// SAFETY: the pointer is never dereferenced, only used to unlock the range
unsafe impl Send for MemoryLock {}
// SAFETY: as above
unsafe impl Sync for MemoryLock {}

impl MemoryLock {
    fn new(ptr: *const u8, len: usize) -> std::io::Result<Self> {
        // posix allows mlock to require page aligned ranges
        let page_size = rustix::param::page_size();
        #[allow(clippy::as_conversions)]
        let offset = (ptr as usize) % page_size;
        let ptr = ptr.wrapping_sub(offset).cast_mut().cast();
        let len = (len + offset).next_multiple_of(page_size);
        // SAFETY: mlock doesn't access the memory, and the range covers only
        // whole pages containing our allocation
        unsafe { rustix::mm::mlock(ptr, len) }?;
        Ok(Self { ptr, len })
    }
}

impl Drop for MemoryLock {
    fn drop(&mut self) {
        // SAFETY: this is the same range that was locked in new
        let _ = unsafe { rustix::mm::munlock(self.ptr, self.len) };
    }
}

impl Vec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    pub fn zero(&mut self) {
        self.truncate(0);
        self.data.extend(std::iter::repeat_n(0, LEN));
    }

    pub fn extend(&mut self, it: impl Iterator<Item = u8>) {
        self.data.extend(it);
    }

    pub fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
    }
}

impl Drop for Vec {
    fn drop(&mut self) {
        self.zero();
        self.data.as_mut().zeroize();
    }
}

impl Clone for Vec {
    fn clone(&self) -> Self {
        let mut new_vec = Self::new();
        new_vec.extend(self.data().iter().copied());
        new_vec
    }
}

#[derive(Clone)]
pub struct Password {
    password: Vec,
}

impl Password {
    pub fn new(password: Vec) -> Self {
        Self { password }
    }

    pub fn password(&self) -> &[u8] {
        self.password.data()
    }
}

#[derive(Clone)]
pub struct Keys {
    keys: Vec,
}

impl Keys {
    pub fn new(keys: Vec) -> Self {
        Self { keys }
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.keys.data()[0..32]
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.keys.data()[32..64]
    }
}

#[derive(Clone)]
pub struct PasswordHash {
    hash: Vec,
}

impl PasswordHash {
    pub fn new(hash: Vec) -> Self {
        Self { hash }
    }

    pub fn hash(&self) -> &[u8] {
        self.hash.data()
    }
}

#[derive(Clone)]
pub struct PrivateKey {
    private_key: Vec,
}

impl PrivateKey {
    pub fn new(private_key: Vec) -> Self {
        Self { private_key }
    }

    pub fn private_key(&self) -> &[u8] {
        self.private_key.data()
    }
}

#[derive(Clone)]
pub struct ApiKey {
    client_id: Password,
    client_secret: Password,
}

impl ApiKey {
    pub fn new(client_id: Password, client_secret: Password) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }

    pub fn client_id(&self) -> &[u8] {
        self.client_id.password()
    }

    pub fn client_secret(&self) -> &[u8] {
        self.client_secret.password()
    }
}
