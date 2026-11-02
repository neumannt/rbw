use zeroize::Zeroize as _;

const LEN: usize = 4096;

static REGION_LOCK_WORKS: std::sync::OnceLock<bool> =
    std::sync::OnceLock::new();

pub struct Vec {
    data: Pages,
    len: usize,
}

impl Default for Vec {
    fn default() -> Self {
        let mut data = Pages::new(LEN);
        match REGION_LOCK_WORKS.get() {
            Some(true) => data.lock().unwrap(),
            Some(false) => {}
            None => match data.lock() {
                Ok(()) => {
                    let _ = REGION_LOCK_WORKS.set(true);
                }
                Err(e) => {
                    if REGION_LOCK_WORKS.set(false).is_ok() {
                        eprintln!("failed to lock memory region: {e}");
                    }
                }
            },
        }
        Self { data, len: 0 }
    }
}

// a zeroed allocation consisting of whole pages, which is zeroed again (and
// unlocked, if it was locked into ram) when dropped. memory locks don't nest,
// so this ensures that unlocking it can never unlock a page that is shared
// with another locked allocation.
struct Pages {
    ptr: std::ptr::NonNull<u8>,
    layout: std::alloc::Layout,
    locked: bool,
}

// SAFETY: Pages uniquely owns its allocation, like a Box
unsafe impl Send for Pages {}
// SAFETY: as above
unsafe impl Sync for Pages {}

impl Pages {
    fn new(len: usize) -> Self {
        assert!(len > 0);
        let page_size = rustix::param::page_size();
        let layout = std::alloc::Layout::from_size_align(
            len.next_multiple_of(page_size),
            page_size,
        )
        .unwrap();
        // SAFETY: the layout has a nonzero size
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        let ptr = std::ptr::NonNull::new(ptr)
            .unwrap_or_else(|| std::alloc::handle_alloc_error(layout));
        Self {
            ptr,
            layout,
            locked: false,
        }
    }

    fn lock(&mut self) -> std::io::Result<()> {
        // SAFETY: mlock doesn't access the memory, and the range is exactly
        // our allocation, which is page aligned
        unsafe {
            rustix::mm::mlock(self.ptr.as_ptr().cast(), self.layout.size())
        }?;
        self.locked = true;
        Ok(())
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: the allocation is initialized (zeroed in new), and is
        // owned by self
        unsafe {
            std::slice::from_raw_parts(self.ptr.as_ptr(), self.layout.size())
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, and we have exclusive access through &mut self
        unsafe {
            std::slice::from_raw_parts_mut(
                self.ptr.as_ptr(),
                self.layout.size(),
            )
        }
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        self.as_mut_slice().zeroize();
        if self.locked {
            // SAFETY: this is the same range that was locked in lock
            let _ = unsafe {
                rustix::mm::munlock(
                    self.ptr.as_ptr().cast(),
                    self.layout.size(),
                )
            };
        }
        // SAFETY: ptr was allocated in new with the same layout
        unsafe { std::alloc::dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

impl Vec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data(&self) -> &[u8] {
        &self.data.as_slice()[..self.len]
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut_slice()[..self.len]
    }

    // zeroes the whole buffer, and extends the length to cover all of it
    pub fn zero(&mut self) {
        self.data.as_mut_slice()[..LEN].zeroize();
        self.len = LEN;
    }

    pub fn extend(&mut self, mut it: impl Iterator<Item = u8>) {
        let free = &mut self.data.as_mut_slice()[self.len..LEN];
        // zip takes from free first, so no bytes are lost from it when free
        // runs out
        let mut n = 0;
        for (dst, byte) in free.iter_mut().zip(&mut it) {
            *dst = byte;
            n += 1;
        }
        self.len += n;
        assert!(it.next().is_none(), "locked::Vec capacity exceeded");
    }

    pub fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vec() {
        let mut vec = Vec::new();
        assert_eq!(vec.data(), b"");
        vec.extend(b"secret".iter().copied());
        assert_eq!(vec.data(), b"secret");
        vec.truncate(3);
        assert_eq!(vec.data(), b"sec");
        vec.truncate(10);
        assert_eq!(vec.data(), b"sec");
        assert_eq!(vec.clone().data(), b"sec");

        // the pattern used when reading into the buffer
        vec.zero();
        assert_eq!(vec.data(), &[0; LEN][..]);
        vec.data_mut()[..4].copy_from_slice(b"read");
        vec.truncate(4);
        assert_eq!(vec.data(), b"read");

        vec.extend(std::iter::repeat_n(b'x', LEN - 4));
        assert_eq!(vec.data().len(), LEN);
    }

    #[test]
    #[should_panic(expected = "capacity exceeded")]
    fn test_vec_overflow() {
        let mut vec = Vec::new();
        vec.extend(std::iter::repeat_n(0, LEN + 1));
    }

    #[test]
    fn test_pages() {
        let page_size = rustix::param::page_size();
        let pages = Pages::new(1);
        #[allow(clippy::as_conversions)]
        let addr = pages.ptr.as_ptr() as usize;
        assert_eq!(addr % page_size, 0);
        assert_eq!(pages.as_slice().len(), page_size);
        assert!(pages.as_slice().iter().all(|&b| b == 0));
    }
}
