//! Memory-only secret bytes that never serialize, log or clone.

use zeroize::Zeroize;

/// Memory-only secret. Dropping it overwrites its allocation before release.
///
/// It intentionally implements neither `Clone`, `Debug`, nor serde traits.
///
/// ```compile_fail
/// use vortix::core::ids::Secret;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<Secret>();
/// ```
///
/// ```compile_fail
/// use vortix::core::ids::Secret;
/// let secret = Secret::new(b"answer".to_vec());
/// let _ = serde_json::to_string(&secret);
/// ```
pub struct Secret(Box<[u8]>);

impl Secret {
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into().into_boxed_slice())
    }

    /// Borrow credential bytes only at the final in-process protocol boundary.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Transfer through an existing byte-oriented local client boundary.
    /// The source allocation is cleared before this value is returned; the
    /// receiver must immediately re-wrap the returned bytes in `Secret`.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        let bytes = self.0.to_vec();
        self.clear();
        bytes
    }

    fn clear(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.clear();
    }
}
