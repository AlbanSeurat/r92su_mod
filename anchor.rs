use core::mem::MaybeUninit;
use kernel::bindings;

// Per-type lockdep keys for the wait queue and spinlock inside usb_anchor.
static mut WAIT_KEY: MaybeUninit<bindings::lock_class_key> = MaybeUninit::zeroed();
static mut LOCK_KEY: MaybeUninit<bindings::lock_class_key> = MaybeUninit::zeroed();

pub struct UsbAnchor(bindings::usb_anchor);

// SAFETY: usb_anchor uses a spinlock internally — safe to send across threads
unsafe impl Send for UsbAnchor {}
unsafe impl Sync for UsbAnchor {}

impl UsbAnchor {
    pub fn new() -> Self {
        let mut anchor = bindings::usb_anchor::default();
        // Replicate init_usb_anchor() manually:
        // 1. init_waitqueue_head(&anchor->wait)
        // SAFETY: WAIT_KEY and LOCK_KEY are module-lifetime statics; anchor is
        // local and not yet shared, so exclusive access is guaranteed here.
        unsafe {
            bindings::__init_waitqueue_head(
                &mut anchor.wait,
                b"usb_anchor::wait\0".as_ptr(),
                WAIT_KEY.as_mut_ptr(),
            );
            // 2. spin_lock_init(&anchor->lock)
            bindings::__spin_lock_init(
                &mut anchor.lock,
                b"usb_anchor::lock\0".as_ptr() as *const kernel::ffi::c_char,
                LOCK_KEY.as_mut_ptr(),
            );
        }
        Self(anchor)
    }

    /// Call before usb_submit_urb()
    pub fn anchor_urb(&mut self, urb: &mut bindings::urb) {
        unsafe { bindings::usb_anchor_urb(urb, &mut self.0) };
    }

    /// Call if submit failed, to detach
    pub fn unanchor_urb(&mut self, urb: &mut bindings::urb) {
        unsafe { bindings::usb_unanchor_urb(urb) };
    }

    /// Block until all URBs complete (timeout in ms)
    pub fn wait_empty(&mut self, timeout_ms: u32) -> bool {
        unsafe { bindings::usb_wait_anchor_empty_timeout(&mut self.0, timeout_ms) != 0 }
    }

    /// Kill all in-flight URBs — synchronous
    pub fn kill_anchored_urbs(&mut self) {
        unsafe { bindings::usb_kill_anchored_urbs(&mut self.0) };
    }

    /// Poison — also rejects future anchoring
    pub fn poison(&mut self) {
        unsafe { bindings::usb_poison_anchored_urbs(&mut self.0) };
    }

    pub fn is_empty(&mut self) -> bool {
        unsafe { bindings::usb_anchor_empty(&mut self.0) != 0 }
    }
}

impl Drop for UsbAnchor {
    fn drop(&mut self) {
        // Always drain on drop — never leave in-flight URBs dangling
        self.kill_anchored_urbs();
    }
}
