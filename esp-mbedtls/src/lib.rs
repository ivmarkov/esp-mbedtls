#![no_std]

extern crate alloc;

use alloc::boxed::Box;

use core::alloc::Layout;
use core::cell::Cell;
use core::ffi::{c_int, c_uchar, c_ulong, c_void, CStr};
use core::fmt;
use core::marker::PhantomData;
use core::mem::MaybeUninit;

use critical_section::Mutex;

use embedded_io::{ErrorKind, ErrorType};

use log::Level;

use embedded_io::Read;
use embedded_io::Write;

use esp_mbedtls_sys::bindings::*;

// For 'random` which is provided by `esp-wifi` on baremetal
#[cfg(any(
    feature = "esp32",
    feature = "esp32c3",
    feature = "esp32s2",
    feature = "esp32s3"
))]
use esp_wifi as _;

#[cfg(feature = "edge-nal")]
mod edge_nal;
#[cfg(any(
    feature = "esp32",
    feature = "esp32c3",
    feature = "esp32s2",
    feature = "esp32s3"
))]
mod esp_hal;

/// Re-export of the `embedded-io` crate so that users don't have to explicitly depend on it
/// to use e.g. `write_all` or `read_exact`.
pub mod io {
    pub use embedded_io::*;
}

// Baremetal: these will come from `esp-wifi` (i.e. this can only be used together with esp-wifi)
// STD: these will come from `libc` indirectly via the Rust standard library
// TODO: Retire this
extern "C" {
    fn random() -> c_ulong;
}

macro_rules! mbed {
    ($block:expr) => {{
        let res = $block;
        if res != 0 {
            Err(TlsError::MbedTlsError(res))
        } else {
            Ok(())
        }
    }};
}

/// The mode of operation of a TLS `Session` instance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode<'a> {
    /// Client mode
    Client {
        /// The server name to check against the received server certificate.
        servername: &'a CStr,
    },
    /// Server mode
    Server,
}

impl Mode<'_> {
    fn to_mbed_tls(&self) -> i32 {
        match self {
            Mode::Client { .. } => MBEDTLS_SSL_IS_CLIENT as i32,
            Mode::Server => MBEDTLS_SSL_IS_SERVER as i32,
        }
    }
}

/// The minimum TLS version that will be supported by a particular `Session` instance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    /// TLS 1.2
    Tls1_2,
    /// TLS 1.3
    Tls1_3,
}

impl TlsVersion {
    fn to_mbed_tls_version(&self) -> u32 {
        match self {
            TlsVersion::Tls1_2 => 0x303,
            TlsVersion::Tls1_3 => 0x304,
        }
    }
}

/// Error type for TLS operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    /// A `Tls` instance has already been created
    AlreadyCreated,
    /// An unknown error occurred
    Unknown,
    /// Out of heap
    OutOfMemory,
    /// MBedTLS error
    MbedTlsError(i32),
    /// End of stream
    Eof,
    /// X509 certificate missing null terminator
    X509MissingNullTerminator,
    /// The client has given no certificates for the request
    NoClientCertificate,
    /// IO error
    Io(ErrorKind),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyCreated => write!(f, "TLS already created"),
            Self::Unknown => write!(f, "Unknown error"),
            Self::OutOfMemory => write!(f, "Out of memory"),
            Self::MbedTlsError(e) => write!(f, "MbedTLS error: {e}"),
            Self::Eof => write!(f, "End of stream"),
            Self::X509MissingNullTerminator => {
                write!(f, "X509 certificate missing null terminator")
            }
            Self::NoClientCertificate => write!(f, "No client certificate"),
            Self::Io(e) => write!(f, "IO error: {e:?}"),
        }
    }
}

impl embedded_io::Error for TlsError {
    fn kind(&self) -> embedded_io::ErrorKind {
        match self {
            Self::Io(e) => *e,
            _ => embedded_io::ErrorKind::Other,
        }
    }
}

/// Format type for [X509]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CertificateFormat {
    PEM,
    DER,
}

/// Holds a X509 certificate
///
/// # Examples
/// Initialize with a PEM certificate
/// ```
/// const CERTIFICATE: &[u8] = include_bytes!("certificate.pem");
/// let cert = X509::pem(CERTIFICATE).unwrap();
/// ```
///
/// Initialize with a DER certificate
/// ```
/// const CERTIFICATE: &[u8] = include_bytes!("certificate.der");
/// let cert = X509::der(CERTIFICATE);
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct X509<'a> {
    bytes: &'a [u8],
    format: CertificateFormat,
}

impl<'a> X509<'a> {
    /// Reads certificate in pem format from bytes
    ///
    /// # Error
    /// This function returns [TlsError::X509MissingNullTerminator] if the certificate
    /// doesn't end with a null-byte.
    pub fn pem(bytes: &'a [u8]) -> Result<Self, TlsError> {
        if let Some(len) = X509::get_null(bytes) {
            // Get a slice of only the certificate bytes including the \0
            let bytes = unsafe { core::slice::from_raw_parts(bytes.as_ptr(), len + 1) };
            Ok(Self {
                bytes,
                format: CertificateFormat::PEM,
            })
        } else {
            Err(TlsError::X509MissingNullTerminator)
        }
    }

    /// Reads certificate in der format from bytes
    ///
    /// *Note*: This function assumes that the size of the size is the exact
    /// length of the certificate
    pub fn der(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            format: CertificateFormat::DER,
        }
    }

    /// Returns the bytes of the certificate
    pub fn data(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the length of the certificate
    pub(crate) fn len(&self) -> usize {
        self.data().len()
    }

    /// Returns a pointer to the data for parsing
    pub(crate) fn as_ptr(&self) -> *const c_uchar {
        self.data().as_ptr().cast()
    }

    /// Gets the first null byte in a slice
    fn get_null(bytes: &[u8]) -> Option<usize> {
        bytes.iter().position(|&byte| byte == 0)
    }
}

/// A TLS self-test type
#[derive(enumset::EnumSetType, Debug)]
pub enum TlsTest {
    Mpi,
    Rsa,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Aes,
    Md5,
}

impl fmt::Display for TlsTest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsTest::Mpi => write!(f, "MPI"),
            TlsTest::Rsa => write!(f, "RSA"),
            TlsTest::Sha1 => write!(f, "SHA1"),
            TlsTest::Sha224 => write!(f, "SHA224"),
            TlsTest::Sha256 => write!(f, "SHA256"),
            TlsTest::Sha384 => write!(f, "SHA384"),
            TlsTest::Sha512 => write!(f, "SHA512"),
            TlsTest::Aes => write!(f, "AES"),
            TlsTest::Md5 => write!(f, "MD5"),
        }
    }
}

static TLS_CREATED: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));

// TODO: Lower to `u32` for Riscv32
type BlockSize = u64;

const BLOCK_SIZE: usize = core::mem::size_of::<BlockSize>();
const BLOCK_ALIGN: usize = core::mem::align_of::<BlockSize>();

/// A TLS instance
///
/// Represents an instance of the MbedTLS library.
/// Only one such instance can be active at any point in time.
pub struct Tls<'d>(PhantomData<&'d mut ()>);

impl<'d> Tls<'d> {
    /// Create a new instance of the `Tls` type.
    ///
    /// Note that there could be only one active `Tls` instance at any point in time,
    /// and the function will return an error if there is already an active instance.
    #[cfg(all(not(any(
        feature = "esp32",
        feature = "esp32c3",
        feature = "esp32s2",
        feature = "esp32s3"
    ))))]
    pub fn new() -> Result<Self, TlsError> {
        Self::create()
    }

    pub(crate) fn create() -> Result<Self, TlsError> {
        critical_section::with(|cs| {
            let created = TLS_CREATED.borrow(cs).get();

            if created {
                return Err(TlsError::AlreadyCreated);
            }

            TLS_CREATED.borrow(cs).set(true);

            unsafe { mbedtls_platform_set_calloc_free(Some(Self::calloc), Some(Self::free)); }

            Ok(Self(PhantomData))
        })
    }

    /// Set the MbedTLS debug level (0 - 5)
    #[allow(unused)]
    pub fn set_debug(&mut self, level: u32) {
        #[cfg(not(target_os = "espidf"))]
        unsafe {
            mbedtls_debug_set_threshold(level as c_int);
        }
    }

    /// Run a self-test on the MbedTLS library
    ///
    /// # Arguments
    ///
    /// * `test` - The test to run
    /// * `verbose` - Whether to run the test in verbose mode
    pub fn self_test(&mut self, test: TlsTest, verbose: bool) -> bool {
        let verbose = verbose as _;

        let result = unsafe {
            match test {
                TlsTest::Mpi => mbedtls_mpi_self_test(verbose),
                TlsTest::Rsa => mbedtls_rsa_self_test(verbose),
                TlsTest::Sha1 => mbedtls_sha1_self_test(verbose),
                TlsTest::Sha224 => mbedtls_sha224_self_test(verbose),
                TlsTest::Sha256 => mbedtls_sha256_self_test(verbose),
                TlsTest::Sha384 => mbedtls_sha384_self_test(verbose),
                TlsTest::Sha512 => mbedtls_sha512_self_test(verbose),
                TlsTest::Aes => mbedtls_aes_self_test(verbose),
                TlsTest::Md5 => mbedtls_md5_self_test(verbose),
            }
        };

        result != 0
    }

    /// Get a reference to the `Tls` instance
    ///
    /// Each `Session` needs a reference to (the) active `Tls` instance
    /// throughout its lifetime.
    pub fn reference(&self) -> TlsReference<'_> {
        TlsReference(PhantomData)
    }

    unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut c_void {
        let Some(total_size) = count.checked_mul(size) else {
            return core::ptr::null_mut();
        };

        let Some(total_size_prefixed) = total_size.checked_add(BLOCK_SIZE) else {
            return core::ptr::null_mut();
        };

        let layout = Layout::from_size_align(total_size_prefixed, BLOCK_ALIGN).unwrap();

        let ptr = alloc::alloc::alloc_zeroed(layout);

        let size_ptr = ptr as *mut BlockSize;
        unsafe { core::ptr::write(size_ptr, total_size_prefixed as _); }

        ptr.add(BLOCK_SIZE) as *mut _
    }

    unsafe extern "C" fn free(ptr: *mut c_void) {
        let ptr = ptr.sub(BLOCK_SIZE) as *mut u8;

        let size_ptr = ptr as *mut BlockSize;

        let total_size_prefixed = unsafe { core::ptr::read(size_ptr) } as _;

        let layout = Layout::from_size_align(total_size_prefixed, BLOCK_ALIGN).unwrap();

        alloc::alloc::dealloc(ptr, layout);
    }
}

impl Drop for Tls<'_> {
    fn drop(&mut self) {
        unsafe { mbedtls_platform_set_calloc_free(None, None); }

        critical_section::with(|cs| {
            TLS_CREATED.borrow(cs).set(false);
        });
    }
}

/// A reference to (the) active `Tls` instance
///
/// Used instead of just `&'a Tls` so that the invariant `'d` lifetime of the `Tls` instance
/// is not exposed in the `Session` type.
#[allow(unused)]
#[derive(Debug, Copy, Clone)]
pub struct TlsReference<'a>(PhantomData<&'a ()>);

/// A type representing the certificate chain for a TLS connection
pub struct CaCertificate {
    cert: mbedtls_x509_crt,
}

impl CaCertificate {
    /// Initialize a new `CaCertificate` instance
    /// 
    /// # Arguments
    /// - `this` - A `MaybeUninit` instance to initialize
    /// 
    /// # Returns
    /// A boxed `CaCertificate` instance
    pub fn init(mut this: Box<MaybeUninit<Self>>) -> Box<Self> {
        Self::init_mut(&mut this);

        unsafe { this.assume_init() }
    }

    /// Initialize a `MaybeUninit` `CaCertificate` instance
    /// 
    /// # Arguments
    /// - `this` - A `MaybeUninit` instance to initialize
    /// 
    /// # Returns
    /// A mutable reference to the initialized `CaCertificate` instance
    pub fn init_mut(this: &mut MaybeUninit<Self>) -> &mut Self {
        unsafe {
            let this = this.assume_init_mut();

            mbedtls_x509_crt_init(&mut this.cert);

            this
        }
    }

    /// Load a `X509` representation of a certificate (DER or PEM) into the `CaCertificate` instance
    pub fn load(&mut self, cert: X509) -> Result<(), TlsError> {
        match cert.format {
            CertificateFormat::PEM => mbed!(unsafe { mbedtls_x509_crt_parse(&mut self.cert, cert.as_ptr(), cert.len()) }),
            CertificateFormat::DER => mbed!(unsafe { mbedtls_x509_crt_parse_der_nocopy(&mut self.cert, cert.as_ptr(), cert.len()) }),
        }
    }
}

impl Drop for CaCertificate {
    fn drop(&mut self) {
        unsafe {
            mbedtls_x509_crt_free(&mut self.cert);
        }
    }
}

/// A type representing an own certificate and its private key
pub struct OwnCertificate {
    cert: mbedtls_x509_crt,
    pk: mbedtls_pk_context,
}

impl OwnCertificate {
    /// Initialize a new `OwnCertificate` instance
    /// 
    /// # Arguments
    /// - `this` - A `MaybeUninit` instance to initialize
    /// 
    /// # Returns
    /// A boxed `OwnCertificate` instance
    pub fn init(mut this: Box<MaybeUninit<Self>>) -> Box<Self> {
        Self::init_mut(&mut this);

        unsafe { this.assume_init() }
    }

    fn init_mut(this: &mut MaybeUninit<Self>) -> &mut Self {
        unsafe {
            let this = this.assume_init_mut();

            mbedtls_x509_crt_init(&mut this.cert);
            mbedtls_pk_init(&mut this.pk);

            this
        }
    }

    /// Load a `X509` representation of a certificate (DER or PEM) and a private key into the `OwnCertificate` instance
    /// 
    /// # Arguments
    /// - `cert` - The `X509` representation of a certificate (DER or PEM) to load into the `OwnCertificate` instance
    /// - `pk` - The `X509` representation of a private key to load into the `OwnCertificate` instance
    /// - `password` - The password for the private key, if any
    pub fn load(&mut self, cert: X509, pk: X509, password: Option<&str>) -> Result<(), TlsError> {
        match cert.format {
            CertificateFormat::PEM => mbed!(unsafe { mbedtls_x509_crt_parse(&mut self.cert, cert.as_ptr(), cert.len()) }),
            CertificateFormat::DER => mbed!(unsafe { mbedtls_x509_crt_parse_der_nocopy(&mut self.cert, cert.as_ptr(), cert.len()) }),
        }?;

        mbed!(unsafe {
            mbedtls_pk_parse_key(
                &mut self.pk,
                pk.as_ptr(),
                pk.len(),
                password.map_or(core::ptr::null(), |p| p.as_ptr()),
                password.map_or(0, |p| p.len()),
                None,
                core::ptr::null_mut(),
            )
        })
    }
}

impl Drop for OwnCertificate {
    fn drop(&mut self) {
        unsafe {
            mbedtls_x509_crt_free(&mut self.cert);
            mbedtls_pk_free(&mut self.pk);
        }
    }
}

/// A TLS session context
struct SessionCtx<'a> {
    drbg: mbedtls_ctr_drbg_context,
    ssl_context: mbedtls_ssl_context,
    ssl_config: mbedtls_ssl_config,
    _p: PhantomData<&'a ()>,
}

impl<'a> SessionCtx<'a> {
    /// Create a new `SessionCtx` instance
    /// 
    /// # Arguments
    /// - `mode` - The mode of operation of the TLS session
    /// - `min_version` - The minimum TLS version that will be supported by the TLS session
    /// - `ca_cert` - The certificate chain for the connection, if any
    /// - `own_cert` - The certificate and private key for the connection, if any
    fn new(        
        mode: Mode,
        min_version: TlsVersion,
        ca_cert: Option<&'a CaCertificate>, 
        own_cert: Option<&'a OwnCertificate>,
    ) -> Result<Box<Self>, TlsError> {
        let mut this = Self::init(Box::new_uninit());

        this.setup(mode, min_version, ca_cert, own_cert)?;

        Ok(this)
    }

    /// Initialize a new `SessionCtx` instance
    /// 
    /// # Arguments
    /// - `this` - A `MaybeUninit` instance to initialize
    /// 
    /// # Returns
    /// A boxed `SessionCtx` instance
    fn init(mut this: Box<MaybeUninit<Self>>) -> Box<Self> {
        unsafe {
            Self::init_mut(&mut this);
        
            this.assume_init()
        }
    }

    /// Setup the boxed `SessionCtx` instance
    /// 
    /// # Arguments
    /// - `mode` - The mode of operation of the TLS session
    /// - `min_version` - The minimum TLS version that will be supported by the TLS session
    /// - `ca_cert` - The certificate chain for the connection, if any
    /// - `own_cert` - The certificate and private key for the connection, if any
    fn setup(
        self: &mut Box<Self>, 
        mode: Mode,
        min_version: TlsVersion,
        ca_cert: Option<&CaCertificate>, 
        own_cert: Option<&OwnCertificate>,
    ) -> Result<(), TlsError> {
        mbed!(unsafe { mbedtls_ssl_setup(&mut self.ssl_context, &mut self.ssl_config) })?;

        mbed!(unsafe {
            mbedtls_ssl_config_defaults(
                &mut self.ssl_config,
                mode.to_mbed_tls(),
                MBEDTLS_SSL_TRANSPORT_STREAM as i32,
                MBEDTLS_SSL_PRESET_DEFAULT as i32,
            )
        })?;

        // Set the minimum TLS version
        // Use a ddirect field modified for compatibility with the `esp-idf-svc` mbedtls
        self.ssl_config.private_min_tls_version = min_version.to_mbed_tls_version();

        unsafe {
            mbedtls_ssl_conf_authmode(
                &mut self.ssl_config,
                if ca_cert.is_some() {
                    MBEDTLS_SSL_VERIFY_REQUIRED as i32
                } else {
                    // Use this config when in server mode
                    // Ref: https://os.mbed.com/users/markrad/code/mbedtls/docs/tip/ssl_8h.html#a5695285c9dbfefec295012b566290f37
                    MBEDTLS_SSL_VERIFY_NONE as i32
                },
            );
        }

        if let Mode::Client { servername } = mode {
            mbed!(unsafe {
                mbedtls_ssl_set_hostname(&mut self.ssl_context, servername.as_ptr())
            })?;
        }

        if let Some(ca_cert) = ca_cert {
            unsafe {
                mbedtls_ssl_conf_ca_chain(&mut self.ssl_config, &ca_cert.cert as *const _ as *mut _, core::ptr::null_mut());
            }
        }

        if let Some(own_cert) = own_cert {
            unsafe {
                mbedtls_ssl_conf_own_cert(&mut self.ssl_config, &own_cert.cert as *const _ as *mut _, &own_cert.pk as *const _ as *mut _);
            }
        }

        Ok(())
    }

    unsafe fn init_mut(this: &mut MaybeUninit<Self>) -> &mut Self {
        let this = this.assume_init_mut();

        mbedtls_ssl_init(&mut this.ssl_context);
        mbedtls_ssl_config_init(&mut this.ssl_config);
        mbedtls_ctr_drbg_init(&mut this.drbg);

        // Init debug print
        mbedtls_ssl_conf_dbg(&mut this.ssl_config, Some(dbg_print), core::ptr::null_mut());

        // Init RNG
        mbedtls_ssl_conf_rng(&mut this.ssl_config, Some(rng), &mut this.drbg as *mut _ as *mut c_void);

        this
    }
}

impl Drop for SessionCtx<'_> {
    fn drop(&mut self) {
        unsafe {
            mbedtls_ssl_config_free(&mut self.ssl_config);
            mbedtls_ssl_free(&mut self.ssl_context);
            mbedtls_ctr_drbg_free(&mut self.drbg);
        }
    }
}

/// A TLS session state
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
enum SessionState {
    /// Initial state (TLS handshake not started yet)
    Initial,
    /// Handshake complete
    Connected,
    /// End of stream reached
    Eof,
}

/// A blocking TLS session over a stream represented by `embedded-io`'s `Read` and `Write` traits.
pub struct Session<'a, T> {
    stream: T,
    ctx: Box<SessionCtx<'a>>,
    state: SessionState,
    _tls_ref: TlsReference<'a>,
}

impl<'a, T> Session<'a, T> {
    /// Create a session for a TLS stream.
    ///
    /// # Arguments
    ///
    /// * `stream` - The stream for the connection.
    /// * `mode` - Use [Mode::Client] if you are running a client. [Mode::Server] if you are
    ///   running a server.
    /// * `min_version` - The minimum TLS version for the connection, that will be accepted.
    /// * `ca_cert` - The CA certificate chain for the connection, if any
    /// * `own_cert` - The own certificate and private key for the connection, if any
    /// * `tls_ref` - A reference to the active `Tls` instance.
    ///
    /// # Errors
    ///
    /// This will return a [TlsError] if there were an error during the initialization of the
    /// session. This can happen if there is not enough memory of if the certificates are in an
    /// invalid format.
    pub fn new(
        stream: T,
        mode: Mode,
        min_version: TlsVersion,
        ca_cert: Option<&'a CaCertificate>,
        own_cert: Option<&'a OwnCertificate>,
        tls_ref: TlsReference<'a>,
    ) -> Result<Self, TlsError> {
        Ok(Self {
            stream,
            ctx: SessionCtx::new(mode, min_version, ca_cert, own_cert)?,
            state: SessionState::Initial,
            _tls_ref: tls_ref,
        })
    }
}

impl<'a, T> Session<'a, T>
where
    T: Read + Write,
{
    /// Negotiate the TLS connection
    ///
    /// This function will perform the TLS handshake with the server.
    ///
    /// Note that calling it is not mandatory, because the TLS session is anyway
    /// negotiated during the first read or write operation.
    pub fn connect(&mut self) -> Result<(), TlsError> {
        if matches!(self.state, SessionState::Connected) {
            return Ok(());
        } else if matches!(self.state, SessionState::Eof) {
            return Err(TlsError::Eof);
        }

        unsafe {
            mbedtls_ssl_set_bio(
                &mut self.ctx.ssl_context,
                self as *mut _ as *mut c_void,
                Some(Self::send),
                Some(Self::receive),
                None,
            );

            loop {
                let res = mbedtls_ssl_handshake(&mut self.ctx.ssl_context);
                log::debug!("mbedtls_ssl_handshake: {res:x}");
                if res == 0 {
                    // success
                    break;
                }
                if res < 0 && res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE
                    // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                    && res != MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
                {
                    // real error
                    // Reference: https://os.mbed.com/teams/sandbox/code/mbedtls/docs/tip/ssl_8h.html#a4a37e497cd08c896870a42b1b618186e
                    mbedtls_ssl_session_reset(&mut self.ctx.ssl_context);
                    #[allow(non_snake_case)]
                    return Err(match res {
                        MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE => TlsError::NoClientCertificate,
                        _ => TlsError::MbedTlsError(res),
                    });
                }

                // try again immediately
            }

            self.state = SessionState::Connected;

            Ok(())
        }
    }

    /// Read unencrypted data from the TLS connection
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to read the data into
    ///
    /// # Returns
    ///
    /// The number of bytes read or an error
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        self.connect()?;

        loop {
            let res = self.internal_read(buf);
            #[allow(non_snake_case)]
            match res {
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_WANT_READ | MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue, // no data
                0_i32..=i32::MAX => return Ok(res as usize), // data
                i32::MIN..=-1_i32 => return Err(TlsError::MbedTlsError(res)), // error
            }
        }
    }

    /// Write unencrypted data to the TLS connection
    ///
    /// Arguments:
    ///
    /// * `data` - The data to write
    ///
    /// Returns:
    ///
    /// The number of bytes written or an error
    pub fn write(&mut self, data: &[u8]) -> Result<usize, TlsError> {
        self.connect()?;

        loop {
            let res = self.internal_write(data);
            #[allow(non_snake_case)]
            match res {
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_WANT_WRITE | MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => {
                    continue
                } // no data
                0_i32..=i32::MAX => return Ok(res as usize), // data
                i32::MIN..=-1_i32 => return Err(TlsError::MbedTlsError(res)), // error
            }
        }
    }

    /// Flush the TLS connection
    ///
    /// This function will flush the TLS connection, ensuring that all data is sent.
    ///
    /// Returns:
    ///
    /// An error if the flush failed
    pub fn flush(&mut self) -> Result<(), TlsError> {
        self.connect()?;

        self.stream.flush().map_err(|_| TlsError::Unknown)
    }

    fn internal_write(&mut self, buf: &[u8]) -> i32 {
        unsafe {
            mbedtls_ssl_set_bio(
                &mut self.ctx.ssl_context,
                self as *mut _ as *mut c_void,
                Some(Self::send),
                Some(Self::receive),
                None,
            );

            mbedtls_ssl_write(&mut self.ctx.ssl_context, buf.as_ptr(), buf.len())
        }
    }

    fn internal_read(&mut self, buf: &mut [u8]) -> i32 {
        unsafe {
            mbedtls_ssl_set_bio(
                &mut self.ctx.ssl_context,
                self as *mut _ as *mut c_void,
                Some(Self::send),
                Some(Self::receive),
                None,
            );

            mbedtls_ssl_read(&mut self.ctx.ssl_context, buf.as_mut_ptr(), buf.len())
        }
    }

    unsafe extern "C" fn send(ctx: *mut c_void, buf: *const c_uchar, len: usize) -> c_int {
        let session = ctx as *mut Session<T>;
        let stream = &mut (*session).stream;
        let slice = core::ptr::slice_from_raw_parts(buf as *const u8, len as usize);
        let res = stream.write(&*slice);

        match res {
            Ok(written) => {
                if written > 0 {
                    written as i32
                } else {
                    MBEDTLS_ERR_SSL_WANT_WRITE
                }
            }
            Err(_) => 0,
        }
    }

    unsafe extern "C" fn receive(ctx: *mut c_void, buf: *mut c_uchar, len: usize) -> c_int {
        let session = ctx as *mut Session<T>;
        let stream = &mut (*session).stream;
        let mut buffer = core::slice::from_raw_parts_mut(buf as *mut u8, len as usize);
        let res = stream.read(&mut buffer);

        match res {
            Ok(len) => {
                if len == 0 {
                    MBEDTLS_ERR_SSL_WANT_READ
                } else {
                    len as c_int
                }
            }
            Err(_) => 0,
        }
    }
}

impl<T> ErrorType for Session<'_, T>
where
    T: Read + Write,
{
    type Error = TlsError;
}

impl<T> Read for Session<'_, T>
where
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        Session::read(self, buf)
    }
}

impl<T> Write for Session<'_, T>
where
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Session::write(self, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Session::flush(self)
    }
}

#[cfg(feature = "async")]
pub mod asynch {
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll};

    use embedded_io::Error;

    use super::*;

    /// Re-export of the `embedded-io-async` crate so that users don't have to explicitly depend on it
    /// to use e.g. `write_all` or `read_exact`.
    pub mod io {
        pub use embedded_io_async::*;
    }

    /// Re-export of the `edge-nal` crate so that users don't have to explicitly depend on it
    /// to use e.g. `TlsAccept` and `TlsConnect` methods.
    #[cfg(feature = "edge-nal")]
    pub mod nal {
        pub use crate::edge_nal::*;
    }

    #[cfg(feature = "edge-nal")]
    pub use super::edge_nal::*;

    /// An async TLS session over a stream represented by `embedded-io-async`'s `Read` and `Write` traits.
    pub struct Session<'a, T> {
        pub(crate) stream: T,
        ctx: Box<SessionCtx<'a>>,
        state: SessionState,
        read_byte: Option<u8>,
        write_byte: Option<u8>,
        _token: TlsReference<'a>,
    }

    impl<'a, T> Session<'a, T> {
        /// Create a session for a TLS stream.
        ///
        /// # Arguments
        ///
        /// * `stream` - The stream for the connection.
        /// * `mode` - Use [Mode::Client] if you are running a client. [Mode::Server] if you are
        ///   running a server.
        /// * `min_version` - The minimum TLS version for the connection, that will be accepted.
        /// * `certificates` - Certificate chain for the connection. Will play a different role
        ///   depending on if running as client or server. See [Certificates] for more information.
        /// * `tls_ref` - A reference to the active `Tls` instance.
        ///
        /// # Errors
        ///
        /// This will return a [TlsError] if there were an error during the initialization of the
        /// session. This can happen if there is not enough memory of if the certificates are in an
        /// invalid format.
        pub fn new(
            stream: T,
            mode: Mode,
            min_version: TlsVersion,
            ca_cert: Option<&'a CaCertificate>,
            own_cert: Option<&'a OwnCertificate>,
            tls_ref: TlsReference<'a>,
        ) -> Result<Self, TlsError> {
            Ok(Self {
                stream,
                ctx: SessionCtx::new(mode, min_version, ca_cert, own_cert)?,
                state: SessionState::Initial,
                read_byte: None,
                write_byte: None,
                _token: tls_ref,
            })
        }
    }

    impl<'a, T> Session<'a, T>
    where
        T: embedded_io_async::Read + embedded_io_async::Write,
    {
        /// Negotiate the TLS connection
        ///
        /// This function will perform the TLS handshake with the server.
        ///
        /// Note that calling it is not mandatory, because the TLS session is anyway
        /// negotiated during the first read or write operation.
        pub async fn connect(&mut self) -> Result<(), TlsError> {
            match self.state {
                SessionState::Initial => {
                    log::debug!("Establishing SSL connection");

                    self.io(|ssl| unsafe { mbedtls_ssl_handshake(ssl) }).await?;
                    self.state = SessionState::Connected;

                    Ok(())
                }
                SessionState::Connected => Ok(()),
                SessionState::Eof => Err(TlsError::Eof),
            }
        }

        /// Read unencrypted data from the TLS connection
        ///
        /// # Arguments
        ///
        /// * `buf` - The buffer to read the data into
        ///
        /// # Returns
        ///
        /// The number of bytes read or an error
        pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
            self.connect().await?;

            let len = self
                .io(|ssl| unsafe {
                    mbedtls_ssl_read(ssl, buf.as_mut_ptr() as *mut _, buf.len() as _)
                })
                .await?;

            Ok(len as _)
        }

        /// Write unencrypted data to the TLS connection
        ///
        /// Arguments:
        ///
        /// * `data` - The data to write
        ///
        /// Returns:
        ///
        /// The number of bytes written or an error
        pub async fn write(&mut self, data: &[u8]) -> Result<usize, TlsError> {
            self.connect().await?;

            let len = self
                .io(|ssl| unsafe {
                    mbedtls_ssl_write(ssl, data.as_ptr() as *const _, data.len() as _)
                })
                .await?;

            Ok(len as _)
        }

        /// Flush the TLS connection
        ///
        /// This function will flush the TLS connection, ensuring that all data is sent.
        ///
        /// Returns:
        ///
        /// An error if the flush failed
        pub async fn flush(&mut self) -> Result<(), TlsError> {
            self.connect().await?;

            self.flush_write().await?;
            self.stream
                .flush()
                .await
                .map_err(|e| TlsError::Io(e.kind()))?;

            Ok(())
        }

        /// Close the TLS connection
        ///
        /// This function will close the TLS connection, sending the TLS "close notify" info the the peer.
        ///
        /// Returns:
        ///
        /// An error if the close failed
        pub async fn close(&mut self) -> Result<(), TlsError> {
            self.connect().await?;

            self.io(|ssl| unsafe { mbedtls_ssl_close_notify(ssl) })
                .await?;
            self.flush().await?;

            self.state = SessionState::Eof;

            Ok(())
        }

        /// Perform an async IO operation on the TLS connection, by calling the
        /// provided MbedTLS function.
        ///
        /// The MbedTLS function is usually either `mbedtls_ssl_read`, `mbedtls_ssl_write` or `mbedtls_ssl_handshake`.
        async fn io<F>(&mut self, mut f: F) -> Result<i32, TlsError>
        where
            F: FnMut(*mut mbedtls_ssl_context) -> i32,
        {
            loop {
                let outcome =
                    core::future::poll_fn(|cx| PollCtx::poll(self, cx, |ssl| f(ssl))).await?;

                self.flush_write().await?;

                match outcome {
                    PollOutcome::Success(res) => break Ok(res),
                    PollOutcome::Retry => continue,
                    PollOutcome::WantRead => self.wait_read().await?,
                    PollOutcome::WantWrite => self.flush_write().await?,
                }
            }
        }

        /// Wait for the stream to be readable
        ///
        /// Since the `Session` is implemented purely with the `Read` trait, this method
        /// will read a single byte from the stream, so that the `Read` trait can be polled
        async fn wait_read(&mut self) -> Result<(), TlsError> {
            if self.read_byte.is_none() {
                let mut buf = [0];

                let len = self
                    .stream
                    .read(&mut buf)
                    .await
                    .map_err(|e| TlsError::Io(e.kind()))?;
                if len > 0 {
                    self.read_byte = Some(buf[0]);
                }
            }

            Ok(())
        }

        /// Wait for the stream to be writable
        ///
        /// Since the `Session` is implemented purely with the `Write` trait, this method
        /// will write a single byte to the stream (provided by the "mbio" MbedTLS callbacks),
        /// so that the `Write` trait can be polled
        async fn flush_write(&mut self) -> Result<(), TlsError> {
            if let Some(byte) = self.write_byte.as_ref().copied() {
                let data = [byte];
                let len = self
                    .stream
                    .write(&data)
                    .await
                    .map_err(|e| TlsError::Io(e.kind()))?;
                if len > 0 {
                    self.write_byte.take();
                }
            }

            Ok(())
        }
    }

    impl<T> embedded_io_async::ErrorType for Session<'_, T>
    where
        T: embedded_io_async::ErrorType,
    {
        type Error = TlsError;
    }

    impl<T> embedded_io_async::Read for Session<'_, T>
    where
        T: embedded_io_async::Read + embedded_io_async::Write,
    {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            self.read(buf).await
        }
    }

    impl<T> embedded_io_async::Write for Session<'_, T>
    where
        T: embedded_io_async::Read + embedded_io_async::Write,
    {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.write(buf).await
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            self.flush().await
        }
    }

    /// Poll outcome for the `PollCtx` type
    #[derive(Copy, Clone, Debug)]
    pub enum PollOutcome {
        /// The operation was successful
        ///
        /// The returned value would be either 0, or how many bytes were read/written
        Success(i32),
        /// The IO layer needs to read more data asynchronously
        WantRead,
        /// The IO layer needs to write more data asynchronously
        WantWrite,
        /// Operation needs to be retried
        Retry,
    }

    /// A context for using the async `Read` and `Write` traits from within the synchronous MbedTLS "mbio" callbacks
    /// **without any additional buffers** / memory.
    ///
    /// Using the MbedTLS callback-based IO metaphor is a bit of a challenge with the async `Read` and `Write` traits,
    /// in that these cannot be `await`-ed from within the MbedTLS mbio callbacks, as the latter are synchronous callback
    /// functions.
    ///
    /// What the `PollCtx` type implements therefore is the following trick:
    /// - While we cannot `await` on the `Read` and `Write` traits directly from within the "mbio" callbacks, we can still
    ///   poll them (with `Future::poll`). This is because the `poll` method is synchronous in that it either resolves the
    ///   future immediately (`Poll::Ready`), or returns `Poll::Pending` if the future needs to be polled again.
    /// - Because of the `Read` and `Write` traits' semantics, polling them MUST return immediately, if there is even one
    ///   byte available for reading from the networking stack buffers (or - correspondingly - if there is space to write
    ///   even one byte in the networking stack buffers).
    /// - Since the network stack usually does not operate byte-by-byte, what this means is that by just calling `Future::poll`
    ///   on the `Read` / `Write` trait, we can efficiently transfer the incoming/outgoing data from/to the network stack, without
    ///   any additional network buffers.
    /// - Of course, if the network read buffers are empty (or write buffers are full), we still need to `await` outside the
    ///   MbedTLS callbacks, in the `Session::read` / `Session::write` / `Session::connect` methods.
    ///
    /// Note also, that the implementation of `PollCtx` is a tad more complex, because it is implemented purely in terms of the
    /// `Read` and `Write` traits, rather than `edge-nal`'s `Readable` and (future) `Writable`, so we need to shuffle single bytes
    /// between the "mbio" callbacks and the `Session` asunc context to make it work.
    ///
    /// On the other hand, this enables `Session` to be used over any streaming transport that implements the `Read` and `Write` traits
    /// (i.e. UART and others).
    struct PollCtx<'s, 'a, 'c, 'q, T> {
        /// The session
        session: &'s mut Session<'a, T>,
        /// The async context with which `Session::read` / `Session::write` / `Session::connect` are called.
        /// Necessary so that we can invoke `Future::poll`
        context: &'c mut Context<'q>,
        /// The result from `Future::poll`, if it returned `Poll::Ready`
        io_result: Option<Result<(), TlsError>>,
    }

    impl<'s, 'a, 'c, 'q, T> PollCtx<'s, 'a, 'c, 'q, T>
    where
        T: embedded_io_async::Read + embedded_io_async::Write,
    {
        fn poll<F>(
            session: &'s mut Session<'a, T>,
            context: &'c mut Context<'q>,
            f: F,
        ) -> Poll<Result<PollOutcome, TlsError>>
        where
            F: FnOnce(*mut mbedtls_ssl_context) -> i32,
        {
            Self::new(session, context).poll_mut(f)
        }

        /// Create a new `PollCtx` instance
        fn new(session: &'s mut Session<'a, T>, context: &'c mut Context<'q>) -> Self {
            Self {
                session,
                context,
                io_result: None,
            }
        }

        /// Call `Future::poll` on the `Read` or `Write` traits
        fn poll_mut<F>(&mut self, f: F) -> Poll<Result<PollOutcome, TlsError>>
        where
            F: FnOnce(*mut mbedtls_ssl_context) -> i32,
        {
            unsafe {
                mbedtls_ssl_set_bio(
                    &mut self.session.ctx.ssl_context,
                    self as *mut _ as *mut c_void,
                    Some(Self::raw_send),
                    Some(Self::raw_receive),
                    None,
                );
            }

            let res = f(&mut self.session.ctx.ssl_context);

            // Remove the callbacks so that we get a warning from MbedTLS in case
            // it needs to invoke them when we don't anticipate so (for bugs detection)
            unsafe {
                mbedtls_ssl_set_bio(
                    &mut self.session.ctx.ssl_context,
                    core::ptr::null_mut(),
                    None,
                    None,
                    None,
                );
            }

            if let Some(Err(e)) = self.io_result.take() {
                Err(e)?;
            }

            #[allow(non_snake_case)]
            Poll::Ready(match res {
                MBEDTLS_ERR_SSL_WANT_READ => Ok(PollOutcome::WantRead),
                MBEDTLS_ERR_SSL_WANT_WRITE => Ok(PollOutcome::WantWrite),
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => Ok(PollOutcome::Retry),
                res if res < 0 => {
                    ::log::warn!("MbedTLS error: {res} / {res:x}");
                    Err(TlsError::MbedTlsError(res))
                }
                len => Ok(PollOutcome::Success(len)),
            })
        }

        fn send(&mut self, buf: &[u8]) -> i32 {
            ::log::debug!("Send {}B", buf.len());

            if buf.is_empty() {
                // MbedTLS does not want us to read anything
                return 0;
            }

            if self.session.write_byte.is_some() {
                // We have a byte to write from the previous call
                // Indicate to the `Session` instance that it needs to write it
                return MBEDTLS_ERR_SSL_WANT_WRITE;
            }

            // Poll the `write` future by trying to immediately send (part of) the MbedTLS write data
            // into the network stack buffers
            let fut = pin!(self.session.stream.write(buf));

            if let Poll::Ready(result) = fut.poll(self.context) {
                match result {
                    Ok(len) => {
                        // Success!

                        if len == 0 {
                            // The stream has reached EOF
                            self.session.state = SessionState::Eof;
                            self.io_result = Some(Err(TlsError::Eof));
                            ::log::warn!("IO error: EOF");
                        } else {
                            // The write was successful, indicate so
                            self.io_result = Some(Ok(()));
                        }

                        len as _
                    }
                    Err(err) => {
                        // MbedTLS error
                        ::log::warn!("TCP error: {:?}", err.kind());
                        self.io_result = Some(Err(TlsError::Io(err.kind())));
                        MBEDTLS_ERR_SSL_WANT_WRITE
                    }
                }
            } else {
                // Network write buffers are full, indicate to the `Session` instance that
                // it needs to write-await
                // Also give it one byte of the TLS data so that it can call `Write::write` on something
                self.session.write_byte = Some(buf[0]);
                1
            }
        }

        fn receive(&mut self, buf: &mut [u8]) -> i32 {
            ::log::debug!("Recv {}B", buf.len());

            if buf.is_empty() {
                // MbedTLS does not want us to read anything
                return 0;
            }

            let offset = if let Some(byte) = self.session.read_byte.take() {
                // We have one byte read from the `Session` async context, give it
                // to MbedTLS
                buf[0] = byte;
                1
            } else {
                0
            };

            if buf.len() == offset {
                // MbedTLS requested only one byte anyway
                return offset as _;
            }

            let fut = pin!(self.session.stream.read(&mut buf[offset..]));

            if let Poll::Ready(result) = fut.poll(self.context) {
                match result {
                    Ok(len) => {
                        // Success!

                        let len = len + offset;

                        if len == 0 {
                            // The stream has reached EOF
                            self.session.state = SessionState::Eof;
                            self.io_result = Some(Err(TlsError::Eof));
                            ::log::warn!("IO error: EOF");
                        } else {
                            // The read was successful, indicate so
                            self.io_result = Some(Ok(()));
                        }

                        len as _
                    }
                    Err(err) => {
                        // MbedTLS error
                        ::log::warn!("TCP error: {:?}", err.kind());
                        self.io_result = Some(Err(TlsError::Io(err.kind())));
                        MBEDTLS_ERR_SSL_WANT_READ
                    }
                }
            } else {
                // Network read buffers are empty, either return the single byte we have
                // or indicate to the `Session` async context, that it needs to invoke `read` on the
                // `Read` trait
                if offset == 0 {
                    MBEDTLS_ERR_SSL_WANT_READ
                } else {
                    offset as _
                }
            }
        }

        unsafe extern "C" fn raw_send(ctx: *mut c_void, buf: *const c_uchar, len: usize) -> c_int {
            let ctx = (ctx as *mut PollCtx<'s, 'a, 'c, 'q, T>).as_mut().unwrap();

            ctx.send(core::slice::from_raw_parts(buf as *const _, len))
        }

        unsafe extern "C" fn raw_receive(ctx: *mut c_void, buf: *mut c_uchar, len: usize) -> c_int {
            let ctx = (ctx as *mut PollCtx<'s, 'a, 'c, 'q, T>).as_mut().unwrap();

            ctx.receive(core::slice::from_raw_parts_mut(buf as *mut _, len))
        }
    }
}

/// Outputs the MbedTLS debug messages to the log
unsafe extern "C" fn dbg_print(
    _arg: *mut c_void,
    lvl: i32,
    file: *const i8,
    line: i32,
    msg: *const i8,
) {
    let file = CStr::from_ptr(file as *const i8);
    let msg = CStr::from_ptr(msg as *const i8);

    let file = file.to_str().unwrap_or("???").trim();
    let msg = msg.to_str().unwrap_or("???").trim();

    let level = match lvl {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Debug,
        _ => Level::Trace,
    };

    log::log!(level, "{} ({}:{}) {}", lvl, file, line, msg);
}

unsafe extern "C" fn rng(_param: *mut c_void, buffer: *mut c_uchar, len: usize) -> c_int {
    for i in 0..len {
        buffer
            .offset(i as isize)
            .write_volatile((random() & 0xff) as u8);
    }

    0
}

#[cfg(not(target_os = "espidf"))]
#[no_mangle]
unsafe extern "C" fn mbedtls_platform_zeroize(dst: *mut u8, len: u32) {
    for i in 0..len as isize {
        dst.offset(i).write_volatile(0);
    }
}

#[no_mangle]
unsafe extern "C" fn mbedtls_psa_external_get_random(
    _ctx: *mut (),
    output: *mut u8,
    out_size: usize,
    output_len: *mut usize,
) -> i32 {
    *output_len = out_size;
    rng(core::ptr::null_mut(), output, out_size);
    0
}
