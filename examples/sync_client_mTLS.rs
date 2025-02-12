//! Example for a client connection using certificate authentication (mTLS)
#![no_std]
#![no_main]

// See https://github.com/esp-rs/esp-mbedtls/pull/62#issuecomment-2560830139
//
// This is by the way a generic way to polyfill the libc functions used by `mbedtls`:
// - If your (baremetal) platform does not provide one or more of these, just
//   add a dependency on `tinyrlibc` in your binary crate with features for all missing functions
//   and then put such a `use` statement in your main file
#[cfg(feature = "esp32c3")]
use tinyrlibc as _;

#[doc(hidden)]
pub use esp_hal as hal;

use blocking_network_stack::Stack;

use esp_alloc as _;
use esp_backtrace as _;
use esp_mbedtls::{Certificates, Session};
use esp_mbedtls::{Mode, Tls, TlsVersion, X509};
use esp_println::{logger::init_logger, print, println};
use esp_wifi::{
    init,
    wifi::{utils::create_network_interface, ClientConfiguration, Configuration, WifiStaDevice},
};
use hal::{prelude::*, rng::Rng, time, timer::timg::TimerGroup};
use smoltcp11::{
    iface::{SocketSet, SocketStorage},
    wire::IpAddress,
};

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

#[entry]
fn main() -> ! {
    init_logger(log::LevelFilter::Info);
    let peripherals = esp_hal::init({
        let mut config = esp_hal::Config::default();
        config.cpu_clock = CpuClock::max();
        config
    });

    esp_alloc::heap_allocator!(115 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);

    let mut rng = Rng::new(peripherals.RNG);

    let init = init(timg0.timer0, rng, peripherals.RADIO_CLK).unwrap();

    let wifi = peripherals.WIFI;

    let (iface, device, mut controller) =
        create_network_interface(&init, wifi, WifiStaDevice).unwrap();

    let mut socket_set_entries: [SocketStorage; 3] = Default::default();
    let sockets = SocketSet::new(&mut socket_set_entries[..]);

    let now = || time::now().duration_since_epoch().to_millis();
    let wifi_stack = Stack::new(iface, device, sockets, now, rng.random());

    println!("Call wifi_connect");
    let client_config = Configuration::Client(ClientConfiguration {
        ssid: SSID.try_into().unwrap(),
        password: PASSWORD.try_into().unwrap(),
        ..Default::default()
    });
    controller.set_configuration(&client_config).unwrap();
    controller.start().unwrap();
    controller.connect().unwrap();

    println!("Wait to get connected");
    loop {
        let res = controller.is_connected();
        match res {
            Ok(connected) => {
                if connected {
                    break;
                }
            }
            Err(err) => {
                println!("{:?}", err);
                #[allow(clippy::empty_loop)]
                loop {}
            }
        }
    }

    // wait for getting an ip address
    println!("Wait to get an ip address");
    loop {
        wifi_stack.work();

        if wifi_stack.is_iface_up() {
            println!("Got ip {:?}", wifi_stack.get_ip_info());
            break;
        }
    }

    println!("We are connected!");

    println!("Making HTTP request");
    let mut rx_buffer = [0u8; 1536];
    let mut tx_buffer = [0u8; 1536];
    let mut socket = wifi_stack.get_socket(&mut rx_buffer, &mut tx_buffer);

    socket.work();

    socket
        .open(IpAddress::v4(62, 210, 201, 125), 443) // certauth.cryptomix.com
        .unwrap();

    let certificates = Certificates {
        ca_chain: X509::pem(
            concat!(include_str!("./certs/certauth.cryptomix.com.pem"), "\0").as_bytes(),
        )
        .ok(),
        certificate: X509::pem(concat!(include_str!("./certs/certificate.pem"), "\0").as_bytes())
            .ok(),
        private_key: X509::pem(concat!(include_str!("./certs/private_key.pem"), "\0").as_bytes())
            .ok(),
        password: None,
    };

    let mut tls = Tls::new(peripherals.SHA)
        .unwrap()
        .with_hardware_rsa(peripherals.RSA);

    tls.set_debug(0);

    let mut session = Session::new(
        &mut socket,
        Mode::Client {
            servername: c"certauth.cryptomix.com",
        },
        TlsVersion::Tls1_3,
        certificates,
        tls.reference(),
    )
    .unwrap();

    println!("Start tls connect");
    session.connect().unwrap();

    println!("Write to connection");
    session
        .write(b"GET /json/ HTTP/1.0\r\nHost: certauth.cryptomix.com\r\n\r\n")
        .unwrap();

    println!("Read from connection");
    let mut buffer = [0u8; 4096];
    loop {
        match session.read(&mut buffer) {
            Ok(len) => {
                print!("{}", unsafe {
                    core::str::from_utf8_unchecked(&buffer[..len])
                });
            }
            Err(_) => {
                println!();
                break;
            }
        }
    }
    println!("Done");

    #[allow(clippy::empty_loop)]
    loop {}
}
