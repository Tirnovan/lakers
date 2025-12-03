#![no_std]
#![no_main]

use defmt::info;
use defmt::unwrap;
use embassy_executor::Spawner;
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::radio::ble::Mode;
use embassy_nrf::radio::ble::Radio;
use embassy_nrf::radio::TxPower;
use embassy_nrf::{bind_interrupts, peripherals, radio};
use embassy_time::WithTimeout;
use embassy_time::{Duration, Instant, Timer};
use {defmt_rtt as _, panic_probe as _};

use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};

extern crate alloc;

use embedded_alloc::Heap;

use core::ffi::c_char;

#[global_allocator]
static HEAP: Heap = Heap::empty();

extern "C" {
    pub fn mbedtls_memory_buffer_alloc_init(buf: *mut c_char, len: usize);
}

mod common;

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

// Struct to hold energy measurement metrics
struct EnergyMetrics {
    total_cycles: u32,
    prepare_msg1_cycles: u32,
    parse_msg2_cycles: u32,
    verify_msg2_cycles: u32,
    prepare_msg3_cycles: u32,
    process_msg4_cycles: u32,
    total_duration_us: u64,
}

impl EnergyMetrics {
    fn new() -> Self {
        Self {
            total_cycles: 0,
            prepare_msg1_cycles: 0,
            parse_msg2_cycles: 0,
            verify_msg2_cycles: 0,
            prepare_msg3_cycles: 0,
            process_msg4_cycles: 0,
            total_duration_us: 0,
        }
    }

    fn print_report(&self) {
        info!("=== ENERGY MEASUREMENT REPORT (INITIATOR) ====");
        info!("Total duration: {} us", self.total_duration_us);
        info!("Total CPU Cycles: {}", self.total_cycles);
        info!("Prepare message_1 Cycles: {}", self.prepare_msg1_cycles);
        info!("Parse message_2 Cycles: {}", self.parse_msg2_cycles);
        info!("Verify message_2 Cycles: {}", self.verify_msg2_cycles);
        info!("Prepare message_3 Cycles: {}", self.prepare_msg3_cycles);
        info!("Process message_4 Cycles: {}", self.process_msg4_cycles);
        info!("===============================================");

        let active_time_ms = self.total_duration_us / 1000;
        let estimated_charge_mah = (active_time_ms as f32 * 5.0) / 36000.0; // Assuming 5mA current consumption
        let estimated_energy_mwh = estimated_charge_mah * 3.3; // Assuming 3.3V supply voltage

        info!("Estmated active current: 5 mA");
        info!("Estimated energy: {} mWh", estimated_energy_mwh);
    }
}

#[inline(always)]
fn get_cpu_cycles() -> u32 {
    unsafe {
        const DWT_CTRL: *mut u32 = 0xE0001000 as *mut u32;
        const DWT_CYCCNT: *mut u32 = 0xE0001004 as *mut u32;
        const SCB_DEMCR: *mut u32 = 0xE000EDFC as *mut u32;

        // Enable trace
        core::ptr::write_volatile(SCB_DEMCR, core::ptr::read_volatile(SCB_DEMCR) | 0x01000000);
        // Enable the cycle counter
        core::ptr::write_volatile(DWT_CTRL, core::ptr::read_volatile(DWT_CTRL) | 0x00000001);

        core::ptr::read_volatile(DWT_CYCCNT)
    }
        // Read the cycle counter
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let peripherals = embassy_nrf::init(config);

    info!("Starting BLE radio");
    let mut radio: Radio<'_, _> = Radio::new(peripherals.RADIO, Irqs).into();

    let mut led = Output::new(peripherals.P0_13, Level::Low, OutputDrive::Standard);
    led.set_high();

    radio.set_mode(Mode::BLE_1MBIT);
    radio.set_tx_power(TxPower::_0D_BM);
    radio.set_frequency(common::FREQ);

    radio.set_access_address(common::ADV_ADDRESS);
    radio.set_header_expansion(false);
    radio.set_crc_init(common::ADV_CRC_INIT);
    radio.set_crc_poly(common::CRC_POLY);

    info!("init_handshake");

    // Memory buffer for mbedtls
    #[cfg(feature = "crypto-psa")]
    let mut buffer: [c_char; 4096 * 2] = [0; 4096 * 2];
    #[cfg(feature = "crypto-psa")]
    unsafe {
        mbedtls_memory_buffer_alloc_init(buffer.as_mut_ptr(), buffer.len());
    }

    let cred_i = Credential::parse_ccs(common::CRED_I.try_into().unwrap()).unwrap();
    let cred_r = Credential::parse_ccs(common::CRED_R.try_into().unwrap()).unwrap();

    const NUM_RUNS: usize = 10;
    let mut all_cycles: [u32; NUM_RUNS] = [0; NUM_RUNS];
    let mut all_durations: [u64; NUM_RUNS] = [0; NUM_RUNS];

    info!("Starting {} EDHOC handshake runs...", NUM_RUNS);

    for run in 0..NUM_RUNS {
        info!("Run {}/{}", run + 1, NUM_RUNS);

        Timer::after(Duration::from_millis(100)).await;

        let mut initiator = EdhocInitiator::new(
        lakers_crypto::default_crypto(),
        EDHOCMethod::StatStat,
        EDHOCSuite::CipherSuite2,
        );
        initiator.set_identity(common::I.try_into().unwrap(), cred_i.clone());

        // START MEASUREMENT
        let start_time = Instant::now();
        let start_cycles = get_cpu_cycles();
        let mut energy_metrics = EnergyMetrics::new();

     

    // Send Message 1 over raw BLE and convert the response to byte
    let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
    let cycles_before = get_cpu_cycles();
    let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &EadItems::new()).unwrap();
    energy_metrics.prepare_msg1_cycles = get_cpu_cycles().wrapping_sub(cycles_before);

    let pckt_1 = common::Packet::new_from_slice(message_1.as_slice(), Some(0xf5))
        .expect("Buffer not long enough");
    let rcvd = common::transmit_and_wait_response(&mut radio, pckt_1, Some(0xf5)).await;

    match rcvd {
        Ok(pckt_2) => {
            info!("Received message_2");
            let message_2: EdhocMessageBuffer =
                // starts in 1 to consider only the content and not the metadata
                pckt_2.pdu[1..pckt_2.len].try_into().expect("wrong length");

            let cycles_before = get_cpu_cycles();
            info!("message_2 :{:?}", message_2.content);
            let (initiator, c_r, id_cred_r, ead_2) = initiator.parse_message_2(&message_2).unwrap();
            energy_metrics.parse_msg2_cycles = get_cpu_cycles().wrapping_sub(cycles_before);

            let valid_cred_r = credential_check_or_fetch(Some(cred_r.clone()), id_cred_r).unwrap();
            // Measure verify_message_2
            let cycles_before = get_cpu_cycles();
            let initiator = initiator.verify_message_2(valid_cred_r).unwrap();
            energy_metrics.verify_msg2_cycles = get_cpu_cycles().wrapping_sub(cycles_before);

            // Measure prepare_message_3
            let cycles_before = get_cpu_cycles();
            let (mut initiator, message_3, i_prk_out) = initiator
                .prepare_message_3(CredentialTransfer::ByReference, &None)
                .unwrap();
            energy_metrics.prepare_msg3_cycles = get_cpu_cycles().wrapping_sub(cycles_before);

            let pckt_3 =
                common::Packet::new_from_slice(message_3.as_slice(), Some(c_r.as_slice()[0]))
                    .expect("Buffer not long enough");
            info!("Send message_3 and wait message_4");
            let rcvd =
                common::transmit_and_wait_response(&mut radio, pckt_3, Some(c_r.as_slice()[0]))
                    .await;

            info!("Sent message_3");
            match rcvd {
                Ok(pckt_4) => {
                    info!("Received message_4");
                    let message_4: EdhocMessageBuffer =
                        pckt_4.pdu[1..pckt_4.len].try_into().expect("wrong length");
                    
                    // Measure process_message_4
                    let cycles_before = get_cpu_cycles();
                    let (initiator, ead_4) = initiator.process_message_4(&message_4).unwrap();
                    energy_metrics.process_msg4_cycles = get_cpu_cycles().wrapping_sub(cycles_before);

                    // END MEASUREMENT
                    let end_cycles = get_cpu_cycles();
                    let end_time = Instant::now();
                    led.set_low();

                    energy_metrics.total_cycles = end_cycles.wrapping_sub(start_cycles);
                    energy_metrics.total_duration_us = (end_time - start_time).as_micros();

                    info!("Handshake completed. prk_out = {:X}", i_prk_out);
                    energy_metrics.print_report();

                    // Store results
                    all_cycles[run] = energy_metrics.total_cycles;
                    all_durations[run] = energy_metrics.total_duration_us;
                }
                Err(_) => {
                    led.set_low();
                    panic!("Error in run {}, skipping...", run + 1);
                    continue;
                }
            }
        }
        Err(_) => {
            led.set_low();
            panic!("Error in run {}, skipping...", run + 1);
            continue;
        }
    }
    
    // Print average results after all runs
    info!("");
    info!("=================================");
    info!("Final STATISTICS OVER {} RUNS:", NUM_RUNS);
    info!("=================================");

    let mut sum_cycles: u64 = 0;
    for cycles in &all_cycles {
        sum_cycles += *cycles as u64;
    }
    let avg_cycles = sum_cycles / NUM_RUNS as u64;

    let mut sum_durations: u64 = 0;
    for duration in &all_durations {
        sum_durations += *duration;
    }
    let avg_duration = sum_durations / NUM_RUNS as u64;

    let mut min_cycles = all_cycles[0];
    let mut max_cycles = all_cycles[0];
    for cycles in &all_cycles {
        if *cycles < min_cycles { min_cycles = *cycles; }
        if *cycles > max_cycles { max_cycles = *cycles; }
    }
    info!("Average cycles: {}", avg_cycles);
    info!("Minimum cycles: {}", min_cycles);
    info!("Maximum cycles: {}", max_cycles);
    info!("Average duration: {} us", avg_duration);
    info!("Average duration: {} ms", avg_duration / 1000);

    // calculate estimated energy
    let avg_time_ms = avg_duration / 1000;
    let estimated_charge_mah = (avg_time_ms as f32 * 5.0) / 36000.0; // Assuming 5mA current consumption
    let estimated_energy_mwh = estimated_charge_mah * 3.3; // Assuming 3.3
    info!("Estimated average energy: {} mWh", estimated_energy_mwh);

    info!("=================================");
    info!("All runs completed.");
    }
}
 

