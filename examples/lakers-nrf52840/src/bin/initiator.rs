#![no_std]
#![no_main]

use common::{Packet, PacketError, ADV_ADDRESS, ADV_CRC_INIT, CRC_POLY, FREQ, MAX_PDU};
use defmt::info;
use embassy_executor::Spawner;
use embassy_nrf::pac::ficr::info;
use embassy_nrf::radio::ble::Mode;
use embassy_nrf::radio::ble::Radio;
use embassy_nrf::radio::TxPower;
use embassy_nrf::{bind_interrupts, peripherals, radio};
use {defmt_rtt as _, panic_probe as _};
use nrf52840_hal::pac;
use nrf52840_hal::prelude::*;
use nrf52840_hal::gpio::{Level, Output, Pin};
use embassy_time::{Duration, Instant, Timer};


use lakers::*;

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
    let peripherals = pac::Peripherals::take().unwrap();
    let p0 = nrf52840_hal::gpio::p0::Parts::new(peripherals.P0);
    let p1 = nrf52840_hal::gpio::p1::Parts::new(peripherals.P1);

    let mut led_pin_p0_26 = p0.p0_26.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_8 = p0.p0_08.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_7 = p0.p0_07.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_6 = p0.p0_06.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_5 = p0.p0_05.into_push_pull_output(nrf52840_hal::gpio::Level::Low);

    let mut led_pin_p1_07 = p1.p1_07.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p1_08 = p1.p1_08.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p1_06 = p1.p1_06.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p1_05 = p1.p1_05.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p1_04 = p1.p1_04.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p1_10 = p1.p1_10.into_push_pull_output(nrf52840_hal::gpio::Level::Low);

    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let embassy_peripherals = embassy_nrf::init(config);

    info!("Starting BLE radio");
    let mut radio: Radio<'_, _> = Radio::new(embassy_peripherals.RADIO, Irqs).into();

    //let mut led = Output::new(embassy_peripherals.P0_13, Level::Low, OutputDrive::Standard);
    //led.set_high();

    radio.set_mode(Mode::BLE_1MBIT);
    radio.set_tx_power(TxPower::_0D_BM);
    radio.set_frequency(common::FREQ);

    radio.set_access_address(common::ADV_ADDRESS);
    radio.set_header_expansion(false);
    radio.set_crc_init(common::ADV_CRC_INIT);
    radio.set_crc_poly(common::CRC_POLY);

    info!("init_handshake");

    // // Memory buffer for mbedtls
    // #[cfg(feature = "crypto-psa")]
    // let mut buffer: [c_char; 4096 * 2] = [0; 4096 * 2];
    // #[cfg(feature = "crypto-psa")]
    // unsafe {
    //     mbedtls_memory_buffer_alloc_init(buffer.as_mut_ptr(), buffer.len());
    // }
   

    // info!("Prepare message_1");
    led_pin_p0_26.set_high();
    led_pin_p1_07.set_high();
    let cred_i: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
    let cred_r: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
    info!("cred_r:{:?}", cred_r.bytes.content);
    led_pin_p1_07.set_low();

    const NUM_RUNS: usize = 10;
    let mut all_cycles: [u32; NUM_RUNS] = [0; NUM_RUNS];
    let mut all_durations: [u64; NUM_RUNS] = [0; NUM_RUNS];

    info!("Starting {} EDHOC handshakes runs...", NUM_RUNS);

    for run in 0..NUM_RUNS {
        info!("Run {}/{}", run + 1, NUM_RUNS);

        Timer::after(Duration::from_millis(100)).await; // Small delay between runs
    

        led_pin_p1_07.set_high();
        let mut initiator = EdhocInitiator::new(
            lakers_crypto::default_crypto(),
            EDHOCMethod::PSK2,
            EDHOCSuite::CipherSuite2,
        );
        led_pin_p1_07.set_low();

        led_pin_p1_07.set_high();
        // Send Message 1 over raw BLE and convert the response to byte
        // let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
        let c_i = ConnId::from_int_raw(10);
        
        info!("c_i: {:#X}", c_i.as_slice());
        led_pin_p1_07.set_low();

        led_pin_p1_07.set_high();
        initiator.set_identity(cred_i.clone());

        let start_time = Instant::now();
        let start_cycles = get_cpu_cycles();
        let mut energy_metrics = EnergyMetrics::new();
        led_pin_p1_07.set_low();
        let cycles_before = get_cpu_cycles();

        led_pin_p1_07.set_high();
        let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &None).unwrap();
        energy_metrics.prepare_msg1_cycles = get_cpu_cycles().wrapping_sub(cycles_before);
        led_pin_p1_07.set_low();
        info!("message_1: {:#X}", message_1.content[..message_1.len]);

        let pckt_1 = common::Packet::new_from_slice(
            message_1.as_slice(), 
            Some(0xf5)
        ).expect("Buffer not long enough");
        // info!("Send message_1 and wait message_2");
        led_pin_p0_26.set_low();
        let rcvd = common::transmit_and_wait_response(
            &mut radio, 
            pckt_1, 
            Some(0xf5), 
            Some(&mut led_pin_p1_10)
        ).await;
        
        match rcvd {
            Ok(pckt_2) => {
                // info!("Received message_2");
                led_pin_p0_26.set_high();
                let message_2: EdhocMessageBuffer =
                    pckt_2.pdu[1..pckt_2.len].try_into().expect("wrong length");
                let cycles_before = get_cpu_cycles();
                led_pin_p1_06.set_high();
                let (initiator, c_r, id_cred_r, ead_2) = initiator.parse_message_2(&message_2).unwrap();
                energy_metrics.parse_msg2_cycles = get_cpu_cycles().wrapping_sub(cycles_before);

                led_pin_p1_06.set_low();
                let valid_cred_r = credential_check_or_fetch(Some(cred_r), id_cred_r.unwrap()).unwrap();
                let cycles_before = get_cpu_cycles();
                led_pin_p1_06.set_high();
                let initiator = initiator
                    .verify_message_2(valid_cred_r)
                    .unwrap();
                energy_metrics.verify_msg2_cycles = get_cpu_cycles().wrapping_sub(cycles_before);
                led_pin_p1_06.set_low();

                led_pin_p0_26.set_low();

                // info!("Prepare message_3");
                led_pin_p0_26.set_high();

                led_pin_p1_08.set_high();
                let cycles_before = get_cpu_cycles();
                let (initiator, message_3) = initiator
                    .prepare_message_3(CredentialTransfer::ByReference, &None).unwrap();
                energy_metrics.prepare_msg3_cycles = get_cpu_cycles().wrapping_sub(cycles_before);
                led_pin_p1_08.set_low();
                info!("message_3: {:#X}", message_3.content[..message_3.len]);

                let pckt_3 = common::Packet::new_from_slice(message_3.as_slice(), Some(c_r.as_slice()[0]))
                .expect("Buffer not long enough");
                // info!("Send message_3 and wait message_4");
                led_pin_p0_26.set_low();
                let rcvd = common::transmit_and_wait_response(
                    &mut radio, 
                    pckt_3,
                    Some(c_r.as_slice()[0]),
                    Some(&mut led_pin_p1_10),
                ).await;
                
                // info!("Sent message_3");
                match rcvd {
                    Ok(pckt_4) => {
                        // info!("Received message_4");
                        led_pin_p0_26.set_high();
                        let message_4: EdhocMessageBuffer =
                            pckt_4.pdu[1..pckt_4.len].try_into().expect("wrong length");
                        
                        let cycles_before = get_cpu_cycles();
                        led_pin_p1_04.set_high();
                        let (initiator, ead_4) = initiator.parse_message_4(&message_4).unwrap();
                        energy_metrics.process_msg4_cycles = get_cpu_cycles().wrapping_sub(cycles_before);
                        led_pin_p1_04.set_low();
                        let (mut initiator, i_prk_out) = initiator.verify_message_4().unwrap();
                        led_pin_p0_26.set_low();

                        // End Measurement
                        let end_cycles = get_cpu_cycles();
                        let end_time = Instant::now();

                        energy_metrics.total_cycles = end_cycles.wrapping_sub(start_cycles);
                        energy_metrics.total_duration_us = (end_time - start_time).as_micros();
                        
                        info!("Handshake completed. prk_out = {:X}", i_prk_out);

                        energy_metrics.print_report();

                        // Store results
                        all_cycles[run] = energy_metrics.total_cycles;
                        all_durations[run] = energy_metrics.total_duration_us;
                    }  
                    // Err(_) => panic!("parsing error"),
                    // Added to measure time. Otherwise revert to up
                    Err(_) => {
                        info!("Handshake failed, continuing to next iteration");
                        continue;  // Skip to next iteration if handshake fails
                    }
                }
            }
            // Err(_) => panic!("parsing error"),
            // Added to measure time. Otherwise revert to up.
            Err(_) => {
                info!("Hanshake failed. Continue to next iteration. Parsing error");
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
    // let duration = start.elapsed();
    // info!("start time: {:?} and elapsed time in ms: {:?}", start, duration.as_millis());
    // info!("duration of one handshake in ms: {:?}", duration.as_millis()/50);
}
