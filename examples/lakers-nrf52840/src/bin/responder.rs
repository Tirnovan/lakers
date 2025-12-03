#![no_std]
#![no_main]

use common::{Packet, PacketError, ADV_ADDRESS, ADV_CRC_INIT, CRC_POLY, FREQ, MAX_PDU};
use defmt::info;
use defmt::unwrap;
use embassy_executor::Spawner;
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

use core::ffi::c_char;
use core::result;

extern crate alloc;

use embedded_alloc::Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

extern "C" {
    pub fn mbedtls_memory_buffer_alloc_init(buf: *mut c_char, len: usize);
}

mod common;

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

struct EnergyMetrics {
    total_cycles: u32,
    process_msg1_cycles: u32,
    prepare_msg2_cycles: u32,
    parse_msg3_cycles: u32,
    verify_msg3_cycles: u32,
    prepare_msg4_cycles: u32,
    total_duration_us: u64,
}

impl EnergyMetrics {
    fn new() -> Self {
        Self {
            total_cycles: 0,
            process_msg1_cycles: 0,
            prepare_msg2_cycles: 0,
            parse_msg3_cycles: 0,
            verify_msg3_cycles: 0,
            prepare_msg4_cycles: 0,
            total_duration_us: 0,
        }
    }

    fn print_report(&self) {
        info!(" === ENERGY MEASUREMENT REPORT (RESPONDER) ===");
        info!("Total duration: {} us", self.total_duration_us);
        info!("Total CPU cycles: {}", self.total_cycles);
        info!("Cycles for processing message 1: {}", self.process_msg1_cycles);
        info!("Cycles for preparing message 2: {}", self.prepare_msg2_cycles);
        info!("Cycles for parsing message 3: {}", self.parse_msg3_cycles);
        info!("Cycles for verifying message 3: {}", self.verify_msg3_cycles);
        info!("Cycles for preparing message 4: {}", self.prepare_msg4_cycles);
        info!(" ============================================= ");

        let active_time_ms = self.total_duration_us / 1000;
        let estimated_charge_mah = (active_time_ms as f32 * 5.0) / 36000.0; // Assuming 5mA current consumption
        let estimated_energy_mwh = estimated_charge_mah * 3.3; // Assuming 3.3V supply voltage

        info!("Estimated active current: 5 mA");
        info!("Estimated energy: {} mWh", estimated_energy_mwh);
    }
    
}

//Read CPU cycle counter (DWT_CYCCNT register)
#[inline(always)]
fn get_cpu_cycles() -> u32 {
    unsafe { 
         // Enable DWT and CYCCNT if not already enabled
         const DWT_CTRL: *mut u32 = 0xE0001000 as *mut u32;
         const DWT_CYCCNT: *mut u32 = 0xE0001004 as *mut u32;
         const SCB_DEMCR: *mut u32 = 0xE000EDFC as *mut u32;

         // Enable trace
         core::ptr::write_volatile(SCB_DEMCR, core::ptr::read_volatile(SCB_DEMCR) |  0x01000000);
         // Enable cycle counter
         core::ptr::write_volatile(DWT_CTRL, core::ptr::read_volatile(DWT_CTRL) | 0x00000001);

         core::ptr::read_volatile(DWT_CYCCNT) 
     }
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
    let mut led_pin_p1_14 = p1.p1_14.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let peripherals: embassy_nrf::Peripherals = embassy_nrf::init(config);

    info!("Starting BLE radio");
    let mut radio = Radio::new(peripherals.RADIO, Irqs);

    radio.set_mode(Mode::BLE_1MBIT);
    radio.set_tx_power(TxPower::_0D_BM);
    radio.set_frequency(FREQ);

    radio.set_access_address(ADV_ADDRESS);
    radio.set_header_expansion(false);
    radio.set_crc_init(ADV_CRC_INIT);
    radio.set_crc_poly(CRC_POLY);

    // // Memory buffer for mbedtls
    // #[cfg(feature = "crypto-psa")]
    // let mut buffer: [c_char; 4096 * 2] = [0; 4096 * 2];
    // #[cfg(feature = "crypto-psa")]
    // unsafe {
    //     mbedtls_memory_buffer_alloc_init(buffer.as_mut_ptr(), buffer.len());
    // }

    const NUM_RUNS: usize = 10;
    let mut all_cycles: [u32; NUM_RUNS] = [0; NUM_RUNS];
    let mut all_durations: [u64; NUM_RUNS] = [0; NUM_RUNS];
    let mut successful_runs: usize = 0;

    info!("Will process {} EDHOC handshakes...", NUM_RUNS);
    
    for run in 0..NUM_RUNS {

        info!("=== Waiting for handshake {}/{} ===", run + 1, NUM_RUNS);

        let mut energy_metrics = EnergyMetrics::new();
        let buffer: [u8; MAX_PDU] = [0x00u8; MAX_PDU];
        let mut c_r: Option<ConnId> = None;

        info!("Receiving...");
        // filter all incoming packets waiting for CBOR TRUE (0xf5)
        let pckt = common::receive_and_filter(
            &mut radio, 
            Some(0xf5), 
            Some(&mut led_pin_p1_14)
        ) 
            .await
            .unwrap();
        // info!("Received message_1");

        let start_time = Instant::now();
        let start_cycles = get_cpu_cycles();

        led_pin_p0_26.set_high().unwrap();

        led_pin_p1_07.set_high();
        let cred_r: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
        led_pin_p1_07.set_low();

        led_pin_p1_07.set_high();
        let responder = EdhocResponder::new(lakers_crypto::default_crypto(),cred_r);
        led_pin_p1_07.set_low();

        let message_1: EdhocMessageBuffer = pckt.pdu[1..pckt.len].try_into().expect("wrong length"); // get rid of the TRUE byte

        let cycles_before = get_cpu_cycles();

        led_pin_p1_07.set_high();;
        let result = responder.process_message_1(&message_1);
        energy_metrics.process_msg1_cycles = get_cpu_cycles().wrapping_sub(cycles_before);
        led_pin_p1_07.set_low();   
        led_pin_p0_26.set_low();
        
        if let Ok((responder, _c_i, ead_1)) = result {
            c_r = Some(ConnId::from_int_raw(5));
            // c_r = Some(generate_connection_identifier_cbor(
            //     &mut lakers_crypto::default_crypto(),
            // ));
            let ead_2 = None;
            // info!("Prepare message_2");

            let cycles_before = get_cpu_cycles();
            led_pin_p0_26.set_high();
            led_pin_p1_06.set_high();
            let (responder, message_2) = responder
                .prepare_message_2(CredentialTransfer::ByReference, c_r, &ead_2)
                .unwrap();

            energy_metrics.prepare_msg2_cycles = get_cpu_cycles().wrapping_sub(cycles_before);
            info!("message_2: {:#X}", message_2.content[..message_2.len]);
            led_pin_p1_06.set_low();
            led_pin_p0_26.set_low();
            // prepend 0xf5 also to message_2 in order to allow the Initiator filter out from other BLE packets
            // info!("Send message_2 and wait message_3");
            let message_3 = common::transmit_and_wait_response(
                &mut radio,
                Packet::new_from_slice(message_2.as_slice(), Some(0xf5)).expect("wrong length"),
                Some(c_r.unwrap().as_slice()[0]),
                Some(&mut led_pin_p1_10),
            )
            .await;
            
            match message_3 {
                Ok(message_3) => {
                    // info!("Received message_3");
                    led_pin_p0_26.set_high();
                    let rcvd_c_r: ConnId = ConnId::from_int_raw(message_3.pdu[0] as u8);
                    
                    if rcvd_c_r == c_r.unwrap() {

                        led_pin_p1_08.set_high();
                        let message_3: EdhocMessageBuffer = message_3.pdu[1..message_3.len]
                        .try_into()
                        .expect("wrong length");
                        let cycles_before = get_cpu_cycles();
                        let Ok((responder, id_cred_i, _ead_3)) =
                            responder.parse_message_3(&message_3)
                        else {
                            info!("EDHOC error at parse_message_3");
                            continue;
                        };
                        energy_metrics.parse_msg3_cycles = get_cpu_cycles().wrapping_sub(cycles_before);
                        led_pin_p1_08.set_low();
                        
                        led_pin_p1_08.set_high();
                        let cred_i: Credential = 
                            Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
                        let valid_cred_i =
                            credential_check_or_fetch(Some(cred_i), id_cred_i.unwrap()).unwrap();
                        let cycles_before = get_cpu_cycles();
                        led_pin_p1_08.set_low();

                        led_pin_p1_08.set_high();
                        let Ok(responder) = responder.verify_message_3(valid_cred_i)
                        else {
                            info!("EDHOC error at verify_message_3");
                            continue;
                        };
                        energy_metrics.verify_msg3_cycles = get_cpu_cycles().wrapping_sub(cycles_before);
                        led_pin_p1_08.set_low();
                        led_pin_p0_26.set_low();
                        
                        // info!("Prepare message_4");
                        led_pin_p0_26.set_high();
                        
                        led_pin_p1_04.set_high();
                        let cycles_before = get_cpu_cycles();
                        let (responder, message_4, r_prk_out) = responder.prepare_message_4(CredentialTransfer::ByReference, &None).unwrap();
                        energy_metrics.prepare_msg4_cycles = get_cpu_cycles().wrapping_sub(cycles_before);
                        led_pin_p1_04.set_low();
                        info!("message_4: {:#X}", message_4.content[..message_4.len]);

                        // info!("Send message_4");
                        common::transmit_without_response(
                            &mut radio,
                            common::Packet::new_from_slice(message_4.as_slice(),Some(c_r.unwrap().as_slice()[0]))
                                .unwrap(),
                                Some(&mut led_pin_p1_10),
                        ).await;

                        // End Measurement
                        let end_cycles = get_cpu_cycles();
                        let end_time = Instant::now();

                        energy_metrics.total_cycles = end_cycles.wrapping_sub(start_cycles);
                        energy_metrics.total_duration_us = (end_time - start_time).as_micros();
                        led_pin_p0_26.set_low();

                        info!("Handshake completed. prk_out = {:X}", r_prk_out);
                    } else {
                        info!("Another packet interrupted the handshake.");
                    }
                    energy_metrics.print_report();

                    all_cycles[successful_runs] = energy_metrics.total_cycles;
                    all_durations[successful_runs] = energy_metrics.total_duration_us;
                    successful_runs += 1;
                }
                Err(PacketError::TimeoutError) => info!("Timeout while waiting for message_3!"),
                Err(_) => panic!("Unexpected error"),
            }
        }
    }

    info!("");
    info!("===============================");
    info!("FINAL STATISTICS OVER {} SUCCESSFUL RUNS", successful_runs);
    info!("===============================");

    if successful_runs > 0 {
        let mut sum_cycles: u64 = 0;
        for i in 0..successful_runs {
            sum_cycles += all_cycles[i] as u64;
        }
        let average_cycles = sum_cycles / successful_runs as u64;

        let mut sum_durations: u64 = 0;
        for i in 0..successful_runs {
            sum_durations += all_durations[i];
        }
        let average_duration = sum_durations / successful_runs as u64;

        let mut min_cycles = all_cycles[0];
        let mut max_cycles = all_cycles[0];
        for i in 1..successful_runs {
            if all_cycles[i] < min_cycles { min_cycles = all_cycles[i]; }
            if all_cycles[i] > max_cycles { max_cycles = all_cycles[i]; }
        }

        info!("Average cycles: {}", average_cycles);
        info!("Min cycles: {}", min_cycles);
        info!("Max cycles: {}", max_cycles);
        info!("Average duration: {} us", average_duration);
        info!("Average duration: {} ms", average_duration / 1000);

        //Calculate estimated energy consumption
        let avg_time_ms = average_duration / 1000;
        let estimated_charge_mah = (avg_time_ms as f32 * 5.0) / 36000.0; // Assuming 5mA current consumption
        let estimated_energy_mwh = estimated_charge_mah * 3.3; // Assuming 3.3 V
        info!("Estimated average energy: {} mWh", estimated_energy_mwh);
    } else {
        info!("No successful runs recorded.");
    }

    info!("===============================");
    info!("All runs completed!");

    loop {
        Timer::after(Duration::from_secs(1)).await;
    }


#[embassy_executor::task]
async fn example_application_task(secret: BytesHashLen) {
    info!(
        "Successfully spawned an application task. EDHOC prk_out: {:X}",
        secret
    );
    }    
}




