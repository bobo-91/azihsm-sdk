// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HW-only OOB SGL transport smoke test for `SdCreateRemoteBackup`.
//!
//! Purpose: prove that the SDK Linux backend's
//! `AZIHSM_CTRL_PATH_DATA_XFER` path reaches the firmware CreateSD FSM
//! and preserves the selected OOB payload bytes through the driver's
//! metadata-page and SGL-page representation. The firmware returns a
//! test-only length/checksum/index/descriptor-count integrity marker.
//!
//! This is intentionally NOT a full-fidelity CreateSD test.  It
//! deliberately skips the whole provisioning stack — no `PartFinal`,
//! no `SdSealingKeyGen`, no `KeyReport`, no receiver-evidence
//! certificate chain generation.  The **only** real thing about the
//! request is the session id: a valid CO session must be open so the
//! firmware dispatcher's session-lookup gate lets the SQE through to
//! the CreateSD FSM.  Everything downstream of that (masked sealing
//! key, cert-chain descriptors, policy) is zero / empty / placeholder.
//!
//! Pairs with the instrumentation-only CreateSD firmware FSM. It
//! DMA-reads the metadata page, selected level-2 SGL page, and level-3
//! payload Data Blocks, then returns the integrity marker without
//! running HPKE-Auth seal. This isolates OOB transport bring-up.
//!
//! Gated to the native Linux backend via the module-level `cfg`
//! (no `emu` / `mock` / `sock` feature).  When the crate is compiled
//! without any fake-backend feature the test binary picks this test
//! up as an ordinary integration test — no `--ignored` needed.  If
//! any of `emu` / `mock` / `sock` is enabled the whole module
//! compiles out.
//!
//! Run with:
//! ```text
//! cargo test -p azihsm_ddi_tbor_types \
//!     --test azihsm_ddi_tbor_tests -- \
//!     sd_create_remote_backup_oob_transport_smoke --nocapture
//! ```

#![cfg(all(
    target_os = "linux",
    not(feature = "emu"),
    not(feature = "mock"),
    not(feature = "sock")
))]

use azihsm_ddi_tbor_types::tbor_int::U16;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::ReportDescriptor;
use azihsm_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use azihsm_ddi_tbor_types::TborSdCreateRemoteBackupResp;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;

use crate::commands::part_init::bootstrap_rotated_co;
use crate::commands::part_init::ROTATED_CO_PSK;
use crate::harness::TestCtx;

/// Two dummy OOB buffer sizes.  Kept intentionally different so the
/// operator can spot each buffer's `xfer_length` in the driver /
/// firmware SGL walk (kernel builds one SGL segment per buffer).
const OOB_BUF_A_LEN: usize = 128;
const OOB_BUF_B_LEN: usize = 256;
const HOST_PAGE_SIZE: usize = 4096;
const MAX_OOB_BUFFER_COUNT: usize = 16;
const OOB_STRESS_ITERATIONS: usize = 100;

/// Positive lengths supported by the current firmware transport stub.
/// Includes power-of-two and adjacent boundary values through the
/// stub's 4 KiB scratch-buffer ceiling.
const POSITIVE_OOB_LENGTHS: &[usize] = &[
    1, 2, 3, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 511, 512, 1023, 1024, 1025,
    2047, 2048, 2049, 4095, 4096,
];

/// Sizes that require multiple bounded firmware DMA chunks. Exactly 65536
/// cannot be represented by the request's `U16` report length.
const STREAMING_OOB_LENGTHS: &[usize] = &[4097, 8192, 16384, 32768, 65535];

fn make_request(session_id: u16, index: u8, length: usize) -> TborSdCreateRemoteBackupReq {
    TborSdCreateRemoteBackupReq {
        session_id,
        masked_sealing_key: [0u8; MASKED_SEALING_KEY_LEN],
        receiver_mfgr_cert_chain: Vec::new(),
        receiver_owner_cert_chain: Vec::new(),
        receiver_part_owner_cert_chain: Vec::new(),
        receiver_report: ReportDescriptor {
            index,
            length: U16::new(length as u16),
        },
        policy: PartPolicy::zeroed(),
    }
}

fn payload_checksum(payload: &[u8]) -> u32 {
    payload.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

fn patterned_payload(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|offset| {
            seed.wrapping_mul(0x3D)
                .wrapping_add((offset as u8).wrapping_mul(0x25))
        })
        .collect()
}

fn max_data_block_count(payload_len: usize) -> u16 {
    const PAGE_SIZE: usize = 4096;
    debug_assert!(payload_len > 0);
    (payload_len.saturating_sub(1).div_ceil(PAGE_SIZE) + 1) as u16
}

fn assert_stub_response(resp: &TborSdCreateRemoteBackupResp, index: u8, payload: &[u8]) -> u16 {
    let marker = &resp.pok_remote_backup[..15];
    assert_eq!(&marker[..4], b"OOB1", "missing firmware integrity marker");
    assert_eq!(
        u32::from_le_bytes(
            marker[4..8]
                .try_into()
                .expect("firmware payload-length marker must be four bytes"),
        ),
        payload.len() as u32,
        "firmware-reported payload length differs",
    );
    let firmware_checksum = u32::from_le_bytes(
        marker[8..12]
            .try_into()
            .expect("firmware checksum marker must be four bytes"),
    );
    let host_checksum = payload_checksum(payload);
    assert_eq!(
        firmware_checksum,
        host_checksum,
        "payload bytes changed between host and firmware: \
         index={index}, length={}, firmware_checksum={firmware_checksum:#010x}, \
         host_checksum={host_checksum:#010x}",
        payload.len(),
    );
    assert_eq!(marker[12], index, "firmware selected the wrong OOB buffer");

    let descriptor_count = u16::from_le_bytes(
        marker[13..15]
            .try_into()
            .expect("firmware descriptor-count marker must be two bytes"),
    );
    assert!(
        descriptor_count > 0,
        "firmware parsed no Data Block descriptors"
    );
    assert!(
        descriptor_count <= max_data_block_count(payload.len()),
        "firmware reported implausible descriptor count {descriptor_count}",
    );
    assert!(
        resp.pok_remote_backup[15..].iter().all(|&byte| byte == 0),
        "unused remote-backup bytes must remain zero-filled",
    );
    assert!(
        resp.pok_local_backup.iter().all(|&byte| byte == 0),
        "stub local backup must be zero-filled",
    );
    assert!(
        resp.sd_mk_backup.iter().all(|&byte| byte == 0),
        "stub masking-key backup must be zero-filled",
    );

    descriptor_count
}

#[test]
fn sd_create_remote_backup_oob_transport_smoke() {
    let ctx = TestCtx::new();

    // Open a real CO session under a rotated PSK.  This is the ONLY
    // non-dummy input to the request: the firmware dispatcher rejects
    // any SQE whose session id is not a live session slot, so a
    // fabricated id would fail before the CreateSD FSM is even
    // reached — and then we would learn nothing about OOB parsing.
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    // Two arbitrary OOB payloads with distinct fill bytes so the
    // operator can trace each segment through the driver log and
    // firmware trace independently.
    let oob_a = vec![0xAAu8; OOB_BUF_A_LEN];
    let oob_b = vec![0xBBu8; OOB_BUF_B_LEN];
    let oob_items: Vec<&[u8]> = vec![&oob_a, &oob_b];

    // Every other request field is zeroed / empty.  The stub CreateSD
    // FSM on the firmware side is expected to ignore these and only
    // exercise the metadata-page + SGL walk.
    let req = make_request(session.session_id, 0, oob_a.len());

    eprintln!(
        "[oob smoke] session_id={} issuing SdCreateRemoteBackup with {} OOB buffers ({} + {} bytes)",
        session.session_id,
        oob_items.len(),
        oob_a.len(),
        oob_b.len(),
    );

    let resp = ctx
        .tbor_oob(&req, &oob_items)
        .expect("two-buffer OOB smoke request must succeed");
    assert_stub_response(&resp, 0, &oob_a);

    eprintln!(
        "[oob smoke] Ok response: pok_remote_backup={}B, \
         pok_local_backup={}B, sd_mk_backup={}B",
        resp.pok_remote_backup.len(),
        resp.pok_local_backup.len(),
        resp.sd_mk_backup.len(),
    );
}

#[test]
fn sd_create_remote_backup_oob_positive_size_matrix() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    for &length in POSITIVE_OOB_LENGTHS {
        let fill = (length as u8).wrapping_mul(31).wrapping_add(0x5A);
        let oob = vec![fill; length];
        let oob_items = [oob.as_slice()];
        let req = make_request(session.session_id, 0, length);

        let resp = ctx
            .tbor_oob(&req, &oob_items)
            .unwrap_or_else(|error| panic!("OOB payload length {length} failed: {error:?}"));
        assert_stub_response(&resp, 0, &oob);

        eprintln!("[oob positive size] length={length} response=Ok");
    }
}

#[test]
fn sd_create_remote_backup_oob_bounded_streaming_size_matrix() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    for &length in STREAMING_OOB_LENGTHS {
        let payload = patterned_payload((length as u8).wrapping_add(0x90), length);
        let oob_items = [payload.as_slice()];
        let req = make_request(session.session_id, 0, length);

        let resp = ctx.tbor_oob(&req, &oob_items).unwrap_or_else(|error| {
            panic!("streamed OOB payload length {length} failed: {error:?}")
        });
        let descriptor_count = assert_stub_response(&resp, 0, &payload);

        eprintln!("[oob streaming] length={length} descriptors={descriptor_count} integrity=Ok");
    }
}

#[test]
fn sd_create_remote_backup_oob_selects_second_descriptor() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let oob_a = vec![0xAAu8; OOB_BUF_A_LEN];
    let oob_b = vec![0xBBu8; OOB_BUF_B_LEN];
    let oob_items = [oob_a.as_slice(), oob_b.as_slice()];
    let req = make_request(session.session_id, 1, oob_b.len());

    let resp = ctx
        .tbor_oob(&req, &oob_items)
        .expect("OOB request selecting descriptor index 1 must succeed");
    assert_stub_response(&resp, 1, &oob_b);

    eprintln!(
        "[oob descriptor selection] count={} index=1 length={} integrity=Ok",
        oob_items.len(),
        oob_b.len(),
    );
}

#[test]
fn sd_create_remote_backup_oob_unaligned_page_crossing_payload() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut backing = vec![0u8; HOST_PAGE_SIZE * 2];
    let base_page_offset = backing.as_ptr() as usize & (HOST_PAGE_SIZE - 1);
    let requested_page_offset = HOST_PAGE_SIZE - 31;
    let slice_offset =
        (requested_page_offset + HOST_PAGE_SIZE - base_page_offset) & (HOST_PAGE_SIZE - 1);
    let payload = &mut backing[slice_offset..slice_offset + HOST_PAGE_SIZE];
    for (offset, byte) in payload.iter_mut().enumerate() {
        *byte = 0xC7u8.wrapping_add((offset as u8).wrapping_mul(0x25));
    }

    let actual_page_offset = payload.as_ptr() as usize & (HOST_PAGE_SIZE - 1);
    assert_eq!(actual_page_offset, requested_page_offset);

    let oob_items = [payload as &[u8]];
    let req = make_request(session.session_id, 0, payload.len());
    let resp = ctx
        .tbor_oob(&req, &oob_items)
        .expect("unaligned page-crossing OOB request must succeed");
    let descriptor_count = assert_stub_response(&resp, 0, payload);

    eprintln!(
        "[oob page crossing] page_offset={actual_page_offset} length={} descriptors={} integrity=Ok",
        payload.len(),
        descriptor_count,
    );
}

#[test]
fn sd_create_remote_backup_oob_selects_every_descriptor_at_max_count() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let buffers: Vec<Vec<u8>> = (0..MAX_OOB_BUFFER_COUNT)
        .map(|index| patterned_payload(index as u8, 97 + index * 113))
        .collect();
    let oob_items: Vec<&[u8]> = buffers.iter().map(Vec::as_slice).collect();

    for (index, payload) in buffers.iter().enumerate() {
        let req = make_request(session.session_id, index as u8, payload.len());
        let resp = ctx.tbor_oob(&req, &oob_items).unwrap_or_else(|error| {
            panic!("OOB descriptor index {index} failed at maximum buffer count: {error:?}")
        });
        assert_stub_response(&resp, index as u8, payload);
    }

    eprintln!(
        "[oob max buffer count] count={MAX_OOB_BUFFER_COUNT} selected_all_indices integrity=Ok"
    );
}

#[test]
fn sd_create_remote_backup_oob_repeated_request_stress() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let lengths = [1, 1025, 2049, 4096];
    let buffers: Vec<Vec<u8>> = lengths
        .iter()
        .enumerate()
        .map(|(index, length)| patterned_payload(index as u8 + 0x40, *length))
        .collect();
    let oob_items: Vec<&[u8]> = buffers.iter().map(Vec::as_slice).collect();

    for iteration in 0..OOB_STRESS_ITERATIONS {
        let index = iteration % buffers.len();
        let payload = &buffers[index];
        let req = make_request(session.session_id, index as u8, payload.len());
        let resp = ctx.tbor_oob(&req, &oob_items).unwrap_or_else(|error| {
            panic!("OOB stress iteration {iteration} failed for index {index}: {error:?}")
        });
        assert_stub_response(&resp, index as u8, payload);
    }

    eprintln!(
        "[oob stress] iterations={OOB_STRESS_ITERATIONS} buffers={} integrity=Ok",
        buffers.len(),
    );
}

#[test]
fn sd_create_remote_backup_oob_rejects_out_of_range_report_index() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let payload = patterned_payload(0x81, OOB_BUF_A_LEN);
    let oob_items = [payload.as_slice()];

    let invalid_req = make_request(session.session_id, 1, payload.len());
    ctx.expect_fw_reject_oob(&invalid_req, &oob_items, TborStatus::InvalidArg);

    let valid_req = make_request(session.session_id, 0, payload.len());
    let resp = ctx
        .tbor_oob(&valid_req, &oob_items)
        .expect("valid OOB request after invalid index must succeed");
    assert_stub_response(&resp, 0, &payload);

    eprintln!("[oob negative] out_of_range_index rejected=InvalidArg recovery=Ok");
}

#[test]
fn sd_create_remote_backup_oob_rejects_zero_report_length() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let payload = patterned_payload(0x82, OOB_BUF_A_LEN);
    let oob_items = [payload.as_slice()];

    let invalid_req = make_request(session.session_id, 0, 0);
    ctx.expect_fw_reject_oob(&invalid_req, &oob_items, TborStatus::InvalidArg);

    let valid_req = make_request(session.session_id, 0, payload.len());
    let resp = ctx
        .tbor_oob(&valid_req, &oob_items)
        .expect("valid OOB request after zero length must succeed");
    assert_stub_response(&resp, 0, &payload);

    eprintln!("[oob negative] zero_report_length rejected=InvalidArg recovery=Ok");
}

#[test]
fn sd_create_remote_backup_oob_rejects_report_length_exceeding_buffer() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let payload = patterned_payload(0x83, OOB_BUF_A_LEN);
    let oob_items = [payload.as_slice()];

    let invalid_req = make_request(session.session_id, 0, payload.len() + 1);
    ctx.expect_fw_reject_oob(&invalid_req, &oob_items, TborStatus::InvalidArg);

    let valid_req = make_request(session.session_id, 0, payload.len());
    let resp = ctx
        .tbor_oob(&valid_req, &oob_items)
        .expect("valid OOB request after oversized length must succeed");
    assert_stub_response(&resp, 0, &payload);

    eprintln!("[oob negative] length_exceeds_buffer rejected=InvalidArg recovery=Ok");
}
