// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HW-only OOB SGL transport smoke test for `SdCreateRemoteBackup`.
//!
//! Purpose: prove that the SDK Linux backend's new
//! `AZIHSM_CTRL_PATH_DATA_XFER` (ioctl `_IOWR('B', 0x7, ...)`) code
//! path actually reaches the firmware CreateSD FSM — i.e. that the
//! kernel driver accepts the multi-buffer OOB payload, walks the
//! metadata page + per-buffer SGL segments, and hands the SQE to the
//! firmware with `cmd.set = CP_CMD_SET_DATA_XFER (0x1)` plus a non-zero
//! `metadata_page_addr`.
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
//! Pairs with a stub / instrumentation-only CreateSD FSM on the
//! firmware side: the firmware CreateSD FSM is expected to accept the
//! SQE, DMA-read the metadata page + SGL segments, log / dump the
//! buffer layout, and reply — success or a deliberate stub-only
//! reject code — WITHOUT actually running HPKE-Auth seal.  That
//! narrows the failure surface for OOB-parsing bring-up.
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
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;

use crate::commands::part_init::bootstrap_rotated_co;
use crate::commands::part_init::ROTATED_CO_PSK;
use crate::harness::TestCtx;

/// Two dummy OOB buffer sizes.  Kept intentionally different so the
/// operator can spot each buffer's `xfer_length` in the driver /
/// firmware SGL walk (kernel builds one SGL segment per buffer).
const OOB_BUF_A_LEN: usize = 128;
const OOB_BUF_B_LEN: usize = 256;

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
    let req = TborSdCreateRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: [0u8; MASKED_SEALING_KEY_LEN],
        receiver_mfgr_cert_chain: Vec::new(),
        receiver_owner_cert_chain: Vec::new(),
        receiver_part_owner_cert_chain: Vec::new(),
        receiver_report: ReportDescriptor {
            index: 0,
            length: U16::new(oob_a.len() as u16),
        },
        policy: PartPolicy::zeroed(),
    };

    eprintln!(
        "[oob smoke] session_id={} issuing SdCreateRemoteBackup with {} OOB buffers ({} + {} bytes)",
        session.session_id,
        oob_items.len(),
        oob_a.len(),
        oob_b.len(),
    );

    match ctx.tbor_oob(&req, &oob_items) {
        Ok(resp) => {
            // The stub FSM may legitimately return an Ok response
            // (e.g. after successfully DMA-reading the metadata page).
            // Surface it so the operator can eyeball the shape.
            eprintln!(
                "[oob smoke] Ok response: pok_remote_backup={}B, \
                 pok_local_backup={}B, sd_mk_backup={}B",
                resp.pok_remote_backup.len(),
                resp.pok_local_backup.len(),
                resp.sd_mk_backup.len(),
            );
        }
        Err(e) => {
            // If the FSM stub deliberately returns a specific error
            // to signal "OOB parsed OK", the operator inspects the
            // status code here.  A transport-level (non-firmware)
            // error would indicate the ioctl 0x7 path itself broke.
            eprintln!("[oob smoke] firmware response: {e:?}");
        }
    }
}
