use blake2b_simd::Hash as Blake2bHash;
use proptest::{
    strategy::{Strategy, ValueTree},
    test_runner::TestRunner,
};
use rand::{rngs::StdRng, RngExt, SeedableRng};

use super::{hash_bundle_txid_data, hasher};
use crate::{
    bundle::{testing::arb_unauthorized_bundle, Authorization, Bundle, EffectsOnly, TxVersion},
    value::ValueCommitment,
};

const ACTION_COUNTS: [usize; 6] = [1, 2, 31, 32, 33, 208];
const BUNDLES_PER_COUNT: usize = 4;
const RNG_SEED: u64 = 0;
const IDENTITY_STRIDE: usize = 3;

// The original per-action serialization, retained as an independent digest oracle.
fn original_txid<A: Authorization, V: Copy + Into<i64>>(
    bundle: &Bundle<A, V>,
    tx_version: TxVersion,
) -> Blake2bHash {
    let format = bundle
        .bundle_version()
        .value_pool()
        .commitment_format(tx_version)
        .unwrap();
    let personalizations = format.personalizations();
    let mut h = hasher(personalizations.bundle);
    let mut ch = hasher(personalizations.actions_compact);
    let mut mh = hasher(personalizations.actions_memos);
    let mut nh = hasher(personalizations.actions_noncompact);

    for action in bundle.actions() {
        ch.update(&action.nullifier().to_bytes());
        ch.update(&action.cmx().to_bytes());
        ch.update(&action.encrypted_note().epk_bytes);
        ch.update(&action.encrypted_note().enc_ciphertext.0[..52]);
        mh.update(&action.encrypted_note().enc_ciphertext.0[52..564]);
        nh.update(&action.cv_net().to_bytes());
        nh.update(&<[u8; 32]>::from(action.rk()));
        nh.update(&action.encrypted_note().enc_ciphertext.0[564..]);
        nh.update(&action.encrypted_note().out_ciphertext);
    }

    h.update(ch.finalize().as_bytes());
    h.update(mh.finalize().as_bytes());
    h.update(nh.finalize().as_bytes());
    h.update(&[bundle.flag_byte()]);
    h.update(&(*bundle.value_balance()).into().to_le_bytes());
    if format.includes_anchor_in_txid_digest() {
        h.update(&bundle.anchor().to_bytes());
    }
    h.finalize()
}

fn check_txid(bundle: &Bundle<EffectsOnly, i64>) {
    for tx_version in [TxVersion::V5, TxVersion::V6] {
        if bundle
            .bundle_version()
            .value_pool()
            .commitment_format(tx_version)
            .is_ok()
        {
            assert_eq!(
                hash_bundle_txid_data(bundle, tx_version).unwrap(),
                original_txid(bundle, tx_version),
            );
        }
    }
}

#[test]
fn batch_normalized_txids_match_per_action_serialization() {
    let mut runner = TestRunner::deterministic();
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    for count in ACTION_COUNTS {
        for _ in 0..BUNDLES_PER_COUNT {
            let bundle = arb_unauthorized_bundle(count)
                .new_tree(&mut runner)
                .unwrap()
                .current()
                .try_map_value_balance(|_| Ok::<_, ()>(rng.random::<i64>()))
                .unwrap();
            check_txid(&bundle);

            // Include identities at both normalization lanes and in the middle of each chain.
            let mut actions = bundle.actions().clone();
            let identity = ValueCommitment::from_bytes(&[0; 32]).unwrap();
            for (index, action) in actions.iter_mut().enumerate() {
                if index % IDENTITY_STRIDE == 0 {
                    *action = crate::Action::from_parts(
                        *action.nullifier(),
                        action.rk().clone(),
                        *action.cmx(),
                        action.encrypted_note().clone(),
                        identity.clone(),
                        (),
                    )
                    .unwrap();
                }
            }
            let identity_bundle = Bundle::<EffectsOnly, _>::from_parts(
                actions,
                *bundle.flags(),
                *bundle.value_balance(),
                *bundle.anchor(),
                EffectsOnly,
                bundle.bundle_version(),
            )
            .unwrap();
            check_txid(&identity_bundle);
        }
    }
}
