use group::{Group as _, GroupEncoding as _};
use pasta_curves::pallas;

use super::{Action, ActionFromPartsError, EncodedAction, EncodedActionError};
use crate::{
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    note_encryption::NoteBytesData,
    primitives::redpallas::{SpendAuth, VerificationKey},
    value::ValueCommitment,
};

fn encoded(cv: [u8; 32], rk: [u8; 32], epk: [u8; 32]) -> EncodedAction<()> {
    EncodedAction {
        cv_net: cv,
        nf: Nullifier::from_bytes(&[1; 32]).unwrap(),
        rk: VerificationKey::<SpendAuth>::try_from(rk).unwrap(),
        cmx: ExtractedNoteCommitment::from_bytes(&[2; 32]).unwrap(),
        encrypted_note: TransmittedNoteCiphertext {
            epk_bytes: epk,
            enc_ciphertext: NoteBytesData([0; 580]),
            out_ciphertext: [0; 80],
        },
        authorization: (),
    }
}

#[test]
fn batch_matches_individual_construction_and_reports_first_error_in_action_order() {
    let valid = pallas::Point::generator().to_bytes();
    let bad = [0xff; 32];
    let identity = pallas::Point::identity().to_bytes();
    let cases = [
        (valid, valid, valid),
        (identity, valid, valid), // Identity is a valid value commitment.
        (bad, valid, valid),
        (valid, identity, valid),
        (valid, valid, identity),
        (valid, valid, bad),
        (bad, identity, bad), // cv has priority over rk and epk.
        (valid, identity, bad), // rk has priority over epk.
    ];

    for size in [1, 2, 3, 4, 5, 8, 9, 17] {
        let inputs: Vec<_> = cases.iter().copied().cycle().take(size).collect();
        let expected: Vec<_> = inputs
            .iter()
            .map(|&(cv, rk, epk)| {
                let cv_net = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&cv))
                    .ok_or(EncodedActionError::InvalidCv)?;
                let part = encoded(cv, rk, epk);
                Action::from_parts(part.nf, part.rk, part.cmx, part.encrypted_note, cv_net, ())
                    .map_err(EncodedActionError::InvalidAction)
            })
            .collect();
        let actual = Action::from_encoded_parts(
            inputs.iter().map(|&(cv, rk, epk)| encoded(cv, rk, epk)).collect(),
        );
        for (actual, expected) in actual.iter().zip(&expected) {
            assert_eq!(actual.as_ref().err(), expected.as_ref().err());
            if let (Ok(actual), Ok(expected)) = (actual, expected) {
                assert_eq!(actual.cv_net().to_bytes(), expected.cv_net().to_bytes());
                assert_eq!(actual.encrypted_note().epk_bytes, expected.encrypted_note().epk_bytes);
            }
        }
    }
    let errors = Action::from_encoded_parts(vec![
        encoded(bad, identity, bad),
        encoded(valid, identity, bad),
        encoded(valid, valid, bad),
    ]);
    assert!(matches!(errors[0], Err(EncodedActionError::InvalidCv)));
    assert!(matches!(errors[1], Err(EncodedActionError::InvalidAction(ActionFromPartsError::IdentityRk))));
    assert!(matches!(errors[2], Err(EncodedActionError::InvalidAction(ActionFromPartsError::InvalidEpk))));
}
