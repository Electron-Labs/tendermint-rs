//! Tendermint validators

use serde::{Deserialize, Serialize};
use tendermint_proto::v0_38::types::{
    SimpleValidator as RawSimpleValidator, ValidatorSet as RawValidatorSet,
};
use tendermint_proto::Protobuf;

use crate::{
    account,
    crypto::signature::Verifier,
    crypto::Sha256,
    hash::Hash,
    merkle::{self, MerkleHash},
    prelude::*,
    public_key::deserialize_public_key,
    vote, Error, PublicKey, Signature,
};

/// Validator set contains a vector of validators
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawValidatorSet")]
pub struct Set {
    validators: Vec<Info>,
    proposer: Option<Info>,
    total_voting_power: vote::Power,
}

impl Set {
    pub const MAX_TOTAL_VOTING_POWER: u64 = (i64::MAX / 8) as u64;

    /// Constructor
    pub fn new(validators: Vec<Info>, proposer: Option<Info>) -> Set {
        Self::try_from_parts(validators, proposer, 0).unwrap()
    }

    fn try_from_parts(
        mut validators: Vec<Info>,
        proposer: Option<Info>,
        unvalidated_total_voting_power: i64,
    ) -> Result<Set, Error> {
        // Compute the total voting power
        let total_voting_power = validators
            .iter()
            .map(|v| v.power.value())
            .fold(0u64, |acc, v| acc.saturating_add(v));

        if total_voting_power > Self::MAX_TOTAL_VOTING_POWER {
            return Err(Error::total_voting_power_overflow());
        }

        // The conversion cannot fail as we have validated against a smaller limit.
        let total_voting_power: vote::Power = total_voting_power.try_into().unwrap();

        // If the given total voting power is not the default value,
        // validate it against the sum of voting powers of the participants.
        if unvalidated_total_voting_power != 0 {
            let given_val: vote::Power = unvalidated_total_voting_power.try_into()?;
            if given_val != total_voting_power {
                return Err(Error::total_voting_power_mismatch());
            }
        }

        Self::sort_validators(&mut validators);

        Ok(Set {
            validators,
            proposer,
            total_voting_power,
        })
    }

    /// Convenience constructor for cases where there is no proposer
    pub fn without_proposer(validators: Vec<Info>) -> Set {
        Self::new(validators, None)
    }

    /// Convenience constructor for cases where there is a proposer
    pub fn with_proposer(
        validators: Vec<Info>,
        proposer_address: account::Id,
    ) -> Result<Self, Error> {
        // Get the proposer.
        let proposer = validators
            .iter()
            .find(|v| v.address == proposer_address)
            .cloned()
            .ok_or_else(|| Error::proposer_not_found(proposer_address))?;

        // Create the validator set with the given proposer.
        // This is required by IBC on-chain validation.
        Ok(Self::new(validators, Some(proposer)))
    }

    /// Get Info of the underlying validators.
    pub fn validators(&self) -> &Vec<Info> {
        &self.validators
    }

    /// Get proposer
    pub fn proposer(&self) -> &Option<Info> {
        &self.proposer
    }

    /// Get total voting power
    pub fn total_voting_power(&self) -> vote::Power {
        self.total_voting_power
    }

    /// Sort the validators according to the current Tendermint requirements
    /// (v. 0.34 -> first by validator power, descending, then by address, ascending)
    fn sort_validators(vals: &mut [Info]) {
        vals.sort_by_key(|v| (core::cmp::Reverse(v.power), v.address));
    }

    /// Returns the validator with the given Id if its in the Set.
    pub fn validator(&self, val_id: account::Id) -> Option<Info> {
        self.validators
            .iter()
            .find(|val| val.address == val_id)
            .cloned()
    }

    /// Compute the hash of this validator set.
    #[cfg(feature = "rust-crypto")]
    pub fn hash(&self) -> Hash {
        self.hash_with::<crate::crypto::default::Sha256>()
    }

    /// Hash this header with a SHA256 hasher provided by a crypto provider.
    pub fn hash_with<H>(&self) -> Hash
    where
        H: MerkleHash + Sha256 + Default,
    {
        let validator_bytes: Vec<Vec<u8>> = self
            .validators()
            .iter()
            .map(|validator| validator.hash_bytes())
            .collect();

        Hash::Sha256(merkle::simple_hash_from_byte_vectors::<H>(&validator_bytes))
    }
}

/// Validator information
// Todo: Remove address and make it into a function that generates it on the fly from pub_key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    /// Validator account address
    pub address: account::Id,

    /// Validator public key
    pub pub_key: PublicKey,

    /// Validator voting power
    // Compatibility with genesis.json https://github.com/tendermint/tendermint/issues/5549
    #[serde(alias = "voting_power", alias = "total_voting_power")]
    pub power: vote::Power,

    /// Validator name
    pub name: Option<String>,

    /// Validator proposer priority
    #[serde(skip)]
    pub proposer_priority: ProposerPriority,
}

impl Info {
    /// Return the voting power of the validator.
    pub fn power(&self) -> u64 {
        self.power.value()
    }

    /// Verify the given signature against the given sign_bytes using the validators
    /// public key.
    pub fn verify_signature<V>(&self, sign_bytes: &[u8], signature: &Signature) -> Result<(), Error>
    where
        V: Verifier,
    {
        V::verify(self.pub_key, sign_bytes, signature)
            .map_err(|_| Error::signature_invalid("Ed25519 signature verification failed".into()))
    }

    #[cfg(feature = "rust-crypto")]
    /// Create a new validator.
    pub fn new(pk: PublicKey, vp: vote::Power) -> Info {
        Info {
            address: account::Id::from(pk),
            pub_key: pk,
            power: vp,
            name: None,
            proposer_priority: ProposerPriority::default(),
        }
    }
}

/// SimpleValidator is the form of the validator used for computing the Merkle tree.
/// It does not include the address, as that is redundant with the pubkey,
/// nor the proposer priority, as that changes with every block even if the validator set didn't.
/// It contains only the pubkey and the voting power.
/// TODO: currently only works for Ed25519 pubkeys
#[derive(Clone, PartialEq, Eq)]
pub struct SimpleValidator {
    /// Public key
    pub pub_key: PublicKey,
    /// Voting power
    pub voting_power: vote::Power,
}

/// Info -> SimpleValidator
impl From<&Info> for SimpleValidator {
    fn from(info: &Info) -> SimpleValidator {
        SimpleValidator {
            pub_key: info.pub_key,
            voting_power: info.power,
        }
    }
}

impl Info {
    /// Returns the bytes to be hashed into the Merkle tree -
    /// the leaves of the tree.
    pub fn hash_bytes(&self) -> Vec<u8> {
        Protobuf::<RawSimpleValidator>::encode_vec(SimpleValidator::from(self))
    }
}

// Todo: Is there more knowledge/restrictions about proposerPriority?
/// Proposer priority
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Default)]
pub struct ProposerPriority(i64);

impl From<i64> for ProposerPriority {
    fn from(value: i64) -> Self {
        ProposerPriority(value)
    }
}

impl From<ProposerPriority> for i64 {
    fn from(priority: ProposerPriority) -> i64 {
        priority.value()
    }
}

impl ProposerPriority {
    /// Get the current proposer priority
    pub fn value(self) -> i64 {
        self.0
    }
}

/// A change to the validator set.
///
/// Used to inform Tendermint of changes to the validator set.
///
/// [ABCI documentation](https://docs.tendermint.com/master/spec/abci/abci.html#validatorupdate)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Update {
    /// Validator public key
    #[serde(deserialize_with = "deserialize_public_key")]
    pub pub_key: PublicKey,

    /// New voting power
    #[serde(default)]
    pub power: vote::Power,
}

// =============================================================================
// Protobuf conversions
// =============================================================================

tendermint_pb_modules! {
    use pb::{
        abci::ValidatorUpdate as RawValidatorUpdate,
        types::{
            SimpleValidator as RawSimpleValidator, Validator as RawValidator,
            ValidatorSet as RawValidatorSet,
        },
    };
    use super::{Info, Set, SimpleValidator, Update};
    use crate::{prelude::*, Error};

    impl Protobuf<RawValidatorSet> for Set {}

    impl TryFrom<RawValidatorSet> for Set {
        type Error = Error;

        fn try_from(value: RawValidatorSet) -> Result<Self, Self::Error> {
            let validators = value
                .validators
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?;

            let proposer = value.proposer.map(TryInto::try_into).transpose()?;

            Self::try_from_parts(validators, proposer, value.total_voting_power)
        }
    }

    impl From<Set> for RawValidatorSet {
        fn from(value: Set) -> Self {
            RawValidatorSet {
                validators: value.validators.into_iter().map(Into::into).collect(),
                proposer: value.proposer.map(Into::into),
                total_voting_power: value.total_voting_power.into(),
            }
        }
    }

    impl TryFrom<RawValidator> for Info {
        type Error = Error;

        fn try_from(value: RawValidator) -> Result<Self, Self::Error> {
            Ok(Info {
                address: value.address.try_into()?,
                pub_key: value
                    .pub_key
                    .ok_or_else(Error::missing_public_key)?
                    .try_into()?,
                power: value.voting_power.try_into()?,
                name: None,
                proposer_priority: value.proposer_priority.into(),
            })
        }
    }

    impl From<Info> for RawValidator {
        fn from(value: Info) -> Self {
            RawValidator {
                address: value.address.into(),
                pub_key: Some(value.pub_key.into()),
                voting_power: value.power.into(),
                proposer_priority: value.proposer_priority.into(),
            }
        }
    }

    impl Protobuf<RawSimpleValidator> for SimpleValidator {}

    impl TryFrom<RawSimpleValidator> for SimpleValidator {
        type Error = Error;

        fn try_from(value: RawSimpleValidator) -> Result<Self, Self::Error> {
            Ok(SimpleValidator {
                pub_key: value.pub_key
                    .ok_or_else(Error::missing_public_key)?
                    .try_into()?,
                voting_power: value.voting_power.try_into()?,
            })
        }
    }

    impl From<SimpleValidator> for RawSimpleValidator {
        fn from(value: SimpleValidator) -> Self {
            RawSimpleValidator {
                pub_key: Some(value.pub_key.into()),
                voting_power: value.voting_power.into(),
            }
        }
    }

    impl Protobuf<RawValidatorUpdate> for Update {}

    impl From<Update> for RawValidatorUpdate {
        fn from(vu: Update) -> Self {
            Self {
                pub_key: Some(vu.pub_key.into()),
                power: vu.power.into(),
            }
        }
    }

    impl TryFrom<RawValidatorUpdate> for Update {
        type Error = Error;

        fn try_from(vu: RawValidatorUpdate) -> Result<Self, Self::Error> {
            Ok(Self {
                pub_key: vu
                    .pub_key
                    .ok_or_else(Error::missing_public_key)?
                    .try_into()?,
                power: vu.power.try_into()?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::println;
    #[cfg(feature = "rust-crypto")]
    mod crypto {
        use super::*;

        // make a validator
        fn make_validator(pk: Vec<u8>, vp: u64) -> Info {
            let pk = PublicKey::from_raw_ed25519(&pk).unwrap();
            Info::new(pk, vote::Power::try_from(vp).unwrap())
        }

        #[test]
        fn test_validator_set() {
            // test vector generated by Go code
            // import (
            // "fmt"
            // "github.com/tendermint/tendermint/crypto/ed25519"
            // "github.com/tendermint/tendermint/types"
            // "strings"
            // )
            // func testValSet() {
            // pk1 := ed25519.GenPrivKeyFromSecret([]byte{4, 211, 14, 157, 10, 0, 205, 9, 10, 116, 207,
            // 161, 4, 211, 190, 37, 108, 88, 202, 168, 63, 135, 0, 141, 53, 55, 254, 57, 40, 184, 20,
            // 242}) pk2 := ed25519.GenPrivKeyFromSecret([]byte{99, 231, 126, 151, 159, 236, 2,
            // 229, 33, 44, 200, 248, 147, 176, 13, 127, 105, 76, 49, 83, 25, 101, 44, 57, 20, 215, 166,
            // 188, 134, 94, 56, 165}) pk3 := ed25519.GenPrivKeyFromSecret([]byte{54, 253, 151,
            // 16, 182, 114, 125, 12, 74, 101, 54, 253, 174, 153, 121, 74, 145, 180, 111, 16, 214, 48,
            // 193, 109, 104, 134, 55, 162, 151, 16, 182, 114}) not_in_set :=
            // ed25519.GenPrivKeyFromSecret([]byte{121, 74, 145, 180, 111, 16, 214, 48, 193, 109, 35,
            // 68, 19, 27, 173, 69, 92, 204, 127, 218, 234, 81, 232, 75, 204, 199, 48, 163, 55, 132,
            // 231, 147}) fmt.Println("pk1: ", strings.Join(strings.Split(fmt.Sprintf("%v",
            // pk1.PubKey().Bytes()), " "), ", ")) fmt.Println("pk2:",
            // strings.Join(strings.Split(fmt.Sprintf("%v", pk2.PubKey().Bytes()), " "), ", "))
            // fmt.Println("pk3: ", strings.Join(strings.Split(fmt.Sprintf("%v", pk3.PubKey().Bytes()),
            // " "), ", ")) fmt.Println("not_in_set: ",
            // strings.Join(strings.Split(fmt.Sprintf("%v", not_in_set.PubKey().Bytes()), " "), ", "))
            // v1 := types.NewValidator(pk1.PubKey(), 148151478422287875)
            // v2 := types.NewValidator(pk2.PubKey(), 158095448483785107)
            // v3 := types.NewValidator(pk3.PubKey(), 770561664770006272)
            // set := types.NewValidatorSet([]*types.Validator{v1, v2, v3})
            // fmt.Println("Hash:", strings.Join(strings.Split(fmt.Sprintf("%v", set.Hash()), " "), ",
            // ")) }
            let v1 = make_validator(
                vec![
                    48, 163, 55, 132, 231, 147, 230, 163, 56, 158, 127, 218, 179, 139, 212, 103,
                    218, 89, 122, 126, 229, 88, 84, 48, 32, 0, 185, 174, 63, 72, 203, 52,
                ],
                148_151_478_422_287_875,
            );
            let v2 = make_validator(
                vec![
                    54, 253, 174, 153, 121, 74, 145, 180, 111, 16, 214, 48, 193, 109, 104, 134, 55,
                    162, 151, 16, 182, 114, 125, 135, 32, 195, 236, 248, 64, 112, 74, 101,
                ],
                158_095_448_483_785_107,
            );
            let v3 = make_validator(
                vec![
                    182, 205, 13, 86, 147, 27, 65, 49, 160, 118, 11, 180, 117, 35, 206, 35, 68, 19,
                    27, 173, 69, 92, 204, 224, 200, 51, 249, 81, 105, 128, 112, 244,
                ],
                770_561_664_770_006_272,
            );
            let hash_expect = vec![
                11, 64, 107, 4, 234, 81, 232, 75, 204, 199, 160, 114, 229, 97, 243, 95, 118, 213,
                17, 22, 57, 84, 71, 122, 200, 169, 192, 252, 41, 148, 223, 180,
            ];

            let val_set = Set::without_proposer(vec![v1.clone(), v2.clone(), v3.clone()]);
            let hash = val_set.hash();
            assert_eq!(hash_expect, hash.as_bytes().to_vec());

            let not_in_set = make_validator(
                vec![
                    110, 147, 87, 120, 27, 218, 66, 209, 81, 4, 169, 153, 64, 163, 137, 89, 168,
                    97, 219, 233, 42, 119, 24, 61, 47, 59, 76, 31, 182, 60, 13, 4,
                ],
                10_000_000_000_000_000,
            );

            assert_eq!(val_set.validator(v1.address).unwrap(), v1);
            assert_eq!(val_set.validator(v2.address).unwrap(), v2);
            assert_eq!(val_set.validator(v3.address).unwrap(), v3);
            assert_eq!(val_set.validator(not_in_set.address), None);
            assert_eq!(
                val_set.total_voting_power().value(),
                148_151_478_422_287_875 + 158_095_448_483_785_107 + 770_561_664_770_006_272
            );
        }
        
    }

    #[test]
    fn deserialize_validator_updates() {
        const FMT1: &str = r#"{
            "pub_key": {
                "Sum": {
                    "type": "tendermint.crypto.PublicKey_Ed25519",
                    "value": {
                        "ed25519": "VqJCr3vjQdffcLIG6RMBl2MgXDFYNY6b3Joaa43gV3o="
                    }
                }
            },
            "power": "573929"
        }"#;
        const FMT2: &str = r#"{
            "pub_key": {
                "type": "tendermint/PubKeyEd25519",
                "value": "VqJCr3vjQdffcLIG6RMBl2MgXDFYNY6b3Joaa43gV3o="
            },
            "power": "573929"
        }"#;

        let update1 = serde_json::from_str::<Update>(FMT1).unwrap();
        let update2 = serde_json::from_str::<Update>(FMT2).unwrap();

        assert_eq!(u64::from(update1.power), 573929);
        assert_eq!(update1, update2);
    }

    #[test]
    fn validator_set_deserialize_all_fields() {
        const VSET: &str = r#"{
            "validators": [
                {
                    "address": "01F527D77D3FFCC4FCFF2DDC2952EEA5414F2A33",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "OAaNq3DX/15fGJP2MI6bujt1GRpvjwrqIevChirJsbc="
                    },
                    "voting_power": "50",
                    "proposer_priority": "-150"
                },
                {
                    "address": "026CC7B6F3E62F789DBECEC59766888B5464737D",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "+vlsKpn6ojn+UoTZl+w+fxeqm6xvUfBokTcKfcG3au4="
                    },
                    "voting_power": "42",
                    "proposer_priority": "50"
                }
            ],
            "proposer": {
                "address": "01F527D77D3FFCC4FCFF2DDC2952EEA5414F2A33",
                "pub_key": {
                    "type": "tendermint/PubKeyEd25519",
                    "value": "OAaNq3DX/15fGJP2MI6bujt1GRpvjwrqIevChirJsbc="
                },
                "voting_power": "50",
                "proposer_priority": "-150"
            },
            "total_voting_power": "92"
        }"#;

        let vset = serde_json::from_str::<Set>(VSET).unwrap();
        println!("vset: {:?}",vset);
        assert_eq!(vset.total_voting_power().value(), 92);
    }

    #[test]
    fn validator_set_deserialize_no_total_voting_power() {
        const VSET: &str = r#"{
            "validators": [
                {
                    "address": "01F527D77D3FFCC4FCFF2DDC2952EEA5414F2A33",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "OAaNq3DX/15fGJP2MI6bujt1GRpvjwrqIevChirJsbc="
                    },
                    "voting_power": "50",
                    "proposer_priority": "-150"
                },=
                {
                    "address": "026CC7B6F3E62F789DBECEC59766888B5464737D",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "+vlsKpn6ojn+UoTZl+w+fxeqm6xvUfBokTcKfcG3au4="
                    },
                    "voting_power": "42",
                    "proposer_priority": "50"
                }
            ],
            "proposer": {
                "address": "01F527D77D3FFCC4FCFF2DDC2952EEA5414F2A33",
                "pub_key": {
                    "type": "tendermint/PubKeyEd25519",
                    "value": "OAaNq3DX/15fGJP2MI6bujt1GRpvjwrqIevChirJsbc="
                },
                "voting_power": "50",
                "proposer_priority": "-150"
            }
        }"#;

        let vset = serde_json::from_str::<Set>(VSET).unwrap();
        assert_eq!(vset.total_voting_power().value(), 92);
    }
    #[test]
    fn validator_hash_verification(){

        const VSET: &str = r#"{"validators": [{"address": "CB5A63B91E8F4EE8DB935942CBE25724636479E0",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "6Nz09YGHzwWxjczG0IhK4Iv0qY2IcX0P/5KitvRXTUc="},
        "voting_power": "21761047",
        "proposer_priority": "-58483176"},
       {"address": "1F7249F418B90714BF52797336B771B5AD467533",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "sf07FnpIA9d4EPZ1F5gh0opcbJiB6u6WzGHZ7qq6FWM="},
        "voting_power": "21293790",
        "proposer_priority": "-67339395"},
       {"address": "E08FBA0FE999707D1496BAAB743EAB27784DC1C5",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "3g5KC6fJ2YYRoN583mKdstLi5egwt2CkyR0yiWIRlQw="},
        "voting_power": "15147280",
        "proposer_priority": "92706385"},
       {"address": "9D0281786872D3BBE53C58FBECA118D86FA82177",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "dfTEd6+krWYzqsBcpqdxySq+iwh7SGcwnBO8XaW2qKY="},
        "voting_power": "14141431",
        "proposer_priority": "41234136"},
       {"address": "765550228CF309BDD33F3F5E768350BA3D69C3B1",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "Vtyc3RAyUf9vWhQ5RlsQdaQNFLt22ZFYxvSHU6d0IKc="},
        "voting_power": "13748753",
        "proposer_priority": "-53575536"},
       {"address": "66B69666EBF776E7EBCBE197ABA466A712E27076",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "wB25StLxbzmD0uTiFiH6xySZd0H13kyanNUvvlUpa34="},
        "voting_power": "6971879",
        "proposer_priority": "151432071"},
       {"address": "A16E480524D636B2DA2AD18483327C2E10A5E8A0",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "Yd2RYHyC0I3G34ZMld5rs94e4S5L1TnWaBDaDIhhpSg="},
        "voting_power": "5394655",
        "proposer_priority": "58102137"},
       {"address": "40CC723314B6EBB93B49FBD9D330EEC8B4641CAB",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "Bgne/8a3qUJfLL4WZvVKFHY6FluVElpzmG7XCqBGaQA="},
        "voting_power": "5138434",
        "proposer_priority": "165805990"},
       {"address": "D24B7A32413338C2AA26FC0016D91FBE73BB5EAE",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "p7vsAmhAKlKj7MOYEx5Ht0N0wGua0On35WzW7q3eFh4="},
        "voting_power": "5044758",
        "proposer_priority": "43722477"},
       {"address": "1B002B6EBEB8653C721301B1B56472B1B4DE7247",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "galx4JN7FbjF2scxKj0u7h1pwNQ/NyPu96rhIermC6s="},
        "voting_power": "4977840",
        "proposer_priority": "-56504542"},
       {"address": "71DF8D9879C20563A4E2ABEDA95CD1FC57DBF6AA",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "DCJh91Oqh9P76gYC71pFSzd0cxnvqRDyZ6/PLFZfgLE="},
        "voting_power": "4845043",
        "proposer_priority": "-24980861"},
       {"address": "131FC79E7A012D9E7EEF21DE3BA5D5033FCDBC1F",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "jd4Dwn3GrqBTcwNpuXaOmge1gNyja9SmYZso6e8xAHA="},
        "voting_power": "4774359",
        "proposer_priority": "43318194"},
       {"address": "768A82700E3046E6DAF849664579E649597CC1B4",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "Nu3YALmVf7kvRXbCCxliwcPHmD8vmRMr9Q39lbK41w4="},
        "voting_power": "4551883",
        "proposer_priority": "-120462038"},
       {"address": "72B1489EFB57A680577A838A5BAAEBE162A7C802",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "cNRUrOt4I5rJcsAVhUOiBvOLYRSFx4dso22bcUEhtnI="},
        "voting_power": "4373396",
        "proposer_priority": "129141914"},
       {"address": "16A169951A878247DBE258FDDC71638F6606D156",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "b77zCh/VsRgVvfGXuW4dB+Dhg4PrMWWBC5G2K/qFgiU="},
        "voting_power": "4365141",
        "proposer_priority": "106207923"},
       {"address": "37714C4DA407C9D13CDA424AAE78C3B28515A15C",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "8xwMEQDI4xoD2Z300f8vpjb4kbYQVud57RgWhlrtBtM="},
        "voting_power": "4358750",
        "proposer_priority": "144517158"},
       {"address": "6239A498C22DF3EC3FB0CA2F96D15535F6F3387A",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "/k7X8YEOE3HtRC91Gq9rWh3Kddk2ls5gyeUThZjq4Do="},
        "voting_power": "4310237",
        "proposer_priority": "-110133161"},
       {"address": "99063B919404B6950A79A6A31E370378FE07020D",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "T1wp5ELzvqVOqBm6eGYiQQWe0TaC2LV2BThHaVxh/rk="},
        "voting_power": "3992955",
        "proposer_priority": "136519708"},
       {"address": "2022FE8CC49E48630C76160E11A880459219D244",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "nq6+oDBXYSKLIR2vksOeGM9iVT3+RtIyWAWEUqcOoO4="},
        "voting_power": "3982555",
        "proposer_priority": "-75314602"},
       {"address": "03C016AB7EC32D9F8D77AFDB191FBF53EA08D917",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "OdVpTfLCvPyBLeE6jNxesgy3Hg1IiA+165lSusZDgLs="},
        "voting_power": "3908508",
        "proposer_priority": "131610828"},
       {"address": "7341E970B9B3EFF82B2060D3469FC50D7AF04146",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "O/sG64fmO9/rnRfkJfCZDNm7KY3ieRM8vCU5hCdyUzU="},
        "voting_power": "3819536",
        "proposer_priority": "25001331"},
       {"address": "F3F55DA24BB47DA60B0FB71EC1A9C9274BCEEDB2",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "jjcSFNFQ8q+t/xHr1uYdI2/c1sPwAD17uKg+AyOWTe4="},
        "voting_power": "3498023",
        "proposer_priority": "-106589297"},
       {"address": "51D7D05A659208A6576190AEBBE8F07603851515",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "YusezK9A/ivVeYQl9AO00x7aS4nFkxEbinwZHhsgVPg="},
        "voting_power": "3473161",
        "proposer_priority": "-103520383"},
       {"address": "E191E654D06B9F721568BB945B2EB51DDC1C8FDC",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "SIinCf4GKmuqG1u01EZCy+PNY/f+8sQjPwynG2akkg8="},
        "voting_power": "3448757",
        "proposer_priority": "-122430503"},
       {"address": "7EDB006522610C58283E30644A14F27BCC0D32ED",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "zzZWZApRCaCX1YIzZQAxcHR5JX+r/zWJv/nT7mek4t0="},
        "voting_power": "3418346",
        "proposer_priority": "-67807348"},
       {"address": "39327692C258A57970EF53F0AA4D3C00F95988B8",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "VZg6hSDRkaeEasT9BuYv/aNQ10RoLMeTEweityKVNr8="},
        "voting_power": "3353245",
        "proposer_priority": "-138131274"},
       {"address": "5F999A4BE254869925A7F2FEA04D7B3B836CFF0B",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "FPpZYlaX1njcZNXS+W0pAm3auPqoOQ6ecoZYfEUBd5U="},
        "voting_power": "3271220",
        "proposer_priority": "-84058884"},
       {"address": "8B1D5676F4C0C871A0C7864850D451D6A8AC8E3B",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "tqaHRk1wkuqHMjfN6kDS1ymU5VZDC1XLmFNFIRkto3o="},
        "voting_power": "3224436",
        "proposer_priority": "-33687502"},
       {"address": "AF195943E44FE1D6250076B8BC1910EABC85F1F2",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "j4Mh60mc9b88H4uCOpmOQ4jYkzBbX41x+AP+CFWm3Ns="},
        "voting_power": "3037097",
        "proposer_priority": "-97949727"},
       {"address": "B0B35FED40DAA5FF9D4BC685C75925187F622119",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "w/cYALnzUUHfP0Ej/N0GcWk8Kl6q5+CnIqxbrX4A2vk="},
        "voting_power": "3009742",
        "proposer_priority": "106784391"},
       {"address": "6912E0BA38CD00C9F2FC9E71E971ECED507B42FD",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "o1AuX3mpuHTs6Gz4BoU8R9Jj08z7/jJ6yVVoqc2VFJA="},
        "voting_power": "3001818",
        "proposer_priority": "178359914"},
       {"address": "A06B5B682B425AD206A35CAF246FD70DD098E506",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "00VGuZFAeenn/Zf8rYqNowyUnTzPo3zcu/LKptGInHU="},
        "voting_power": "2909495",
        "proposer_priority": "62341870"},
       {"address": "F194DD4A8AD83323C3E9C2A93DB25F049621C7B4",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "oboi39aVwyap22GNEnO/xV39Kvv+/njYlKzqXDHQ/u4="},
        "voting_power": "2872647",
        "proposer_priority": "103408732"},
       {"address": "9E7CAE009EFFF4D163F3FB8781A07B25C2B10B32",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "m/n7S1ZO+kUtI7+xgCGnklo5iXgMdI9Qvif2VcvHYjg="},
        "voting_power": "2866887",
        "proposer_priority": "132814086"},
       {"address": "8E0545B1222E7B5C85CE69EDC78F280CB2B79D18",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "vYNTZWxKhe3Un6gF+qX6cVB3o/KG4YxMC4/IgRTK0z4="},
        "voting_power": "2824277",
        "proposer_priority": "133122962"},
       {"address": "C02F531D9BBBA4907511EF2680421CE714A11E3B",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "I9sfSptsfnwEOIY8fRT3GezAiOs7H8in/mB0lkR/rE4="},
        "voting_power": "2809861",
        "proposer_priority": "-53253124"},
       {"address": "04C83AA20F7563BBCBCF6AA150EF6B0C81808DAA",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "95HMDW5006ssh50NO61qSXj94ZqRXGe1Ta78qy7u6Z0="},
        "voting_power": "2791528",
        "proposer_priority": "-136560222"},
       {"address": "40C48839CD487D8A13D65955B7FC6C4F560D8F72",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "u6iZIVGM1il2+eaishuCM1gOjJMJlM6mPL5trWWsbao="},
        "voting_power": "2674585",
        "proposer_priority": "-11652742"},
       {"address": "7E0ED7689B65C345D1C817C5B0332FD132DE5875",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "RfEMj+BAig8+YIjwIlquGWA7VRO1CMfign6PtwEct6k="},
        "voting_power": "2643712",
        "proposer_priority": "-151739649"},
       {"address": "5E809E91EAB69D385784D191140E9C8CF6DD1037",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "LCCt4CBSrkDvSDHWMB7vepYZ4swoq1A0rOpmRM4+Y6c="},
        "voting_power": "2501562",
        "proposer_priority": "8196923"},
       {"address": "F9A968A405FB0429410AE5165E5F2193271E678A",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "wWiuQR6CYq2S31ogvrDrYD8iI3V1chILJ6xie+JrRJ8="},
        "voting_power": "2497570",
        "proposer_priority": "16884406"},
       {"address": "E12CEF3871B9595EF15401EED2466E9310E4816B",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "C3nYl+FLAdbkTkrvP8OhgdyUQH4DpID5pT27oSj8Xlo="},
        "voting_power": "2462577",
        "proposer_priority": "-60933676"},
       {"address": "9F8EC2EF581CE25630C819F19B5484039E748D1A",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "d2hzX/3wrmjtrb+jAKUUvO95VeejdRoxTHdQY7/8gLo="},
        "voting_power": "2435502",
        "proposer_priority": "-141376631"},
       {"address": "273F72EE55987AFA771B27D370FA131F608B83AC",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "GPlrdJ5z/EbXbUKc3xIcQn+LOU1UaF4kyk7CfvephJg="},
        "voting_power": "2379243",
        "proposer_priority": "176423604"},
       {"address": "76F706AE73A8251652BC72CB801E4294E2135AFB",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "vNya6ReeIsgTR3h7cNq0uDwIX9Zcn4Sx/ZAFQW9oS7U="},
        "voting_power": "2375181",
        "proposer_priority": "53636604"},
       {"address": "06F45C36FCB957E55D923A6D4E905C2D715115AD",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "LOUaDTS0YZS70HjBwr9ARerXMXbXxFPsSxQ47uNmAvA="},
        "voting_power": "2343357",
        "proposer_priority": "-20777556"},
       {"address": "63481F6DCAAF733D2FC953A335C2200EE190862C",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "Z3A0fCkaKR09vvDT7x18I2IczxvVpezksPpsYyK1n2Y="},
        "voting_power": "2304403",
        "proposer_priority": "-133839908"},
       {"address": "D8A6C54C54A236D4843BA566520BA03F60F09E35",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "8YRkE4YdrBPXVK9hgiLYKbrgnNUYJsGGfc8Kd/tOWuo="},
        "voting_power": "2295337",
        "proposer_priority": "93304761"},
       {"address": "DBCD765DB2640631946C1393BA255876C76DA38E",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "UN3akx4LNxT6+vVjf02dzkYb5nPp2Xb1iB9VBisxHeg="},
        "voting_power": "2282333",
        "proposer_priority": "-148498313"},
       {"address": "97AFE45395B74E784C88D45E5CCA2995019FAE08",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "ZH2TWvk7bd8MLjDHLItvOJUv+ElgfItJO4V4XnXedVw="},
        "voting_power": "2245669",
        "proposer_priority": "-16491288"},
       {"address": "9CBEC8CBD4ED3AAD4BB2B0346EFC86A6C41F9160",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "b84FxoaG4k9IKQYNpzqH16nCA35zmAumrhtSPJvMIcc="},
        "voting_power": "2182278",
        "proposer_priority": "25138888"},
       {"address": "712BC891AEB721DA72732BC30D531E0C1EAEDAE0",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "oktjjZcWn7edjx14blWO7V1mhhCkgvBegXzXWD9s9aA="},
        "voting_power": "2158336",
        "proposer_priority": "-112723534"},
       {"address": "E03B985E6C8905E184D88C995CC632AA278981EB",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "JA+BhI3nie9tR+lRCDb3nyZB60tbhHXh7MNWpTarJuI="},
        "voting_power": "2116835",
        "proposer_priority": "45482005"},
       {"address": "95B002DE67707313D123D06492F1A7A58478E546",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "PA+RvSpVTcAWBD/+nxXltHLaOdaUzbrpNGfjMak/usU="},
        "voting_power": "2109064",
        "proposer_priority": "123250002"},
       {"address": "20EFE186DA91A00AC7F042CD6CB6A1E882C583C7",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "/Jn6UX0QVWVOquEg5RWUxMkUR8Q9dRyc7gkmv92DBJQ="},
        "voting_power": "1982705",
        "proposer_priority": "-93501260"},
       {"address": "2712CF68AF6982B4BD7536B94CDD0D104A0313F4",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "4ICana8QvCEuAcXm/O35Kr6TFEQWQhP6KU1vCyOm54g="},
        "voting_power": "1957472",
        "proposer_priority": "34014097"},
       {"address": "943547CACB29C55797E121ACB4E586C49D9D39FD",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "+WKfNubooCpEdJE93a+kKMfn/YjJhi9DB5aZZNS9dp4="},
        "voting_power": "1941749",
        "proposer_priority": "9504997"},
       {"address": "4E154C9288E31436BA814DD92D17C4ED6CEFD3F1",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "d0bdUFPpo0HhlikzHJURLoIXvUiUEvO28q4IncjPy9U="},
        "voting_power": "1856469",
        "proposer_priority": "93718027"},
       {"address": "8445CF55CB51278E63B2131ADB65A81DC2389D8E",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "95JajJJUe/5dMyFROHQGpbxbaOwAhEfQ3Sy8O5NL5mc="},
        "voting_power": "1849607",
        "proposer_priority": "124227314"},
       {"address": "9CBF2EFFD5570B3A9A41346244757CDA3E18D401",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "PwTrMSmKul2l8xfN3RmAryyVv2+PvwG9XpZxf4Vc4uM="},
        "voting_power": "1805985",
        "proposer_priority": "126289472"},
       {"address": "C9E615289D1D92E50292C3B0BD8358D9B2E40290",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "gWt6q+82LR2nMWHo7k2q5LGLsXzuZGajZQVFyqkzygY="},
        "voting_power": "1754570",
        "proposer_priority": "-14466775"},
       {"address": "46DEA137CFB10BC419B2577AA9A58718680E18BA",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "JMF1mzG8fj0a0gSlvq9tP1aDL7ZncTWl/q7LoroytRs="},
        "voting_power": "1745546",
        "proposer_priority": "60985988"},
       {"address": "CEFE7D654B523DEA2A9ED718A591126C74171689",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "JFBDo7s/NlWnoI6hby4ayqstSzsiD8T6KabxVTDZUz0="},
        "voting_power": "1743250",
        "proposer_priority": "43550713"},
       {"address": "966FD89B1DB51535F2D898CF9B0F14DA374EFB96",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "RldYpYQCj26AeZq6tH6uC0ySp9vMYrwIuJowyWiVaTg="},
        "voting_power": "1742658",
        "proposer_priority": "-123762751"},
       {"address": "04446DA0BCC4310003F97B1BED07AB2ABEC6FEA7",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "MKPR9uSBYxuCswBITqGu0MUDx/NBd2PKPkOyZqZTCbE="},
        "voting_power": "1730606",
        "proposer_priority": "-144571109"},
       {"address": "692174B3FFBBA80394A94DC92665DC0144FBA837",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "+icGUVeybNaYc43iNDL0ivcmm9t9/iWi2/1Ac4F1rcU="},
        "voting_power": "1703404",
        "proposer_priority": "-4933284"},
       {"address": "7D53D76F2DB86BE30A9B26CADEA69078531AB9BB",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "Quejs9DfnCsgGElTXxULslAU06c4bzyrxDSTtDZ6VO8="},
        "voting_power": "1656125",
        "proposer_priority": "22428191"},
       {"address": "138FD9AB7ABE0BAED14CA7D41D885B78052A4AA1",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "mmYQm2nAnrUKK5KNy31FCV9lBMl9/KgRla4vBsh/JXA="},
        "voting_power": "1614566",
        "proposer_priority": "85912508"},
       {"address": "3FF6C988799C1ADF3ACA0DA56143C8163890859A",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "l3aWelif4qSwnxd38PcxvOB9F8ood4oBIxwQjcKb/og="},
        "voting_power": "1529423",
        "proposer_priority": "64828697"},
       {"address": "E5CBA199E045E7036711D814E57E2B66C3CC0391",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "U9J4uq5i6zKKHkReUKsMetJSvyCNrCaqLICyIoqXUEw="},
        "voting_power": "1520270",
        "proposer_priority": "107864682"},
       {"address": "CA0F2A7121F86D3B6D91349730155B9A5A31C554",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "QLTgCEIy0zn2f519T6MHvaiK9+52sQTjzsnTw5916dE="},
        "voting_power": "1516051",
        "proposer_priority": "26923828"},
       {"address": "69D0605229C665974EBB736FC77E16245C3F79AA",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "+uY7CLC1Wj16/aR50vw3LcJbwIl2/F/zorbUIhKqK/E="},
        "voting_power": "1507558",
        "proposer_priority": "4222433"},
       {"address": "B5C33A409A589C094E89F77D24139F25C6A6DEE9",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "+rf+Ky6Edfpk5kqdNuv3+nn7moWmbRFCVwLgMwMSR1U="},
        "voting_power": "1504084",
        "proposer_priority": "169937635"},
       {"address": "3E88E7C54F64642A98B2E1DDD5BDBA48794F06C7",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "euJubdwp0WNjX9xPVRYcMaBPd0NCP9mKKMcUVtPhqQk="},
        "voting_power": "1492907",
        "proposer_priority": "17524345"},
       {"address": "BD4F80F0C1A67B4950772662F6EBCAD58A258933",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "QxPhzXFD/heBVTak80mb3g0cAN4fo3iIAfGhzW3Ktks="},
        "voting_power": "1440410",
        "proposer_priority": "139016070"},
       {"address": "7FC1DA40B2568DDBD53CFF3B76C49CE89AE28680",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "5b0VfMkXI1YEotqZ/AvtT8TOwuon7+RggKL4Z6b2bZg="},
        "voting_power": "1438474",
        "proposer_priority": "-130836384"},
       {"address": "68A393C7ED496871150C0A7CAD0CAC09B8E458FB",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "bU1m3aDQwxIpqFYubjZIhSvYCia1MQSfTaaXJBg38nw="},
        "voting_power": "1417009",
        "proposer_priority": "-117247360"},
       {"address": "000A5959634B4296E4DE536481DE00A8A0EB9A58",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "XYCvhdcOlm/5g1gHSO+7/hAuCQ0kZPU7XKvc1C5e1U4="},
        "voting_power": "1388080",
        "proposer_priority": "80740696"},
       {"address": "17386B308EF9670CDD412FB2F3C09C5B875FB8B8",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "XvYMPDffvHhlByH+T2mKCEXczKZ0FoUQWPtou0Q41+U="},
        "voting_power": "1373076",
        "proposer_priority": "128219170"},
       {"address": "2C2467180BBA84F2F1D4565E66F565A34003EE4F",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "td7PjOGcqa9YrpaeN8x7g679+Tl/gWihkRJGGLwkH10="},
        "voting_power": "1365954",
        "proposer_priority": "101796785"},
       {"address": "2D159B72D40C1C1DADDF24D2511200001B74ED84",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "cWOywd6/utG67FuJjTyXn8ou1dIBNZtaqSKbH62Wghs="},
        "voting_power": "1359668",
        "proposer_priority": "-55889633"},
       {"address": "C8969171F9B5A3354C712A20F007CDE0648C990F",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "rfQt+vAJ4IX+kpAaBADrF5LJPj3pTBasLJL4fK/KjCw="},
        "voting_power": "1165848",
        "proposer_priority": "-29101477"},
       {"address": "60A433D28B08788C72E2133554BD5CC68769DCEC",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "Ho34cqIRxDu28ioc64/VuIebfKeS3mcjvzBl+mxCZvE="},
        "voting_power": "1123671",
        "proposer_priority": "87483838"},
       {"address": "26F7777BD52918AE71801022B0E2DEED97DDD504",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "zYocxweamZm6GOE4NMZ+VzaPpeGdoSIskIA4QHo+/oE="},
        "voting_power": "1089392",
        "proposer_priority": "-79047603"},
       {"address": "15FEC10416E359CC1DDB424C69166B2671F25148",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "OjJJM+lCPo58lNWDgEDqaE6KmqIEXGj4mn1B/fAlmUc="},
        "voting_power": "1013447",
        "proposer_priority": "-912375"},
       {"address": "DD069A6901D749387A3AEE9846FF8E12705B46A0",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "eCrRd3Y5+N1An6LHW/cRaTji9zsqFNx0N6xEIyNrZio="},
        "voting_power": "991862",
        "proposer_priority": "145330026"},
       {"address": "F233E036248A36FC73C154FFA79261BCBDC4BB76",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "uqhpfK4aZ8MaTC8ZxD4xhgcgXDCnko4ed6zEdz7jDes="},
        "voting_power": "986453",
        "proposer_priority": "-59602852"},
       {"address": "9496535A8F2945BDB60572015D2D6F721AB6FED9",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "eAeAUKnPvGxb6hEQ4VxzVO+6ZWvyqn1OjtzBjqzBKxQ="},
        "voting_power": "975019",
        "proposer_priority": "21291073"},
       {"address": "DA4AF19A378C09B54C26C3467CB0ADF889292954",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "dOk2pUzVZHq8JDdyNLOyHH9k+ry/Xvxl7d/vZivYE0I="},
        "voting_power": "923515",
        "proposer_priority": "12840764"},
       {"address": "4B65255857E4393754F049DBE945C5AC87F563D8",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "2VCm4fclLlyltKmcYuJZE6+UgZ+HtL1uhaxnRittXBQ="},
        "voting_power": "901110",
        "proposer_priority": "101116126"},
       {"address": "99938495407C09B343562AAEC3AB551A5C246232",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "EvMa6sPpEJQz8bqalGMESOvDKq2YYXPo9+ib3qq+mz8="},
        "voting_power": "872944",
        "proposer_priority": "-20055520"},
       {"address": "2335465B27B9548313AAF465217787FD8E6113D3",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "rYPM5swt2DJmKFgI7v0Bzt/7yUIaUWF+Lq0hu6qF/fc="},
        "voting_power": "868027",
        "proposer_priority": "-28600656"},
       {"address": "0614088C41E6A85FB5BF344552A5120E5A0139FC",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "wwsbQ6mkEweZt2ZhPannQap/Fim1sDviGOdQpa0gyA8="},
        "voting_power": "863119",
        "proposer_priority": "-116111696"},
       {"address": "C02ACBA7653AC3782750B53D03A672E191F00361",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "HG3qcg4yqCzlBG5NqYtZaRKtVp5WKcxnETQZr0GTJmY="},
        "voting_power": "859549",
        "proposer_priority": "12214706"},
       {"address": "901FD122CC512EF13DE8E1A3D7953BFDDC0786D6",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "XgIu1lX318LSJylroCLzRjAliJoOI+nye7r3vG8S7Fc="},
        "voting_power": "818709",
        "proposer_priority": "-119144552"},
       {"address": "3FF719F1664BEE93D482B480677C03A47EC0B643",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "gJvkPLiHo2+12JJGprhwVsABASXzXO/dSWtnk0ywNB4="},
        "voting_power": "757800",
        "proposer_priority": "152301193"},
       {"address": "7364BE6CC7B6E404BD1C2050CCB6A7472786E3B6",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "Vlyhe1RD0MI9OENbbN2yjmTTtVJgSYYZOiSNC+k0JuU="},
        "voting_power": "742524",
        "proposer_priority": "173861070"},
       {"address": "F6783D8FB30E283081C16398293F482DCA0E912D",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "2cuVqUIby057xZ8ndvosCk3fuovzBoJGLMyB74JsZNg="},
        "voting_power": "739325",
        "proposer_priority": "-137414706"},
       {"address": "7E11ED7DD06FAE7B0BEDB469721151F2F31CBB6A",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "THacBjUl8Ex9Y2FrlKMrj5oZboq/sVpTWMtamwUWloQ="},
        "voting_power": "728644",
        "proposer_priority": "102739177"},
       {"address": "E06DADEB413829558F7C95339FFB61499C5A1BB9",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "d3qNk2Nc5DzapRRPNJ//djb6UJ8cRlJRtYxe48QlW+g="},
        "voting_power": "723239",
        "proposer_priority": "70545876"},
       {"address": "C9B753ED297E5F9894D4A43149CFC9F7B207B6B2",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "QEpXxUDaunv2wmnaQ1Qw0zYS/zHCOa3wJIImSInhjaw="},
        "voting_power": "707610",
        "proposer_priority": "-106107474"},
       {"address": "A9C4E0E2AF00183DA11434ED413219905E9A868D",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "tXnmhUMcIybIb9Wzmx5tiLD4xojGQc5irbOcNb/RTho="},
        "voting_power": "707594",
        "proposer_priority": "135778873"},
       {"address": "0CEB917DE4DF1C4B4F8EDFC4ACE6FD6D39F1E61E",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "1XjgGivzBPhmBVgB1OIFpn7zCrwcTYaemyu8gxlBJNA="},
        "voting_power": "684809",
        "proposer_priority": "59664556"},
       {"address": "3749086B6D85BDE3DACFBE4485E3DF95E709B6DB",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "1//p4z/9wJv66q9XBZdfArdiQ38m4L2HFofs29rG4/E="},
        "voting_power": "665169",
        "proposer_priority": "95943431"},
       {"address": "894C56D6CFC3A8E09EB6D1A2E33467C4CF77C0F5",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "iGQ1nBgIebCilnCQwrqf9kzKvoAxDzAyf1j/BHS8bz8="},
        "voting_power": "664623",
        "proposer_priority": "-118565918"},
       {"address": "CE485517649E4F8C71469EF7DAFCF9A558BF167F",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "TWhrgLe+T+LFELUqUHzcvmFoRUy+A+NL1ZvKIGdc1NU="},
        "voting_power": "654681",
        "proposer_priority": "89326996"},
       {"address": "8D8CB9C26740BA74A2AA0ABF9D2BAF98226485A6",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "uRUDzQd5POrn/+PUujTx0CvwO6sZxrw0MIEJcgFGCNU="},
        "voting_power": "652959",
        "proposer_priority": "-154195047"},
       {"address": "68275C37CFF86BB53D29D6237AD370E8FD5097FC",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "Uav1dgQiOhQuCXtcQbQ0Gd02IRUBiTD1mOgHCGr67xE="},
        "voting_power": "632830",
        "proposer_priority": "-12063032"},
       {"address": "E242DB2CB929D6F44A1A2FE485CC7D3F620FFAEB",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "s5PS5N/ichjOxyDowRowgjqZChE3Q/qEweTIK3Sn/X4="},
        "voting_power": "625093",
        "proposer_priority": "-9953787"},
       {"address": "41B543E91479A95CD5CA9F109C26DFAC149126FA",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "C88upbte468p6VnUYxFStVugaV+Fzi6C3YckK4lwpgI="},
        "voting_power": "623648",
        "proposer_priority": "100266661"},
       {"address": "E23AFCF0035FB01ACD02FE96F680066974D7072B",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "1gHQ+lM41rzVhqxvwK/gltIMdIiA2KzrKu7RJrY5r7Q="},
        "voting_power": "595494",
        "proposer_priority": "129176777"},
       {"address": "972A684F364CCE31469B37A9D439985115EB5A40",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "A/NlPxYDzI3cgNZkl8VSYHXBe90BCv1mgqd5X88eYY0="},
        "voting_power": "555900",
        "proposer_priority": "84205545"},
       {"address": "22BA59AC2918AFA4C1B56D3E6F86083E470CD8CB",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "b2DVNBLrIFXkQ19WXmbzlUKh+sQrBaSY1s8hSPkFFMY="},
        "voting_power": "517196",
        "proposer_priority": "-138519112"},
       {"address": "C5ED122E511FF9D7DEA986FD7423C61AEB139D34",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "5G1sO7sQEggEpNTOoVTGAjkE67W5mL7w0+u59leTd2s="},
        "voting_power": "509852",
        "proposer_priority": "142359118"},
       {"address": "2DD6D22969EE7C2CA1F8B428D13A8995C043044C",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "cM2HUzau2L3D2063LKI5YGmHcha79u5vmQFWyKo3A/4="},
        "voting_power": "508690",
        "proposer_priority": "37046398"},
       {"address": "5FECEC9408A2710833F2F7D848339462C29C1444",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "CSSFpeTmF3bi6Q4GHTnUZ907ghHTQzr23gm/BH439AE="},
        "voting_power": "507338",
        "proposer_priority": "53169327"},
       {"address": "1FADA14DEE843B733ECD5DE2E74552AD234A5451",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "TYPVhAi4+57tjTnNwjtKruQDZR6znYbSjSgsJ0UgsRc="},
        "voting_power": "456938",
        "proposer_priority": "-68053807"},
       {"address": "1571038B5AAAB431EC011F6AB1094463C6ED9842",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "8D8wXkMZ9d/p86sOxIzs/Uv3MMYyer1AMj6UnOKdcW0="},
        "voting_power": "456089",
        "proposer_priority": "-104611357"},
       {"address": "9127DFA61750DD1D56CB1D2A88F8831A2B3F9B0E",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "IrQ2E+ur7gxhk77/gaxHxD0DPyIRWW02Iguo57H/3Zw="},
        "voting_power": "449423",
        "proposer_priority": "-34107840"},
       {"address": "0A70912D18E13D78CB32E6322A4E57F861E6C3C8",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "BqasvZfE3hPDsn9oP+gAtCiSM5vrrocZbJla8nahqAU="},
        "voting_power": "435725",
        "proposer_priority": "-17246455"},
       {"address": "DD5751613FD7D31A952353014BD39FF5609CE2AF",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "shcPmjDfnQ4oXxrNMu1rya86afWI6C5GSWX9RtLhoi4="},
        "voting_power": "397261",
        "proposer_priority": "121808132"},
       {"address": "8014BA212ED388597510D064258F5E30AA30D591",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "xP04sdg7xwZqPpOYaoTIjOhCgQjXK5adgghQLpkP6MM="},
        "voting_power": "394623",
        "proposer_priority": "-90808249"},
       {"address": "5D564F844D411694B131B1C4A4FD3B389494F48F",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "uDxVypf6eEePXCtFB8v3GRKrXxGxLQqxqGO6ERBNi14="},
        "voting_power": "371985",
        "proposer_priority": "-126525507"},
       {"address": "4146FD7A1AB8B861B7018978BCD13D2D1FA63EBE",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "rqsz3Pa5/AbpCuQEJUl/mh6oz2B/mbknJOxdVTeAkUM="},
        "voting_power": "367168",
        "proposer_priority": "65748033"},
       {"address": "E95E6DF08591ED56BF63136328713EE8AC2A2114",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "63Zk6q5n9Gi4GgYnTUiAzuVRAHm6+7/F2sUhEIrGrtg="},
        "voting_power": "364726",
        "proposer_priority": "-76974419"},
       {"address": "2D387D95E13F681D33122E4475F9B7DFC2A68F64",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "4X05OkyOP1QKCiTFfZsIQTHi7oXqiU9FtN/bibpnCrY="},
        "voting_power": "363283",
        "proposer_priority": "-55936611"},
       {"address": "7C5AA87E5203C66EA35C64262F576EDD29BAD980",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "YzA8yyHSvymqCplrh0r50T1DRhlNscmxK38Q4T0U4oI="},
        "voting_power": "359149",
        "proposer_priority": "-84812098"},
       {"address": "373F86CB3755A1DE78CC69D3E5F7AD5D7615B85D",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "YMogBkqxrStOmjdKuQOfUpbUg9OC7SsOTmqgS1ZjJW0="},
        "voting_power": "352757",
        "proposer_priority": "18380814"},
       {"address": "2F89D7D3D1E1478F88EF3AD8AAD76A88189F6124",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "nCD7wpBgaHm5CTMvsWro4W9ODmvzvLzphYoIAmSW5R8="},
        "voting_power": "316432",
        "proposer_priority": "-32934571"},
       {"address": "E20004515311B205618FAD504FB529A3DEEE2E71",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "omxGXH85dkmGesQ5GwQy0YKZ6qvm+/2e8fxoahlKorQ="},
        "voting_power": "265275",
        "proposer_priority": "126628552"},
       {"address": "DA96564D2379ACEE00DD9FAA558681BB499757FD",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "hZcBdfFQiz0C1EOkEPkqwC5fp781juBznOctvFAIs1I="},
        "voting_power": "263100",
        "proposer_priority": "51937394"},
       {"address": "2F4D6730476407195AF3C1BF438B61CB6D785B95",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "4qEagTlC7uJC7w84zvir7tnlKz30AL0DMJ3q0vmozSg="},
        "voting_power": "262164",
        "proposer_priority": "94388897"},
       {"address": "451ACECAA7DC4CCE6E0B7CDE02F455DF973535E5",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "26qOdiy9k8LgWkIF6rDOqgsFl7y0/qLgNn+NQ/QYVlg="},
        "voting_power": "261622",
        "proposer_priority": "-78087126"},
       {"address": "4E2F0E49E1A479B2A213A841E5E8A1F3BC76B3F7",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "FVTcxQeQQs4CexEmSLVkMFrxpYSKv7to7rOdlw+7ej0="},
        "voting_power": "257825",
        "proposer_priority": "-61597272"},
       {"address": "06AA34BD6D1DD34119E3DC173EFAD94F430AB74E",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "uVZQNzphlMWeGEVvSibKtX9NPCd2acqvpTC2xQI7Tc8="},
        "voting_power": "255297",
        "proposer_priority": "39432392"},
       {"address": "E80D1F5519A5B3C9D290D3EA314FA05564535C1A",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "bDnUx51OClMaBjtynE3RLmCb0mlPlkaWLVZDBmrC1Uc="},
        "voting_power": "234249",
        "proposer_priority": "-50915927"},
       {"address": "47C89621F47BA7FF2362C1B2F97A4F6311B646F9",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "yXx+lgd6kDaMjfwzv17DCY9WabIFx3C6HtIZjXPrBwM="},
        "voting_power": "231578",
        "proposer_priority": "155873590"},
       {"address": "B15069E41B1A60FF03AE8D8F741F78C7B1144FBE",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "WKxiiCcH6FsecYR74Oc+o1f14Z2/7q+kzJuD29xRLqk="},
        "voting_power": "230243",
        "proposer_priority": "-77490704"},
       {"address": "191E896A11C0A77A96A99ABEE986A2A40355C044",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "jG3YOPzLxEOmfC2xN8qxqtF+A1IGLvn19AhTvhSmor8="},
        "voting_power": "230008",
        "proposer_priority": "149209230"},
       {"address": "F6C3F7872B046DA7198905E6CB58C1B775B48BEA",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "R4DgU+pyHuF07Toy3N7lsDNCoL5YggyOEw830AwXBWA="},
        "voting_power": "223561",
        "proposer_priority": "103550025"},
       {"address": "F0C8B6ADDAF7CC4ECE57086607A9A0C7EA6275E0",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "J8pHYf6n68tf77wVQrLJGwLU295p5grf4InmCZ7F6sM="},
        "voting_power": "220677",
        "proposer_priority": "-16362145"},
       {"address": "A99ABCE823DF44B72337725AADFF41F0FAAB4DFF",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "czJCRp13SYx70y1D+yenTEZUX6cSIhHSXHOaclbd+aU="},
        "voting_power": "217038",
        "proposer_priority": "-42355646"},
       {"address": "46E5338EF19A939D3D3B0B0B78A1C665F0FA19E8",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "K0P8fWZcajey9vaJfXPA0UYJezBseS8+CUpWPMqGx1Q="},
        "voting_power": "211944",
        "proposer_priority": "74315629"},
       {"address": "CDC018822747024BEAFD10A45ABECC7AC19CBAB0",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "5SA1hEf4+ry5n7qOWjxrN7cBRfwb9SqwPmbwIzEkAXk="},
        "voting_power": "205309",
        "proposer_priority": "44121518"},
       {"address": "20658BF40ED48ED01A2D087C7FF7874F21A56333",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "cf+XPmAgtXNK/B4GuzvEpJdhwaFFo1fn69KPhaPXQOU="},
        "voting_power": "201121",
        "proposer_priority": "-112598124"},
       {"address": "0960EF3FD58FE7DBB8F20FC98269D3B840451603",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "jSNHqQh5u31X5TqJ1dKVdFgeFFihqjP+D1Utvo5lezg="},
        "voting_power": "176429",
        "proposer_priority": "-119638145"},
       {"address": "B6B455A9F85724DC79C789D3344AFDFC603001B2",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "Z1zEMzqwxLQJ/lTcLSyc8s715SojM178iIRxQB6vrOk="},
        "voting_power": "16420",
        "proposer_priority": "-354036159"},
       {"address": "0B97B2BD62680B733C9FB7A4A309BBD40F3E770F",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "5wqRcwcA0u1Cjor+ywAL9AC9QjD3vDP5pM9pUZhVK24="},
        "voting_power": "9719",
        "proposer_priority": "-362177166"},
       {"address": "2BC2A0C3ABAF936778030C004585B4750A862C1D",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "ynIQ9OkSgNvGXqMDhGt+20i2Olzr5PQ99AgbBQAG1XU="},
        "voting_power": "8368",
        "proposer_priority": "-365096752"},
       {"address": "6FA5689F36CC9AD136B8C9F846FCCFF57345DDFB",
        "pub_key": {"type": "tendermint/PubKeyEd25519",
         "value": "tNbZt3RkKgLUDFmg//4wmKtFNsGrVp7ajao0oYQOCn4="},
        "voting_power": "5406",
        "proposer_priority": "-366445322"}],
      "proposer": {"address": "7E0ED7689B65C345D1C817C5B0332FD132DE5875",
       "pub_key": {"type": "tendermint/PubKeyEd25519",
        "value": "RfEMj+BAig8+YIjwIlquGWA7VRO1CMfign6PtwEct6k="},
       "voting_power": "2643712",
       "proposer_priority": "-151739649"}}"#;

        let validator_hash_expected = vec![232, 89, 230, 77, 86, 114, 76, 122, 224, 97, 170, 76, 43, 119, 30, 183, 
                                                92, 152, 183, 190, 44, 225, 8, 7, 237, 32, 132, 245, 7, 108, 141, 252];
        let vset = serde_json::from_str::<Set>(VSET).unwrap();
        let hash = vset.hash();
        assert_eq!(validator_hash_expected, hash.as_bytes().to_vec());

        let validator_bytes: Vec<Vec<u8>> = vset
            .validators()
            .iter()
            .map(|validator| validator.hash_bytes())
            .collect();
        println!("validators bytes {:?}",validator_bytes);
        use std::fs::File;
        use std::io::Write;

        let file_path = "output.bin";
        let mut file = File::create(file_path).unwrap();

        for inner_vec in validator_bytes.iter() {
            file.write_all(inner_vec).unwrap();
        }

        
        

        
    }

    #[test]
    fn validator_set_deserialize_total_voting_power_mismatch() {
        const VSET: &str = r#"{
            "validators": [
                {
                    "address": "01F527D77D3FFCC4FCFF2DDC2952EEA5414F2A33",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "OAaNq3DX/15fGJP2MI6bujt1GRpvjwrqIevChirJsbc="
                    },
                    "voting_power": "50",
                    "proposer_priority": "-150"
                },
                {
                    "address": "026CC7B6F3E62F789DBECEC59766888B5464737D",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "+vlsKpn6ojn+UoTZl+w+fxeqm6xvUfBokTcKfcG3au4="
                    },
                    "voting_power": "42",
                    "proposer_priority": "50"
                }
            ],
            "proposer": {
                "address": "01F527D77D3FFCC4FCFF2DDC2952EEA5414F2A33",
                "pub_key": {
                    "type": "tendermint/PubKeyEd25519",
                    "value": "OAaNq3DX/15fGJP2MI6bujt1GRpvjwrqIevChirJsbc="
                },
                "voting_power": "50",
                "proposer_priority": "-150"
            },
            "total_voting_power": "100"
        }"#;

        let err = serde_json::from_str::<Set>(VSET).unwrap_err();
        assert!(
            err.to_string()
                .contains("total voting power in validator set does not match the sum of participants' powers"),
            "{err}"
        );
    }

    #[test]
    fn validator_set_deserialize_total_voting_power_exceeds_limit() {
        const VSET: &str = r#"{
            "validators": [
                {
                    "address": "01F527D77D3FFCC4FCFF2DDC2952EEA5414F2A33",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "OAaNq3DX/15fGJP2MI6bujt1GRpvjwrqIevChirJsbc="
                    },
                    "voting_power": "576460752303423488",
                    "proposer_priority": "-150"
                },
                {
                    "address": "026CC7B6F3E62F789DBECEC59766888B5464737D",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "+vlsKpn6ojn+UoTZl+w+fxeqm6xvUfBokTcKfcG3au4="
                    },
                    "voting_power": "576460752303423488",
                    "proposer_priority": "50"
                }
            ],
            "proposer": {
                "address": "01F527D77D3FFCC4FCFF2DDC2952EEA5414F2A33",
                "pub_key": {
                    "type": "tendermint/PubKeyEd25519",
                    "value": "OAaNq3DX/15fGJP2MI6bujt1GRpvjwrqIevChirJsbc="
                },
                "voting_power": "50",
                "proposer_priority": "-150"
            },
            "total_voting_power": "92"
        }"#;

        let err = serde_json::from_str::<Set>(VSET).unwrap_err();
        assert!(
            err.to_string()
                .contains("total voting power in validator set exceeds the allowed maximum"),
            "{err}"
        );
    }

    #[test]
    fn validator_set_deserialize_total_voting_power_overflow() {
        const VSET: &str = r#"{
            "validators": [
                {
                    "address": "01F527D77D3FFCC4FCFF2DDC2952EEA5414F2A33",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "OAaNq3DX/15fGJP2MI6bujt1GRpvjwrqIevChirJsbc="
                    },
                    "voting_power": "6148914691236517205",
                    "proposer_priority": "-150"
                },
                {
                    "address": "026CC7B6F3E62F789DBECEC59766888B5464737D",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "+vlsKpn6ojn+UoTZl+w+fxeqm6xvUfBokTcKfcG3au4="
                    },
                    "voting_power": "6148914691236517205",
                    "proposer_priority": "50"
                },
                {
                    "address": "044EB1BB5D4C1CDB90029648439AEB10431FF295",
                    "pub_key": {
                        "type": "tendermint/PubKeyEd25519",
                        "value": "Wc790fkCDAi7LvZ4UIBAIJSNI+Rp2aU80/8l+idZ/wI="
                    },
                    "voting_power": "6148914691236517206",
                    "proposer_priority": "50"
                }
            ],
            "proposer": {
                "address": "01F527D77D3FFCC4FCFF2DDC2952EEA5414F2A33",
                "pub_key": {
                    "type": "tendermint/PubKeyEd25519",
                    "value": "OAaNq3DX/15fGJP2MI6bujt1GRpvjwrqIevChirJsbc="
                },
                "voting_power": "50",
                "proposer_priority": "-150"
            }
        }"#;

        let err = serde_json::from_str::<Set>(VSET).unwrap_err();
        assert!(
            err.to_string()
                .contains("total voting power in validator set exceeds the allowed maximum"),
            "{err}"
        );
    }
}
