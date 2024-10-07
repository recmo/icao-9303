mod pace_protocol;

pub use pace_protocol::{KeyMapping, PaceProtocol};
use {
    super::{AnySecurityInfo, KeyAgreement},
    crate::icao9303::{secure_messaging::SymmetricCipher, Error},
    der::{asn1::ObjectIdentifier as Oid, Any, Sequence, ValueOrd},
};

/// See ICAO-9303-11 9.2.1
#[derive(Clone, PartialEq, Eq, Debug, Sequence)]
pub struct PaceInfo {
    pub protocol: PaceProtocol,

    /// Version must be 2
    pub version: u64,

    pub parameter_id: Option<u64>,
}

/// See ICAO-9303-11 9.2.2
#[derive(Clone, PartialEq, Eq, Debug, Sequence)]
pub struct PaceDomainParameterInfo {
    pub protocol: PaceProtocol,

    /// Algorithm identifier for the domain parameter.
    pub domain_parameter: AlgorithmIdentifier,
    pub parameter_id: Option<u64>,
}

pub type AlgorithmIdentifier = Any; // TODO

impl PaceInfo {
    pub fn ensure_valid(&self) {
        assert!(self.protocol.cipher.is_some());
        assert_eq!(self.version, 2);
    }
}

impl PaceDomainParameterInfo {
    pub fn ensure_valid(&self) {
        assert!(self.protocol.cipher.is_none());
    }
}
