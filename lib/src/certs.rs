// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use openssl::x509::{X509, X509Ref};

pub struct X509Cert {
    cert: X509,
    bytes: Vec<u8>,
}

impl X509Cert {
    pub fn from_db_bytes(bytes: &[u8]) -> Result<Self, openssl::error::ErrorStack> {
        Ok(Self {
            cert: X509::from_der(&bytes[16..])?,
            bytes: bytes.to_vec(),
        })
    }

    /// For certs stored so raw byte representation equals the der representation
    pub fn from_der(data: &[u8]) -> Result<Self, openssl::error::ErrorStack> {
        Ok(Self {
            cert: X509::from_der(data)?,
            bytes: data.to_vec(),
        })
    }

    pub fn subject_matches(&self, other: &X509Ref) -> bool {
        let self_subject = self.cert.subject_name();
        let other_subject = other.subject_name();
        let other_issuer = other.issuer_name();
        self_subject.try_cmp(other_subject).is_ok_and(|o| o.is_eq())
            || self_subject.try_cmp(other_issuer).is_ok_and(|o| o.is_eq())
    }

    pub fn raw(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl<'s> From<&'s X509Cert> for &'s X509 {
    fn from(val: &'s X509Cert) -> Self {
        &val.cert
    }
}
