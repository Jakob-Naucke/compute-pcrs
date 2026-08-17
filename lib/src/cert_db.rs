// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::default::Default;
use std::fmt;

use crate::certs::X509Cert;
use crate::uefi::{EFI_CERT_TYPE_X509_GUID, guid_to_le_bytes};

#[derive(Clone, Debug)]
pub struct CertDbParsingError {
    string: String,
}

impl CertDbParsingError {
    pub fn new(string: &str) -> CertDbParsingError {
        CertDbParsingError {
            string: string.into(),
        }
    }
}

impl fmt::Display for CertDbParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error parsing cert db: {}", self.string)
    }
}

pub struct Certdb {
    certs: Vec<X509Cert>,
}

impl Certdb {
    pub fn empty() -> Self {
        Certdb { certs: vec![] }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CertDbParsingError> {
        let mut certs = Vec::new();
        let mut offset = 0;

        if data.is_empty() {
            return Ok(Self { certs: vec![] });
        }

        while offset < data.len() - 28 {
            let list_type = &data[offset..offset + 16];
            let list_size = u32::from_le_bytes(
                data[offset + 16..offset + 20]
                    .try_into()
                    .expect("Badly hardcoded section size"),
            ) as usize;
            let head_size = u32::from_le_bytes(
                data[offset + 20..offset + 24]
                    .try_into()
                    .expect("Badly hardcoded section size"),
            ) as usize;
            let item_size = u32::from_le_bytes(
                data[offset + 24..offset + 28]
                    .try_into()
                    .expect("Badly hardcoded section size"),
            ) as usize;

            if offset + list_size > data.len() {
                return Err(CertDbParsingError::new("Invalid list size"));
            }

            offset += 28 + head_size;
            let mut item_offset = 0;

            if list_type == guid_to_le_bytes(&EFI_CERT_TYPE_X509_GUID) {
                while item_offset < list_size - (head_size + 28) {
                    let item = &data[offset + item_offset..offset + item_offset + item_size];
                    if let Ok(c) = X509Cert::from_db_bytes(item) {
                        certs.push(c);
                    }
                    item_offset += item_size;
                }
            }
            offset += list_size - (28 + head_size);
        }

        Ok(Self { certs })
    }

    pub fn from_unique_der(data: &[u8]) -> Result<Self, CertDbParsingError> {
        match X509Cert::from_der(data) {
            Ok(cert) => Ok(Self { certs: vec![cert] }),
            Err(_) => Err(CertDbParsingError::new("Couldn't parse single der")),
        }
    }

    pub fn contains(&self, cert: &openssl::x509::X509Ref) -> bool {
        for db_cert in &self.certs {
            if db_cert.subject_matches(cert) {
                return true;
            }
        }
        false
    }

    /// Looks up for certificates in the db which match the subject or issuer
    /// name of the target certificate
    pub fn get(&self, cert: &openssl::x509::X509Ref) -> Option<&X509Cert> {
        self.certs
            .iter()
            .find(|&db_cert| db_cert.subject_matches(cert))
            .map(|v| v as _)
    }
}

impl Default for Certdb {
    fn default() -> Self {
        Self::empty()
    }
}
