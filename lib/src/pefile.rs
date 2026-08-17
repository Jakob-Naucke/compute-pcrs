// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use crate::cert_db::Certdb;
use anyhow::Result;
use authenticode::authenticode_digest;
use object::ObjectSection;
use object::read::Object;
use object::read::pe::NativePeFile;
use openssl::pkcs7::Pkcs7;
use sha2::{Digest, Sha256};

const SHIM_VENDOR_CERT_SECTION: &str = ".vendor_cert";

// Attribute certificate table entry constants
// The attribute certificate table format and constants are documented in
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
//
// The table has cert entries each of which:
//      offset   size   field
//      0        4      dwlength (or len below)
//      4        2      wRevision
//      6        2      cert type
//      8        len    certificate
//
// wRevision and cert type values are also documented in that document
const PEFILE_CERT_ENTRY_LENGTH_START_OFFSET: usize = 0;
const PEFILE_CERT_ENTRY_LENGTH_LENGTH: usize = 4;
const PEFILE_CERT_ENTRY_LENGTH_END_OFFSET: usize =
    PEFILE_CERT_ENTRY_LENGTH_START_OFFSET + PEFILE_CERT_ENTRY_LENGTH_LENGTH;
const PEFILE_CERT_ENTRY_REV_START_OFFSET: usize = PEFILE_CERT_ENTRY_LENGTH_END_OFFSET;
const PEFILE_CERT_ENTRY_REV_LENGTH: usize = 2;
const PEFILE_CERT_ENTRY_REV_END_OFFSET: usize =
    PEFILE_CERT_ENTRY_REV_START_OFFSET + PEFILE_CERT_ENTRY_REV_LENGTH;
const PEFILE_CERT_ENTRY_TYPE_START_OFFSET: usize = PEFILE_CERT_ENTRY_REV_END_OFFSET;
const PEFILE_CERT_ENTRY_TYPE_LENGTH: usize = 2;
const PEFILE_CERT_ENTRY_TYPE_END_OFFSET: usize =
    PEFILE_CERT_ENTRY_TYPE_START_OFFSET + PEFILE_CERT_ENTRY_TYPE_LENGTH;
const PEFILE_CERT_ENTRY_DATA_START_OFFSET: usize = PEFILE_CERT_ENTRY_TYPE_END_OFFSET;

#[non_exhaustive]
struct WinCertRevision;
impl WinCertRevision {
    #[allow(dead_code)]
    pub const REV_1_0: u16 = 0x0100;
    pub const REV_2_0: u16 = 0x0200;
}

#[non_exhaustive]
struct WinCertType;
impl WinCertType {
    #[allow(dead_code)]
    pub const X509: u16 = 0x0001; // Not supported
    pub const PKS_SIGNED_DATA: u16 = 0x0002;
    #[allow(dead_code)]
    pub const RESERVED_1: u16 = 0x0003; // Reserved
    #[allow(dead_code)]
    pub const TS_STACK_SIGNED: u16 = 0x0004; // Not supported
}

pub struct PeFile<'data> {
    image: NativePeFile<'data>,
    certchain: Vec<Pkcs7>,
}

impl<'data> PeFile<'data> {
    pub fn new(bin_data: &'data [u8]) -> Result<PeFile<'data>> {
        let mut pe = PeFile {
            image: NativePeFile::parse(bin_data)?,
            certchain: vec![],
        };
        pe.parse_certchain();
        Ok(pe)
    }

    pub fn image(&self) -> &NativePeFile<'_> {
        &self.image
    }

    pub fn authenticode(&self) -> Vec<u8> {
        let mut digest = Sha256::new();
        authenticode_digest(&self.image, &mut digest).unwrap();
        digest.finalize().to_vec()
    }

    pub fn section(&self, name: &str) -> Option<&'data [u8]> {
        self.image.section_by_name(name).and_then(|s| s.data().ok())
    }

    fn get_vendor_cert_auth(&self) -> Option<Vec<u8>> {
        let vendor_cert_raw = self.section(SHIM_VENDOR_CERT_SECTION)?;
        // 4 u32 header consisting of:
        //  - auth_size
        //  - deauth_size
        //  - auth_offset
        //  - deauth_offset
        let auth_size = u32::from_le_bytes(
            vendor_cert_raw[0..4]
                .try_into()
                .expect("Badly hardcoded section size"),
        ) as usize;
        let auth_offset = u32::from_le_bytes(
            vendor_cert_raw[8..12]
                .try_into()
                .expect("Badly hardcoded section size"),
        ) as usize;
        Some(vendor_cert_raw[auth_offset..auth_offset + auth_size].to_vec())
    }

    /// The pe file can carry a .vendor_cert section, in which it could store
    /// certificates in db format. Just as shim could do.
    /// This function parses the db and returns the certificates
    pub fn vendor_db(&self) -> Certdb {
        if let Some(db_bytes) = self.get_vendor_cert_auth() {
            return Certdb::from_bytes(&db_bytes).unwrap_or_default();
        }
        Certdb::default()
    }

    /// The .vendor_cert section of the pe file could also store just a
    /// certificate. Just as shim could do.
    /// This function parses the certificate and returns a vector that holds it
    pub fn vendor_cert(&self) -> Certdb {
        if let Some(der_bytes) = self.get_vendor_cert_auth() {
            return Certdb::from_unique_der(&der_bytes).unwrap_or_default();
        }
        Certdb::default()
    }

    pub fn find_cert_in_db(&self, db: &Certdb) -> Option<Vec<u8>> {
        for signature in self.certchain.iter().filter_map(|c| c.signed()) {
            if let Some(certs) = signature.certificates() {
                for pe_cert in certs.iter() {
                    if let Some(cert) = db.get(pe_cert) {
                        return Some(cert.raw());
                    }
                }
            }
        }
        None
    }

    fn parse_certchain(&mut self) {
        let mut certchain: Vec<Pkcs7> = vec![];
        let (cert_table_offset_u32, cert_table_size_u32) = self
            .image
            .data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_SECURITY)
            .expect("can't find pe file cert table data directory")
            .address_range();
        let (cert_table_offset, cert_table_size) =
            (cert_table_offset_u32 as usize, cert_table_size_u32 as usize);

        let data = self.image.data();
        let mut offset = 0;
        while offset < cert_table_size {
            let cert_entry_offset = cert_table_offset + offset;
            let cert_length = u32::from_le_bytes(
                data[cert_entry_offset + PEFILE_CERT_ENTRY_LENGTH_START_OFFSET
                    ..cert_entry_offset + PEFILE_CERT_ENTRY_LENGTH_END_OFFSET]
                    .try_into()
                    .expect("unexpected cert length parse error"),
            ) as usize;
            let cert_revision = u16::from_le_bytes(
                data[cert_entry_offset + PEFILE_CERT_ENTRY_REV_START_OFFSET
                    ..cert_entry_offset + PEFILE_CERT_ENTRY_REV_END_OFFSET]
                    .try_into()
                    .expect("unexpected cert revision parse error"),
            );
            let cert_type = u16::from_le_bytes(
                data[cert_entry_offset + PEFILE_CERT_ENTRY_TYPE_START_OFFSET
                    ..cert_entry_offset + PEFILE_CERT_ENTRY_TYPE_END_OFFSET]
                    .try_into()
                    .expect("unexpected cert type parse error"),
            );
            if cert_type == WinCertType::PKS_SIGNED_DATA
                && cert_revision == WinCertRevision::REV_2_0
                && cert_length != 0
            {
                let cert = Pkcs7::from_der(
                    &data[cert_entry_offset + PEFILE_CERT_ENTRY_DATA_START_OFFSET
                        ..cert_entry_offset + cert_length],
                )
                .unwrap();
                certchain.push(cert);
            }

            // nearest 8-byte multiple
            offset += (offset + cert_length).div_ceil(8) * 8;
        }

        self.certchain = certchain;
    }
}
