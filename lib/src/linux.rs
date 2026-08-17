// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use crate::pefile::PeFile;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::result::Result;

pub struct Linux {
    bin: Vec<u8>,
}

/// Given a glob pattern find and load a vmlinuz image candidate
fn find_vmlinuz(linux_path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Given a directory path, it will look under it for vmlinuz images
    let glob_path = linux_path.join("*/vmlinuz");
    let glob_pattern = glob_path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid efi bin search pattern",
        )
    })?;
    // TODO: At the moment just the first found path will be returned.
    // The logic should be improved to return the latest one, or an iterator
    // so we could work on all the found vmlinuz images instead
    if let Some(path) = glob::glob(glob_pattern)?.filter_map(Result::ok).next() {
        return Ok(path);
    }
    Err(Box::new(io::Error::new(
        io::ErrorKind::NotFound,
        String::from("vmlinuz not found"),
    )))
}

pub fn load_vmlinuz(linux_path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    return Ok(fs::read(find_vmlinuz(linux_path)?)?);
}

impl Linux {
    pub fn new<P: AsRef<Path>>(linux_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Linux {
            bin: load_vmlinuz(linux_path.as_ref())?,
        })
    }

    fn pe(&self) -> PeFile<'_> {
        PeFile::new(&self.bin).expect("can't parse linux binary")
    }

    pub fn authenticode(&self) -> Vec<u8> {
        self.pe().authenticode()
    }
}
