// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use crate::pefile;
use glob::glob;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Esp {
    shim: Vec<u8>,
    grub: Vec<u8>,
}

fn find_efi_bin(search_path: &Path, bin_name: &str) -> io::Result<PathBuf> {
    if !fs::metadata(search_path)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("{search_path:?}"),
        ));
    }

    let glob_path = search_path.join(Path::new("**/EFI/*/").join(bin_name));
    let glob_pattern = glob_path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid efi bin search pattern",
        )
    })?;

    let search_results = match glob(glob_pattern) {
        Ok(results) => results,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid efi bin search pattern",
            ));
        }
    };
    if let Some(path) = search_results.filter_map(Result::ok).next() {
        // Assume there's just one of them; return the first one
        return Ok(path);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("{bin_name} not found"),
    ))
}

fn load_efi_bin(search_path: &Path, bin_name: &str) -> io::Result<Vec<u8>> {
    fs::read(find_efi_bin(search_path, bin_name)?)
}

impl Esp {
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Esp> {
        Ok(Esp {
            grub: load_efi_bin(path.as_ref(), "grubx64.efi")?,
            shim: load_efi_bin(path.as_ref(), "shimx64.efi")?,
        })
    }

    /// Tries loading the shim binary
    pub fn shim(&self) -> pefile::PeFile<'_> {
        pefile::PeFile::new(&self.shim).expect("Can't open shim binary")
    }

    /// Tries loading the grub binary
    pub fn grub(&self) -> pefile::PeFile<'_> {
        pefile::PeFile::new(&self.grub).expect("Can't open grub binary")
    }
}
