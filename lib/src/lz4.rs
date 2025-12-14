// LZ4 decompression - minimal implementation for Stronghold snapshots
// Based on the engine's compression/decoder.rs

use thiserror::Error;

#[derive(Debug, Error)]
#[error("LZ4 decode failed: {0}")]
pub struct Lz4DecodeError(pub String);

pub fn decompress(input: &[u8]) -> Result<Vec<u8>, Lz4DecodeError> {
    let mut output = Vec::with_capacity(4096);
    let mut decoder = Lz4Decoder {
        input,
        output: &mut output,
        token: 0,
    };
    decoder.complete()?;
    Ok(output)
}

struct Lz4Decoder<'a> {
    input: &'a [u8],
    output: &'a mut Vec<u8>,
    token: u8,
}

impl<'a> Lz4Decoder<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], Lz4DecodeError> {
        if self.input.len() < size {
            return Err(Lz4DecodeError("Unexpected end".into()));
        }
        let (taken, rest) = self.input.split_at(size);
        self.input = rest;
        Ok(taken)
    }

    fn read_int(&mut self) -> Result<usize, Lz4DecodeError> {
        let mut size = 0;
        loop {
            let extra = self.take(1)?[0];
            size += extra as usize;
            if extra != 0xFF {
                break;
            }
        }
        Ok(size)
    }

    fn read_u16(&mut self) -> Result<u16, Lz4DecodeError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().unwrap();
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_literal(&mut self) -> Result<(), Lz4DecodeError> {
        let mut literal = (self.token >> 4) as usize;
        if literal == 15 {
            literal += self.read_int()?;
        }
        let data = self.take(literal)?;
        self.output.extend_from_slice(data);
        Ok(())
    }

    fn read_duplicate(&mut self) -> Result<(), Lz4DecodeError> {
        let offset = self.read_u16()?;
        let mut length = (4 + (self.token & 0xF)) as usize;
        if length == 4 + 15 {
            length += self.read_int()?;
        }

        let start = self.output.len().wrapping_sub(offset as usize);
        if start >= self.output.len() {
            return Err(Lz4DecodeError("Invalid duplicate offset".into()));
        }

        for i in start..start + length {
            let b = self.output[i];
            self.output.push(b);
        }
        Ok(())
    }

    fn complete(&mut self) -> Result<(), Lz4DecodeError> {
        while !self.input.is_empty() {
            self.token = self.take(1)?[0];
            self.read_literal()?;
            if self.input.is_empty() {
                break;
            }
            self.read_duplicate()?;
        }
        Ok(())
    }
}
