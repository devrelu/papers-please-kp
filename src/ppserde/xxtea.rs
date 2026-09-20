const KEY: [u32; 4] = [0xF2A30174, 0x8C59E5E7, 0xD0A3425D, 0x03692407];
const DELTA: u32 = 0x9E3779B9;

fn words(input: &[u8]) -> Result<Vec<u32>, &'static str> {
	if input.is_empty() || input.len() % 4 != 0 {
		return Err("XXTEA input must contain a non-zero multiple of 4 bytes");
	}
	Ok(input
		.chunks_exact(4)
		.map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
		.collect())
}

pub(crate) fn encrypt(input: &[u8]) -> Result<Vec<u8>, &'static str> {
	let mut words = words(input)?;
	let mut z = *words.last().unwrap();
	let rounds = 52 / words.len() as u32 + 6;
	let mut sum: u32 = 0;
	for _ in 0..rounds {
		sum = sum.wrapping_add(DELTA);
		let e = ((sum >> 2) & 3) as usize;
		for p in 0..words.len() {
			let y = words[(p + 1) % words.len()];
			let mx = ((z >> 5 ^ y << 2).wrapping_add(y >> 3 ^ z << 4))
				^ ((sum ^ y).wrapping_add(KEY[(p & 3) ^ e] ^ z));
			words[p] = words[p].wrapping_add(mx);
			z = words[p];
		}
	}
	Ok(words.into_iter().flat_map(u32::to_le_bytes).collect())
}

pub(crate) fn decrypt(input: &[u8]) -> Result<Vec<u8>, &'static str> {
	let mut words = words(input)?;
	let mut y = words[0];
	let rounds = 52 / words.len() as u32 + 6;
	let mut sum = DELTA.wrapping_mul(rounds);
	for _ in 0..rounds {
		let e = ((sum >> 2) & 3) as usize;
		for p in (1..words.len()).rev() {
			let z = words[p - 1];
			let mx = ((z >> 5 ^ y << 2).wrapping_add(y >> 3 ^ z << 4))
				^ ((sum ^ y).wrapping_add(KEY[(p & 3) ^ e] ^ z));
			words[p] = words[p].wrapping_sub(mx);
			y = words[p];
		}
		let z = *words.last().unwrap();
		let mx = ((z >> 5 ^ y << 2).wrapping_add(y >> 3 ^ z << 4))
			^ ((sum ^ y).wrapping_add(KEY[e] ^ z));
		words[0] = words[0].wrapping_sub(mx);
		y = words[0];
		sum = sum.wrapping_sub(DELTA);
	}
	Ok(words.into_iter().flat_map(u32::to_le_bytes).collect())
}

#[cfg(test)]
mod tests {
	use super::{decrypt, encrypt};

	#[test]
	fn round_trip() {
		let plaintext = *b"PapersPleaseART!";
		let encrypted = encrypt(&plaintext).unwrap();
		assert_ne!(encrypted, plaintext);
		assert_eq!(decrypt(&encrypted).unwrap(), plaintext);
	}

	#[test]
	fn rejects_non_block_aligned_input() {
		assert!(encrypt(b"").is_err());
		assert!(decrypt(b"abc").is_err());
	}
}
