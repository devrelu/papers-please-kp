const LOC_SIG: u32 = 0x04034B50;
const CEN_SIG: u32 = 0x02014B50;
const END_SIG: u32 = 0x06054B50;
const VERSION: u16 = 20;

fn crc32(data: &[u8]) -> u32 {
	let mut crc = u32::MAX;
	for byte in data {
		crc ^= u32::from(*byte);
		for _ in 0..8 {
			crc = (crc >> 1) ^ (0xEDB8_8320 & (0_u32.wrapping_sub(crc & 1)));
		}
	}
	!crc
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
	output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
	output.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn build(entries: &[(String, Vec<u8>)]) -> Result<Vec<u8>, &'static str> {
	if entries.len() > usize::from(u16::MAX) {
		return Err("too many localization ZIP entries");
	}
	let mut output = Vec::new();
	let mut central_entries = Vec::with_capacity(entries.len());
	for (name, data) in entries {
		let name = if name.starts_with('/') { name.clone() } else { format!("/{name}") };
		let name = name.as_bytes();
		let name_len =
			u16::try_from(name.len()).map_err(|_| "localization path is too long")?;
		let data_len =
			u32::try_from(data.len()).map_err(|_| "localization file is too large")?;
		let offset =
			u32::try_from(output.len()).map_err(|_| "localization ZIP is too large")?;
		let checksum = crc32(data);
		push_u32(&mut output, LOC_SIG);
		push_u16(&mut output, VERSION);
		push_u16(&mut output, 0);
		push_u16(&mut output, 0);
		push_u16(&mut output, 0);
		push_u16(&mut output, 0);
		push_u32(&mut output, checksum);
		push_u32(&mut output, data_len);
		push_u32(&mut output, data_len);
		push_u16(&mut output, name_len);
		push_u16(&mut output, 0);
		output.extend_from_slice(name);
		output.extend_from_slice(data);
		central_entries.push((name.to_vec(), data_len, checksum, offset));
	}
	let central_offset =
		u32::try_from(output.len()).map_err(|_| "localization ZIP is too large")?;
	for (name, data_len, checksum, offset) in central_entries {
		push_u32(&mut output, CEN_SIG);
		push_u16(&mut output, VERSION);
		push_u16(&mut output, VERSION);
		push_u16(&mut output, 0);
		push_u16(&mut output, 0);
		push_u16(&mut output, 0);
		push_u16(&mut output, 0);
		push_u32(&mut output, checksum);
		push_u32(&mut output, data_len);
		push_u32(&mut output, data_len);
		push_u16(&mut output, name.len() as u16);
		push_u16(&mut output, 0);
		push_u16(&mut output, 0);
		push_u16(&mut output, 0);
		push_u16(&mut output, 0);
		push_u32(&mut output, 0);
		push_u32(&mut output, offset);
		output.extend_from_slice(&name);
	}
	let central_size = u32::try_from(output.len())
		.map_err(|_| "localization ZIP is too large")?
		- central_offset;
	let entry_count = entries.len() as u16;
	push_u32(&mut output, END_SIG);
	push_u16(&mut output, 0);
	push_u16(&mut output, 0);
	push_u16(&mut output, entry_count);
	push_u16(&mut output, entry_count);
	push_u32(&mut output, central_size);
	push_u32(&mut output, central_offset);
	push_u16(&mut output, 0);
	Ok(output)
}

#[cfg(test)]
mod tests {
	use super::{build, crc32};

	#[test]
	fn crc32_matches_standard_vector() {
		assert_eq!(crc32(b"123456789"), 0xCBF43926);
	}

	#[test]
	fn uses_stored_msdos_entries() {
		let archive = build(&[("/data/Text.xml".into(), b"test".to_vec())]).unwrap();
		assert_eq!(&archive[..4], b"PK\x03\x04");
		assert_eq!(u16::from_le_bytes(archive[8..10].try_into().unwrap()), 0);
		let central = archive.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
		assert_eq!(
			u16::from_le_bytes(archive[central + 4..central + 6].try_into().unwrap()),
			20
		);
		assert_eq!(
			u32::from_le_bytes(archive[central + 38..central + 42].try_into().unwrap()),
			0
		);
	}
}
