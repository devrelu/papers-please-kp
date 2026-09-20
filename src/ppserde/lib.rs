use std::io::Cursor;

use haxeformat::StreamDeserializer;
use haxeformat::value::{DeserializationCache, HaxeObject, HaxeValue};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

const XXTEA_KEY: [u32; 4] = [0xF2A30174, 0x8C59E5E7, 0xD0A3425D, 0x03692407];
const XXTEA_DELTA: u32 = 0x9E3779B9;
const ART_HEADER_LEN: usize = 2;
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

fn xxtea_words(input: &[u8]) -> Result<Vec<u32>, &'static str> {
	if input.is_empty() || input.len() % 4 != 0 {
		return Err("XXTEA input must contain a non-zero multiple of 4 bytes");
	}
	Ok(input
		.chunks_exact(4)
		.map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
		.collect())
}

fn xxtea_encrypt(input: &[u8]) -> Result<Vec<u8>, &'static str> {
	let mut words = xxtea_words(input)?;
	let mut z = *words.last().unwrap();
	let rounds = 52 / words.len() as u32 + 6;
	let mut sum: u32 = 0;
	for _ in 0..rounds {
		sum = sum.wrapping_add(XXTEA_DELTA);
		let e = ((sum >> 2) & 3) as usize;
		for p in 0..words.len() {
			let y = words[(p + 1) % words.len()];
			let mx = ((z >> 5 ^ y << 2).wrapping_add(y >> 3 ^ z << 4))
				^ ((sum ^ y).wrapping_add(XXTEA_KEY[(p & 3) ^ e] ^ z));
			words[p] = words[p].wrapping_add(mx);
			z = words[p];
		}
	}
	Ok(words.into_iter().flat_map(u32::to_le_bytes).collect())
}

fn xxtea_decrypt(input: &[u8]) -> Result<Vec<u8>, &'static str> {
	let mut words = xxtea_words(input)?;
	let mut y = words[0];
	let rounds = 52 / words.len() as u32 + 6;
	let mut sum = XXTEA_DELTA.wrapping_mul(rounds);
	for _ in 0..rounds {
		let e = ((sum >> 2) & 3) as usize;
		for p in (1..words.len()).rev() {
			let z = words[p - 1];
			let mx = ((z >> 5 ^ y << 2).wrapping_add(y >> 3 ^ z << 4))
				^ ((sum ^ y).wrapping_add(XXTEA_KEY[(p & 3) ^ e] ^ z));
			words[p] = words[p].wrapping_sub(mx);
			y = words[p];
		}
		let z = *words.last().unwrap();
		let mx = ((z >> 5 ^ y << 2).wrapping_add(y >> 3 ^ z << 4))
			^ ((sum ^ y).wrapping_add(XXTEA_KEY[e] ^ z));
		words[0] = words[0].wrapping_sub(mx);
		y = words[0];
		sum = sum.wrapping_sub(XXTEA_DELTA);
	}
	Ok(words.into_iter().flat_map(u32::to_le_bytes).collect())
}

fn convert_value(py: Python<'_>, value: HaxeValue) -> PyResult<Py<PyAny>> {
	match value {
		HaxeValue::Int(value) => Ok(value.into_pyobject(py)?.into_any().unbind()),
		HaxeValue::String(value) => Ok(value.into_pyobject(py)?.into_any().unbind()),
		HaxeValue::Object(value) => match *value {
			HaxeObject::Bytes(value) => Ok(PyBytes::new(py, &value).into_any().unbind()),
			HaxeObject::Array(values) => {
				let values = values
					.into_iter()
					.map(|value| convert_value(py, value))
					.collect::<PyResult<Vec<_>>>()?;
				Ok(PyList::new(py, values)?.into_any().unbind())
			}
			HaxeObject::Struct(fields) => {
				let result = PyDict::new(py);
				for (name, value) in fields {
					result.set_item(name, convert_value(py, value)?)?;
				}
				Ok(result.into_any().unbind())
			}
			_ => unimplemented!("unimplemented haxe object: {value:?}"),
		},
		_ => unimplemented!("unimplemented haxe value: {value:?}"),
	}
}

fn deserialize(py: Python<'_>, encrypted: &[u8]) -> PyResult<Py<PyAny>> {
	let data = xxtea_decrypt(encrypted).map_err(PyValueError::new_err)?;
	let metadata_end = data
		.windows(PNG_SIGNATURE.len())
		.position(|window| window == PNG_SIGNATURE)
		.ok_or_else(|| {
			PyValueError::new_err("Art.dat payload does not start with a PNG")
		})?;

	if metadata_end <= ART_HEADER_LEN {
		return Err(PyValueError::new_err("Art.dat metadata is missing"));
	}
	let mut decoder = StreamDeserializer::new(
		Cursor::new(&data[ART_HEADER_LEN..metadata_end]),
		DeserializationCache::new(),
	);
	let value: HaxeValue = decoder
		.deserialize()
		.map_err(|error| PyValueError::new_err(error.to_string()))?;
	decoder.end().map_err(|error| PyValueError::new_err(error.to_string()))?;
	convert_value(py, value)
}

#[pyfunction]
fn decrypt<'py>(
	py: Python<'py>,
	encrypted: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
	let decrypted =
		xxtea_decrypt(encrypted.as_bytes()).map_err(PyValueError::new_err)?;
	Ok(PyBytes::new(py, &decrypted))
}

#[pyfunction]
fn encrypt<'py>(
	py: Python<'py>,
	plaintext: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
	let encrypted =
		xxtea_encrypt(plaintext.as_bytes()).map_err(PyValueError::new_err)?;
	Ok(PyBytes::new(py, &encrypted))
}

#[pyfunction]
fn loads(py: Python<'_>, encrypted: &Bound<'_, PyBytes>) -> PyResult<Py<PyAny>> {
	deserialize(py, encrypted.as_bytes())
}

#[pymodule]
fn ppserde(module: &Bound<'_, PyModule>) -> PyResult<()> {
	module.add_function(wrap_pyfunction!(decrypt, module)?)?;
	module.add_function(wrap_pyfunction!(encrypt, module)?)?;
	module.add_function(wrap_pyfunction!(loads, module)?)?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::{xxtea_decrypt, xxtea_encrypt};

	#[test]
	fn xxtea_round_trip() {
		let plaintext = *b"PapersPleaseART!";
		let encrypted = xxtea_encrypt(&plaintext).unwrap();
		assert_ne!(encrypted, plaintext);
		assert_eq!(xxtea_decrypt(&encrypted).unwrap(), plaintext);
	}

	#[test]
	fn xxtea_rejects_non_block_aligned_input() {
		assert!(xxtea_encrypt(b"").is_err());
		assert!(xxtea_decrypt(b"abc").is_err());
	}
}
