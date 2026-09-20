mod xxtea;
mod zip;

use std::io::Cursor;

use haxeformat::StreamDeserializer;
use haxeformat::value::{DeserializationCache, HaxeObject, HaxeValue};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

const ART_HEADER_LEN: usize = 2;
const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

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
	let data = xxtea::decrypt(encrypted).map_err(PyValueError::new_err)?;
	let metadata_end =
		data.windows(PNG_SIG.len()).position(|window| window == PNG_SIG).ok_or_else(
			|| PyValueError::new_err("Art.dat payload does not start with a PNG"),
		)?;
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
		xxtea::decrypt(encrypted.as_bytes()).map_err(PyValueError::new_err)?;
	Ok(PyBytes::new(py, &decrypted))
}

#[pyfunction]
fn encrypt<'py>(
	py: Python<'py>,
	plaintext: &Bound<'py, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
	let encrypted =
		xxtea::encrypt(plaintext.as_bytes()).map_err(PyValueError::new_err)?;
	Ok(PyBytes::new(py, &encrypted))
}

#[pyfunction]
fn loads(py: Python<'_>, encrypted: &Bound<'_, PyBytes>) -> PyResult<Py<PyAny>> {
	deserialize(py, encrypted.as_bytes())
}

#[pyfunction]
fn zip_archive<'py>(
	py: Python<'py>,
	entries: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyBytes>> {
	let mut values = Vec::with_capacity(entries.len());
	for (name, data) in entries.iter() {
		let name: String = name.extract()?;
		let data: Vec<u8> = data.extract()?;
		values.push((name, data));
	}
	let archive = zip::build(&values).map_err(PyValueError::new_err)?;
	Ok(PyBytes::new(py, &archive))
}

#[pymodule]
fn ppserde(module: &Bound<'_, PyModule>) -> PyResult<()> {
	module.add_function(wrap_pyfunction!(loads, module)?)?;
	module.add_function(wrap_pyfunction!(decrypt, module)?)?;
	module.add_function(wrap_pyfunction!(encrypt, module)?)?;
	module.add_function(wrap_pyfunction!(zip_archive, module)?)
}
