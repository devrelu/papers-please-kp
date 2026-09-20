use haxeformat::StreamDeserializer;
use haxeformat::value::{DeserializationCache, HaxeObject, HaxeValue};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

fn convert_value(py: Python<'_>, value: HaxeValue) -> PyResult<Py<PyAny>> {
	match value {
		HaxeValue::Int(value) => Ok(value.into_pyobject(py)?.into_any().unbind()),
		HaxeValue::String(value) => Ok(value.into_pyobject(py)?.into_any().unbind()),
		HaxeValue::Object(value) => match *value {
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

#[pyfunction]
fn loads(py: Python<'_>, serialized: &str) -> PyResult<Py<PyAny>> {
	let mut decoder =
		StreamDeserializer::new(serialized.as_bytes(), DeserializationCache::new());
	let value: HaxeValue = decoder
		.deserialize()
		.map_err(|error| PyValueError::new_err(error.to_string()))?;
	decoder.end().map_err(|error| PyValueError::new_err(error.to_string()))?;
	convert_value(py, value)
}

#[pymodule]
fn pyhaxeformat(module: &Bound<'_, PyModule>) -> PyResult<()> {
	module.add_function(wrap_pyfunction!(loads, module)?)
}
