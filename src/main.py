import argparse
import shutil
import tempfile
from pathlib import Path
from urllib.parse import quote

import UnityPy

import ppserde

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
ART_HEADER_SIZE = 2


def get_art_asset(environment: UnityPy.Environment):
	for obj in environment.objects:
		if obj.type.name != "TextAsset":
			continue
		asset = obj.read()
		if asset.m_Name == "Art.dat":
			return asset
	raise ValueError("Art.dat TextAsset was not found")


def replace_art_entries(encrypted: bytes, replacements: dict[str, bytes]) -> bytes:
	entries = ppserde.loads(encrypted)
	known_names = {entry["name"] for entry in entries}
	missing = sorted(replacements.keys() - known_names)
	if missing:
		raise ValueError(f"Art.dat entries not found: {', '.join(missing)}")

	plaintext = ppserde.decrypt(encrypted)
	payload_offset = plaintext.find(PNG_SIGNATURE, ART_HEADER_SIZE)
	if payload_offset < 0:
		raise ValueError("Art.dat payload does not start with a PNG")

	metadata = plaintext[:payload_offset]
	metadata_edits: list[tuple[int, int, bytes]] = []
	for entry in entries:
		name = entry["name"]
		if name not in replacements:
			continue
		encoded_name = quote(name, safe="").encode()
		name_offset = metadata.find(encoded_name, ART_HEADER_SIZE)
		if name_offset < 0:
			raise ValueError(f"Art.dat metadata entry not found: {name}")
		old_marker = f"i{entry['size']}g".encode()
		size_offset = metadata.find(old_marker, name_offset + len(encoded_name))
		if size_offset < 0:
			raise ValueError(f"Art.dat size metadata not found: {name}")
		new_marker = f"i{len(replacements[name])}g".encode()
		metadata_edits.append((size_offset, size_offset + len(old_marker), new_marker))

	for start, end, replacement in sorted(metadata_edits, reverse=True):
		metadata = metadata[:start] + replacement + metadata[end:]

	metadata_size = len(metadata) - ART_HEADER_SIZE
	if metadata_size > 0xFFFF:
		raise ValueError(f"Art.dat metadata is too large: {metadata_size} bytes")
	metadata = metadata_size.to_bytes(ART_HEADER_SIZE, "little") + metadata[ART_HEADER_SIZE:]

	payload_end = payload_offset + sum(entry["size"] for entry in entries)
	if payload_end > len(plaintext):
		raise ValueError("Art.dat payload exceeds plaintext bounds")
	cursor = payload_offset
	payload_parts: list[bytes] = []
	for entry in entries:
		entry_end = cursor + entry["size"]
		payload_parts.append(replacements.get(entry["name"], plaintext[cursor:entry_end]))
		cursor = entry_end

	patched = metadata + b"".join(payload_parts)
	patched += bytes((-len(patched)) % 4)
	return ppserde.encrypt(patched)


def collect_replacements(directory: Path) -> dict[str, bytes]:
	files = sorted(path for path in directory.rglob("*") if path.is_file())
	if not files:
		raise ValueError(f"No replacement files found in {directory}")
	return {
		f"assets/{path.relative_to(directory).as_posix()}": path.read_bytes()
		for path in files
	}


def patch_art_file(assets_file: Path, replacements: dict[str, bytes]) -> None:
	environment = UnityPy.load(str(assets_file))
	art = get_art_asset(environment)
	encrypted = art.m_Script.encode("utf-8", "surrogateescape")
	patched = replace_art_entries(encrypted, replacements)
	art.m_Script = patched.decode("utf-8", "surrogateescape")
	art.save()

	with tempfile.TemporaryDirectory(dir=assets_file.parent) as temporary_directory:
		temporary_path = Path(temporary_directory)
		environment.save(out_path=str(temporary_path))
		generated = temporary_path / assets_file.name
		if not generated.is_file():
			raise RuntimeError(f"UnityPy did not save {assets_file.name}")
		_ = shutil.move(generated, assets_file)


def package_localizations(source_directory: Path, output_directory: Path) -> int:
	language_directories = sorted(path for path in source_directory.iterdir() if path.is_dir())
	if not language_directories:
		raise ValueError(f"No localization directories found in {source_directory}")
	output_directory.mkdir(parents=True, exist_ok=True)
	for language_directory in language_directories:
		entries = {
			f"/{path.relative_to(language_directory).as_posix()}": path.read_bytes()
			for path in sorted(p for p in language_directory.rglob("*") if p.is_file())
		}
		archive_path = output_directory / f"{language_directory.name}.zip"
		with tempfile.NamedTemporaryFile(
			dir=output_directory,
			prefix=f"{language_directory.name}.",
			suffix=".zip",
			delete=False,
		) as temporary:
			temporary_path = Path(temporary.name)
			_ = temporary.write(ppserde.zip_archive(entries))
		_ = temporary_path.replace(archive_path)
	return len(language_directories)


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Package and patch Papers, Please assets")
	_ = parser.add_argument("--assets-file", type=Path)
	_ = parser.add_argument("--replacement-dir", type=Path)
	_ = parser.add_argument("--loc-dir", type=Path)
	return parser.parse_args()


def main() -> None:
	args = parse_args()
	replacements = collect_replacements(args.replacement_dir)
	patch_art_file(args.assets_file, replacements)
	localization_output = args.assets_file.parent / "StreamingAssets/loc"
	language_count = package_localizations(args.loc_dir, localization_output)
	print(f"Patched {len(replacements)} Art.dat entries in {args.assets_file}")
	print(f"Packaged {language_count} localization archive(s) in {localization_output}")


if __name__ == "__main__":
	main()
