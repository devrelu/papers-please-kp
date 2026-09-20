from typing import TypedDict

class ArtEntry(TypedDict):
	name: str
	size: int

def loads(encrypted: bytes, /) -> list[ArtEntry]: ...
