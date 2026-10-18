"""Validated data contracts shared by the Nim parser and Python analysis."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SectionFeature(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=8)
    entropy: float = Field(ge=0.0, le=8.0)


class PEFeatureDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal[1]
    file_path: str = Field(min_length=1)
    architecture: Literal["PE32", "PE32+"]
    sections: list[SectionFeature]
    imports: list[str]
    content_hash: str = Field(min_length=1)
    content_hash: str | None = None
