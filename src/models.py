from pydantic import BaseModel, Field
from typing import Literal

class Finding(BaseModel):
    """
    Represents a detected secret or issue in the codebase.
    Rigidly validates all data types.
    """
    file: str
    line: int | str
    pattern: str
    severity: Literal["HIGH", "MEDIUM", "LOW"]
    content: str = Field(max_length=150)
