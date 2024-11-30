from pydantic import BaseModel
from typing import Optional

class Metrics(BaseModel):
    size: int = 0
    text_section: Optional[int] = None
