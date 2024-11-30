from pydantic import BaseModel
from typing import Optional

class Metrics(BaseModel):
    peak_heap: Optional[int] = None
    peak_rss: Optional[int] = None
    leak: Optional[int] = None
