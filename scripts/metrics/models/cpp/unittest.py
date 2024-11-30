from pydantic import BaseModel
from typing import Optional

class Metrics(BaseModel):
    duration: Optional[float] = None
    nb_errors: int = 0
    nb_skipped: int = 0
    nb_failures: int = 0
    nb_tests: int = 0
