from pydantic import BaseModel
from typing import Optional
from models.python import Metrics as PythonMetrics
from models.cpp import Metrics as CppMetrics

class Metrics(BaseModel):
    python: Optional[PythonMetrics] = None
    cpp: Optional[CppMetrics] = None
