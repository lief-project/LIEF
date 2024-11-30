from pydantic import BaseModel
from typing import Optional
from models.cpp.unittest import Metrics as UnittestMetrics
from models.cpp.memory import Metrics as MemoryMetrics

class Metrics(BaseModel):
    unittest: Optional[UnittestMetrics] = None
    memory: Optional[MemoryMetrics] = None
