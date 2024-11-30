from pydantic import BaseModel
from typing import Optional
from models.python.unittest import Metrics as UnittestMetrics
from models.python.native_library import Metrics as NativeLibraryMetric

class Metrics(BaseModel):
    unittest: Optional[UnittestMetrics] = None
    native_library: Optional[NativeLibraryMetric] = None
