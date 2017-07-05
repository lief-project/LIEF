#!/usr/bin/env python
import os

def get_sample(filename):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    fullpath = os.path.join(current_dir, '..', 'samples', filename)

    assert os.path.exists(fullpath)
    assert os.path.isfile(fullpath)

    return fullpath

