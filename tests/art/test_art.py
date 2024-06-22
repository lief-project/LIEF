#!/usr/bin/env python
import lief
from utils import get_sample

lief.logging.set_level(lief.logging.LEVEL.INFO)

def test_art17():
    boot = lief.ART.parse(get_sample("ART/ART_017_AArch64_boot.art"))
    assert boot.header is not None

def test_art29():
    boot = lief.ART.parse(get_sample("ART/ART_029_ARM_boot.art"))
    assert boot.header is not None

def test_art30():
    boot = lief.ART.parse(get_sample("ART/ART_030_AArch64_boot.art"))
    assert boot.header is not None

def test_art44():
    boot = lief.ART.parse(get_sample("ART/ART_044_ARM_boot.art"))
    assert boot.header is not None

def test_art46():
    boot = lief.ART.parse(get_sample("ART/ART_046_AArch64_boot.art"))

    assert boot.header is not None

def test_art56():
    boot = lief.ART.parse(get_sample("ART/ART_056_AArch64_boot.art"))
    assert boot.header is not None

