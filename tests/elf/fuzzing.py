#!/usr/bin/env python
import sys
import subprocess
import lief
import os
import shutil
import argparse
from utils import is_linux, is_x86_64

def generate_samples(melkor, seed='/usr/bin/ls', nb=100):
    cmd = [melkor, '-A', seed, '-n', str(nb), '-q']
    output_dir = "orcs_{}".format(os.path.basename(seed))
    output_dir = os.path.join(os.path.dirname(melkor), output_dir)

    if os.path.exists(output_dir) and os.path.isdir(output_dir):
        shutil.rmtree(output_dir)
    p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.PIPE, cwd = os.path.dirname(melkor))
    out, err = p.communicate()

    return output_dir

def fuzz(melkor, seed, nb):
    outputdir = generate_samples(melkor, seed, nb)
    for _, __, filesname in os.walk(outputdir):
        for file in filesname:
            filepath = os.path.join(outputdir, file)
            if lief.is_elf(filepath):
                print("Try to parse {}".format(filepath))
                try:
                    b = lief.parse(filepath)
                except lief.exception as e:
                    pass


if __name__ == '__main__':

    if not is_linux() and not is_x86_64():
        print("Melkor fuzzing is currently only supported on Linux x86-64", file=sys.stderr)
        sys.exit(0)

    parser = argparse.ArgumentParser(description = "LIEF ELF Fuzzer")
    parser.add_argument("--input-seed",
            dest = 'input_seed',
            type = str,
            default = '/usr/bin/ls')

    parser.add_argument("--numberof_samples", "-n",
            dest = 'nb_samples',
            type = int,
            default = 100)

    parser.add_argument("melkor")

    args = parser.parse_args()
    fuzz(args.melkor, args.input_seed, args.nb_samples)
    print(lief)


