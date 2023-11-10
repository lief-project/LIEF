#!/usr/bin/env python
import sys
import subprocess
import lief
import os
import shutil
import argparse
from pathlib import Path
from utils import is_linux, is_x86_64

DEFAULT_TIMEOUT = 60 # sec

def generate_samples(melkor, seed='/usr/bin/ls', nb=100):
    cmd = [melkor, '-A', seed, '-n', str(nb), '-q']

    seed_path = Path(seed)
    melkor_path = Path(melkor).parent
    if not seed_path.is_file():
        print(f"{seed} does not exist!")
        sys.exit(1)

    output_dir = melkor_path / f"orcs_{seed_path.name}"
    print(f"Files are generated in {output_dir}")

    if output_dir.is_dir():
        shutil.rmtree(output_dir)

    print("Running: {} (cwd={})".format(" ".join(cmd), melkor_path.parent))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              cwd=melkor_path)
    out, err = p.communicate()

    return output_dir

def fuzz(melkor, seed, nb):
    lief.logging.disable()
    print(f"Generating #{nb} samples for {seed}")
    outputdir: Path = generate_samples(melkor, seed, nb)
    print(outputdir)
    for file in outputdir.iterdir():
        if not lief.is_elf(file.as_posix()):
            continue

        print(f"Trying to parse {file!s}")
        try:
            subprocess.check_call(
                (
                    sys.executable, "-c",
                    f"import lief;lief.logging.disable();lief.parse('{file.as_posix()}')"
                ),
                timeout=DEFAULT_TIMEOUT,
                env=os.environ.copy()
            )
        except subprocess.TimeoutExpired:
            print("Timeout!")

if __name__ == '__main__':
    if not is_linux() and not is_x86_64():
        print("Melkor fuzzing is currently only supported on Linux x86-64",
              file=sys.stderr)
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
    sys.exit(0)
