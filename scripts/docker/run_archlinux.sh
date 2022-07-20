#!/usr/bin/sh
set -ex

# This script assumes:
#   1. LIEF repo is mounted in /src
#   2. A valid Python wheel is available in dist/
#
# docker run --rm -v LIEF_SOURCE:/src liefproject/archlinux bash /src/scripts/docker/run_archlinux.sh

export LIEF_SAMPLES_DIR=/tmp/samples
export PYTHONPATH="/src/tests:$PYTHONPATH"

python -m pip install --upgrade pip
python -m pip install pytest

python -m pip install --no-index --find-links /src/dist lief

mkdir -p ${LIEF_SAMPLES_DIR}
[ ! -d "${LIEF_SAMPLES_DIR}/ELF" ] && python /src/tests/dl_samples.py ${LIEF_SAMPLES_DIR}

python -m pytest -rsx \
      /src/tests/elf/test_builder.py \
      /src/tests/elf/test_object_files.py \
      /src/tests/elf/test_section_frame.py \
      /src/tests/elf/test_466.py \
      /src/tests/elf/test_747.py \
      /src/tests/elf/test_empty_gnu_hash.py





