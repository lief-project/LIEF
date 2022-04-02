import requests
import pathlib
import sys
import zipfile
import os

URL = "https://data.romainthomas.fr/lief_tests.zip"
DIR_ENV = os.getenv("LIEF_SAMPLES_DIR", None)
DST = None

if len(sys.argv) > 1:
    DST = pathlib.Path(sys.argv[1])
elif DIR_ENV is not None:
    DST = pathlib.Path(DIR_ENV)
else:
    print("Destination dir not set")
    sys.exit(1)

DST.mkdir(exist_ok=True)

def download():
    out = DST / "samples.zip"
    if out.is_file():
        print("{} already exists".format(out))
        return out
    print("Downloading {} in {} ...".format(URL, out))
    with requests.get(URL, stream=True) as r:
        r.raise_for_status()
        with open(out, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    print("done!")
    return out

zip_samples = download()

with zipfile.ZipFile(zip_samples) as zfile:
    zfile.extractall(path=DST)

print("Files extracted in {}".format(DST))
