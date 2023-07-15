import requests
import pathlib
import sys
import zipfile
import os
import time
import progressbar

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

def hsize(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"

def mb(value: int) -> int:
    return round(value / (1024 * 1024), 3)

def download():
    out = DST / "samples.zip"
    if out.is_file():
        print("{} already exists".format(out))
        return out
    print("Downloading {} in {} ...".format(URL, out))
    with requests.get(URL, stream=True) as r:
        r.raise_for_status()
        size = int(r.headers['Content-Length'].strip())
        pbar = progressbar.ProgressBar(maxval=mb(size)).start()
        print(f"Total size: {hsize(size)}")
        current_len = 0
        with open(out, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
                current_len += len(chunk)
                pbar.update(mb(current_len))

    print("done!")
    return out

def main():
    zip_samples = download()

    with zipfile.ZipFile(zip_samples) as zfile:
        zfile.extractall(path=DST)

    print("Files extracted in {}".format(DST))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Aborted!")
        (DST / "samples.zip").unlink(missing_ok=True)
        sys.exit(1)
