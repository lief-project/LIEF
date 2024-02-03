import requests
import sys
import zipfile
import os
import progressbar
import argparse
from pathlib import Path

URL = "https://lief-tests.s3.fr-par.scw.cloud/lief_tests.zip"
DIR_ENV = os.getenv("LIEF_SAMPLES_DIR", None)
TIMEOUT = 3 # sec

def hsize(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"

def mb(value: int) -> float:
    return round(value / (1024 * 1024), 3)

def download(url: str, dst: Path, use_progress_bar: bool = True):
    out = dst / "samples.zip"
    if out.is_file():
        print(f"{out} already exists")
        return out
    print(f"Downloading {url} in {out} ...")
    with requests.get(url, stream=True, timeout=TIMEOUT) as r:
        r.raise_for_status()
        size = int(r.headers['Content-Length'].strip())
        pbar = progressbar.ProgressBar(maxval=mb(size))
        if use_progress_bar:
            pbar.start()
        print(f"Total size: {hsize(size)}")
        current_len = 0
        with open(out, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
                current_len += len(chunk)
                if use_progress_bar:
                    pbar.update(mb(current_len))

    print("done!")
    return out

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=URL)
    parser.add_argument("--no-progressbar", action="store_true", default=False)

    parser.add_argument("dst_dir", nargs='?')

    args = parser.parse_args()
    dst_dir = args.dst_dir
    if args.dst_dir is None:
        if DIR_ENV is None:
            print("Destination dir not set")
            sys.exit(1)
        dst_dir = Path(DIR_ENV)

    dst_dir_path: Path = Path(dst_dir)
    dst_dir_path.mkdir(exist_ok=True)

    use_progress_bar: bool = not args.no_progressbar
    try:
        zip_samples = download(args.url, dst_dir_path,
                               use_progress_bar=use_progress_bar)

        with zipfile.ZipFile(zip_samples) as zfile:
            zfile.extractall(path=dst_dir_path)
    except KeyboardInterrupt:
        print("Aborted!")
        (dst_dir_path / "samples.zip").unlink(missing_ok=True)
        sys.exit(1)

    print(f"Files extracted in '{dst_dir_path}'")

if __name__ == "__main__":
    main()
