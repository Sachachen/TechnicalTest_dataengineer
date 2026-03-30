import argparse
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

IPSUM_URLS = [
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
]


def download_ipsum(timeout: int = 20) -> str:
    """Download ipsum.txt content from GitHub, trying multiple default branches."""
    headers = {"User-Agent": "TechnicalTest-dataengineer/1.0"}

    for url in IPSUM_URLS:
        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except (HTTPError, URLError, TimeoutError):
            continue

    raise RuntimeError("Unable to download ipsum.txt from GitHub.")


def save_content(content: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download IPsum threat feed (ipsum.txt) from GitHub."
    )
    parser.add_argument(
        "-o",
        "--output",
        default="data/ipsum.txt",
        help="Output file path (default: data/ipsum.txt)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="HTTP timeout in seconds (default: 20)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_path = Path(args.output)

    try:
        content = download_ipsum(timeout=args.timeout)
        save_content(content, output_path)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"IPsum feed saved to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
