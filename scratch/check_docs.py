"""Offline Markdown file/heading-link check for the public documentation."""
from html.parser import HTMLParser
from pathlib import Path
import re
import unicodedata
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]


class LocalLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        self.links.extend(value for key, value in attrs if key in ("href", "src") and value)


def without_fences(text):
    return re.sub(r"^\s*(`{3,}|~{3,}).*?^\s*\1\s*$", "", text, flags=re.M | re.S)


def anchors(text):
    result, counts = set(), {}
    for heading in re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", without_fences(text), re.M):
        heading = re.sub(r"<[^>]+>", "", heading).lower()
        slug = "".join(c for c in heading if c in "_- " or unicodedata.category(c)[0] in "LN")
        slug = slug.replace(" ", "-")
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        result.add(f"{slug}-{count}" if count else slug)
    result.update(re.findall(r'(?:id|name)=[\"\x27]([^\"\x27]+)', text))
    return result


def main():
    files = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    errors, checked = [], 0
    for source in files:
        text = without_fences(source.read_text(encoding="utf-8"))
        parser = LocalLinks()
        parser.feed(text)
        links = re.findall(r"!?\[[^\]\n]*\]\(([^\s)]+)(?:\s+[^)]*)?\)", text)
        for link in links + parser.links:
            parsed = urlsplit(link.strip("<>"))
            if parsed.scheme or parsed.netloc:
                continue
            # Runtime paths are not repository files.
            if parsed.path.startswith("/"):
                continue
            target = (source.parent / unquote(parsed.path)).resolve() if parsed.path else source
            checked += 1
            if not target.exists():
                errors.append(f"{source.relative_to(ROOT)}: missing target {link}")
            elif parsed.fragment and target.suffix.lower() == ".md":
                if unquote(parsed.fragment) not in anchors(target.read_text(encoding="utf-8")):
                    errors.append(f"{source.relative_to(ROOT)}: missing heading {link}")
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Documentation links passed: {len(files)} files, {checked} local links.")


if __name__ == "__main__":
    main()
