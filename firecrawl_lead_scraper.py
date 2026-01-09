#!/usr/bin/env python3
import argparse
import json
import os
import re
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from firecrawl import Firecrawl


CENTRAL_PAGE_KEYWORDS = ["kontakt", "impressum"]
ROLE_KEYWORDS = [
    "einrichtungsleitung",
    "klinikleitung",
    "geschäftsführung",
    "direktion",
    "verwaltungsleitung",
    "pflegedienstleitung",
    "personalleitung",
    "leitung",
    "ansprechpartner",
]
ROLE_PRIORITY = [
    "einrichtungsleitung",
    "klinikleitung",
    "geschäftsführung",
    "direktion",
    "verwaltungsleitung",
    "pflegedienstleitung",
    "personalleitung",
]

EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_REGEX = re.compile(r"(\+49|0)[0-9][0-9\s\/\-()]{6,}")
NAME_REGEX = re.compile(
    r"([A-ZÄÖÜ][A-Za-zÄÖÜäöüß\-]+(?:\s+[A-ZÄÖÜ][A-Za-zÄÖÜäöüß\-]+){1,3})"
)


@dataclass
class Contact:
    phone: Optional[str] = None
    email: Optional[str] = None
    source_url: Optional[str] = None


@dataclass
class DecisionMaker:
    name: Optional[str]
    role: Optional[str]
    phone: Optional[str]
    email: Optional[str]
    source_url: Optional[str]


@dataclass
class CrawlResult:
    organization_name: str
    site: str
    central_contact: Contact
    decision_makers: List[DecisionMaker]


@dataclass
class Document:
    markdown: str
    metadata: dict


def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def extract_emails(text: str) -> List[str]:
    return list(dict.fromkeys(match.group(0) for match in EMAIL_REGEX.finditer(text)))


def extract_phones(text: str) -> List[str]:
    phones = [normalize_space(match.group(0)) for match in PHONE_REGEX.finditer(text)]
    return list(dict.fromkeys(phones))


def pick_first(items: Iterable[str]) -> Optional[str]:
    for item in items:
        return item
    return None


def infer_org_name(base_url: str, documents: List[Document]) -> str:
    for doc in documents:
        source_url = doc.metadata.get("sourceURL") or doc.metadata.get("url")
        if source_url and source_url.rstrip("/") == base_url.rstrip("/"):
            title = doc.metadata.get("title")
            if title:
                return normalize_space(title)
    parsed = urlparse(base_url)
    return parsed.netloc


def is_central_page(url: str, title: str) -> bool:
    candidate = f"{url} {title}".lower()
    return any(keyword in candidate for keyword in CENTRAL_PAGE_KEYWORDS)


def is_decision_page(url: str, text: str) -> bool:
    candidate = f"{url} {text}".lower()
    return any(keyword in candidate for keyword in ROLE_KEYWORDS)


def extract_role(line: str) -> Optional[str]:
    line_lower = line.lower()
    for role in ROLE_PRIORITY:
        if role in line_lower:
            return role
    return None


def extract_decision_makers(text: str, source_url: str) -> List[DecisionMaker]:
    decision_makers: List[DecisionMaker] = []
    seen = set()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for idx, line in enumerate(lines):
        role = extract_role(line)
        if not role:
            continue
        context_lines = [line]
        if idx > 0:
            context_lines.insert(0, lines[idx - 1])
        if idx + 1 < len(lines):
            context_lines.append(lines[idx + 1])
        context_text = " ".join(context_lines)
        name_match = NAME_REGEX.search(context_text)
        name = name_match.group(1) if name_match else None
        emails = extract_emails(context_text)
        phones = extract_phones(context_text)
        record_key = (name or "", role)
        if record_key in seen:
            continue
        seen.add(record_key)
        decision_makers.append(
            DecisionMaker(
                name=name,
                role=role,
                phone=pick_first(phones),
                email=pick_first(emails),
                source_url=source_url,
            )
        )
    return decision_makers


def collect_documents(raw_docs: Iterable[dict]) -> List[Document]:
    documents: List[Document] = []
    for doc in raw_docs:
        markdown = doc.get("markdown") or ""
        metadata = doc.get("metadata") or {}
        documents.append(Document(markdown=markdown, metadata=metadata))
    return documents


def crawl_site(
    api_key: str,
    url: str,
    limit: int,
    only_main_content: bool,
) -> List[Document]:
    client = Firecrawl(api_key=api_key)
    response = client.crawl(
        url=url,
        limit=limit,
        scrape_options={
            "formats": ["markdown"],
            "onlyMainContent": only_main_content,
        },
    )
    raw_docs = response.data if hasattr(response, "data") else response.get("data", [])
    return collect_documents(raw_docs)


def summarize_contacts(base_url: str, documents: List[Document]) -> CrawlResult:
    org_name = infer_org_name(base_url, documents)
    central_contact = Contact()
    decision_makers: List[DecisionMaker] = []

    for doc in documents:
        source_url = doc.metadata.get("sourceURL") or doc.metadata.get("url") or ""
        title = doc.metadata.get("title") or ""
        text = doc.markdown or ""

        if not central_contact.phone or not central_contact.email:
            if is_central_page(source_url, title):
                emails = extract_emails(text)
                phones = extract_phones(text)
                if emails or phones:
                    central_contact.email = central_contact.email or pick_first(emails)
                    central_contact.phone = central_contact.phone or pick_first(phones)
                    central_contact.source_url = central_contact.source_url or source_url

        if len(decision_makers) < 3 and is_decision_page(source_url, text):
            candidates = extract_decision_makers(text, source_url)
            for candidate in candidates:
                if len(decision_makers) >= 3:
                    break
                decision_makers.append(candidate)

    return CrawlResult(
        organization_name=org_name,
        site=base_url,
        central_contact=central_contact,
        decision_makers=decision_makers,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Crawl a site with Firecrawl and extract central contact + decision makers."
    )
    parser.add_argument("url", help="Base URL to crawl")
    parser.add_argument("--limit", type=int, default=40, help="Max pages to crawl")
    parser.add_argument(
        "--only-main-content",
        action="store_true",
        help="Restrict extraction to main content",
    )
    parser.add_argument(
        "--output",
        help="Optional path to write JSON output. Defaults to stdout if omitted.",
    )
    parser.add_argument(
        "--api-key",
        help="Firecrawl API key. Defaults to FIRECRAWL_API_KEY env var.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    api_key = args.api_key or os.environ.get("FIRECRAWL_API_KEY")
    if not api_key:
        raise SystemExit("Missing Firecrawl API key. Set --api-key or FIRECRAWL_API_KEY.")

    documents = crawl_site(
        api_key=api_key,
        url=args.url,
        limit=args.limit,
        only_main_content=args.only_main_content,
    )
    result = summarize_contacts(args.url, documents)
    output = json.dumps(
        {
            "organization_name": result.organization_name,
            "site": result.site,
            "central_contact": asdict(result.central_contact),
            "decision_makers": [asdict(dm) for dm in result.decision_makers],
        },
        ensure_ascii=False,
        indent=2,
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
            handle.write("\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
