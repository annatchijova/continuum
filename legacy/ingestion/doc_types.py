"""
legacy/ingestion/doc_types.py
==============================
Taxonomy of digital-legacy document types.

Each category has:
  - keywords  : terms that increase the signal (Fraction weight)
  - patterns  : regexes for structural detection
  - priority  : importance for the heir guide (1 = highest)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from fractions import Fraction
from typing import Dict, List, Pattern, Tuple


class DocCategory(str, Enum):
    LEGAL       = "legal"           # deeds, wills, contracts
    FINANCIAL   = "financial"       # accounts, investments, insurance
    MEDICAL     = "medical"         # medical history, prescriptions
    IDENTITY    = "identity"        # identity cards, passports, licenses
    REAL_ESTATE = "real_estate"     # property, mortgages, rentals
    SUBSCRIPTION= "subscription"    # active services, subscriptions
    PROFESSIONAL= "professional"    # degrees, resumes, work projects
    MEDIA       = "media"           # photos, videos, audio
    PERSONAL    = "personal"        # journals, letters, memories
    CREDENTIAL  = "credential"      # access clues (not passwords)
    UNKNOWN     = "unknown"


@dataclass
class CategoryProfile:
    category: DocCategory
    priority: int                   # 1 = highest urgency for heirs
    keywords: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)   # regex strings
    weight: Fraction = Fraction(1)

    def compiled_patterns(self) -> List[re.Pattern]:
        return [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.patterns]


CATEGORY_PROFILES: Dict[DocCategory, CategoryProfile] = {
    DocCategory.LEGAL: CategoryProfile(
        category=DocCategory.LEGAL,
        priority=1,
        keywords=[
            "will", "testament", "power of attorney", "deed", "contract",
            "agreement", "inheritance", "executor", "trust", "notary",
            "court", "lawsuit", "judgment", "ruling", "resolution",
        ],
        patterns=[
            r"\b(public\s+instrument|private\s+instrument)\b",
            r"\b(before\s+me\s+the\s+notary)\b",
            r"\b(by\s+means\s+of\s+this)\b",
        ],
        weight=Fraction(3),
    ),

    DocCategory.FINANCIAL: CategoryProfile(
        category=DocCategory.FINANCIAL,
        priority=1,
        keywords=[
            "bank account", "balance", "investment", "fund", "stocks",
            "life insurance", "policy", "loan", "mortgage", "credit",
            "pension", "retirement", "dividend", "tax return", "tax",
            "bank statement", "IBAN", "SWIFT",
        ],
        patterns=[
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",  # IBAN
            r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b",              # card
            r"\$[\d,]+(\.\d{2})?|\[\d,]+(\.\d{2})?",                 # amounts
        ],
        weight=Fraction(3),
    ),

    DocCategory.MEDICAL: CategoryProfile(
        category=DocCategory.MEDICAL,
        priority=2,
        keywords=[
            "medical history", "diagnosis", "prescription", "medication", "dose",
            "hospital", "clinic", "doctor", "physician", "surgery", "treatment",
            "vaccine", "analysis", "laboratory",
        ],
        patterns=[
            r"\b(mg|ml|gr)\s*\d+\b",
            r"\b(each\s+\d+\s+hours?|each\s+\d+\s+days?)\b",
            r"\b(CIE|ICD)[-\s]\d+\b",
        ],
        weight=Fraction(2),
    ),

    DocCategory.IDENTITY: CategoryProfile(
        category=DocCategory.IDENTITY,
        priority=1,
        keywords=[
            "national identity document", "DNI", "passport", "driver license",
            "identification number", "ID number", "CUIL", "CUIT", "RFC", "SSN",
            "social security number",
        ],
        patterns=[
            r"\b[A-Z]{1,3}\d{6,9}[A-Z0-9]?\b",   # common ID formats
            r"\b\d{3}-\d{2}-\d{4}\b",           # US SSN format
        ],
        weight=Fraction(3),
    ),

    DocCategory.REAL_ESTATE: CategoryProfile(
        category=DocCategory.REAL_ESTATE,
        priority=2,
        keywords=[
            "property", "house", "apartment", "land", "parcel", "mortgage",
            "rental", "HOA", "cadastre", "title", "real folio", "deed",
        ],
        patterns=[
            r"\b(lot|parcel|block)\s+\d+\b",
            r"\bfolio\s+(real\s+)?\d+\b",
        ],
        weight=Fraction(2),
    ),

    DocCategory.SUBSCRIPTION: CategoryProfile(
        category=DocCategory.SUBSCRIPTION,
        priority=2,
        keywords=[
            "subscription", "monthly plan", "auto-renewal", "billing",
            "Netflix", "Spotify", "Amazon", "Apple",
            "Google", "Microsoft", "Adobe", "GitHub", "dropbox",
            "iCloud", "OneDrive", "membership",
        ],
        patterns=[
            r"\b(will\s+renew|auto.renew)\b",
            r"\b(monthly\s+charge|billed\s+monthly)\b",
            r"\b(cancel\s+by|next\s+bill)\b",
        ],
        weight=Fraction(2),
    ),

    DocCategory.PROFESSIONAL: CategoryProfile(
        category=DocCategory.PROFESSIONAL,
        priority=3,
        keywords=[
            "curriculum", "CV", "resume", "title", "degree", "certificate",
            "diploma", "accreditation", "project", "client", "employment",
            "company",
        ],
        patterns=[
            r"\b(engineer|doctor|lawyer|teacher|professor)\b",
            r"\b(graduate|doctor)\s+in\b",
        ],
        weight=Fraction(1),
    ),

    DocCategory.MEDIA: CategoryProfile(
        category=DocCategory.MEDIA,
        priority=4,
        keywords=[],
        patterns=[],
        weight=Fraction(1),
    ),

    DocCategory.PERSONAL: CategoryProfile(
        category=DocCategory.PERSONAL,
        priority=4,
        keywords=[
            "dear", "letter", "journal", "diary", "memory", "memoir",
        ],
        patterns=[
            r"^(Dear|To whom\s+it\s+may\s+concern)\b",
        ],
        weight=Fraction(1),
    ),

    DocCategory.CREDENTIAL: CategoryProfile(
        category=DocCategory.CREDENTIAL,
        priority=2,
        keywords=[
            "password", "username", "email", "account", "login", "access",
            "authentication", "2FA", "MFA",
        ],
        patterns=[
            r"\b(login|user):\s*\S+\b",
        ],
        weight=Fraction(2),
    ),
}

# File-extension hints.
EXTENSION_HINTS: Dict[str, DocCategory] = {
    ".jpg": DocCategory.MEDIA,
    ".jpeg": DocCategory.MEDIA,
    ".png": DocCategory.MEDIA,
    ".heic": DocCategory.MEDIA,
    ".gif": DocCategory.MEDIA,
    ".mp4": DocCategory.MEDIA,
    ".mov": DocCategory.MEDIA,
    ".avi": DocCategory.MEDIA,
    ".mp3": DocCategory.MEDIA,
    ".flac": DocCategory.MEDIA,
    ".pdf": DocCategory.UNKNOWN,    # needs analysis of content
    ".doc": DocCategory.UNKNOWN,
    ".docx": DocCategory.UNKNOWN,
    ".xls": DocCategory.FINANCIAL,  # probably financial
    ".xlsx": DocCategory.FINANCIAL,
    ".csv": DocCategory.UNKNOWN,
    ".txt": DocCategory.UNKNOWN,
    ".md": DocCategory.PERSONAL,
}
