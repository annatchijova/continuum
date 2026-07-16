"""
legacy/ingestion/doc_types.py
==============================
Taxonomia of tipos of document of the legado digital.

each categoria tiene:
  - keywords  : terms that aumentan the senal (Fraction weight)
  - patterns  : regex for deteccion estructural
  - priority  : importancia for the guia of heirs (1 = maxima)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from fractions import Fraction
from typing import Dict, List, Pattern, Tuple


class DocCategory(str, Enum):
    LEGAL       = "legal"           # escrituras, testamentos, contratos
    FINANCIAL   = "financial"       # cuentas, inversiones, seguros
    MEDICAL     = "medical"         # historial clinical, recetas
    IDENTITY    = "identity"        # DNI, pasaporte, licencias
    REAL_ESTATE = "real_estate"     # property, hipotecas, alquileres
    SUBSCRIPTION= "subscription"    # servicios activos, suscripciones
    PROFESSIONAL= "professional"    # titulos, curriculum, proyectos laborales
    MEDIA       = "media"           # fotos, videos, audio
    PERSONAL    = "personal"        # diarios, cartas, memories
    CREDENTIAL  = "credential"      # indicios of accesos (without contrasenas)
    UNKNOWN     = "unknown"


@dataclass
class CategoryProfile:
    category: DocCategory
    priority: int                   # 1 = maxima urgencia for heirs
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
            "testamento", "testament", "poder notarial", "power of attorney",
            "escritura", "deed", "contract", "contract", "acuerdo", "agreement",
            "herencia", "inheritance", "albacea", "executor", "fideicomiso",
            "trust", "notaria", "notary", "juzgado", "tribunal", "court",
            "demanda", "judgment", "ruling", "resolucion",
        ],
        patterns=[
            r"\b(instrumento\s+p[uu]blico|instrumento\s+privado)\b",
            r"\b(ante\s+m[ii]\s+the\s+notario|before\s+me\s+the\s+notary)\b",
            r"\b(by\s+medio\s+of the\s+presente|by\s+means\s+of\s+this)\b",
        ],
        weight=Fraction(3),
    ),

    DocCategory.FINANCIAL: CategoryProfile(
        category=DocCategory.FINANCIAL,
        priority=1,
        keywords=[
            "cuenta bancaria", "bank account", "saldo", "balance",
            "inversion", "investment", "fondo", "fund", "acciones", "stocks",
            "seguro of vida", "life insurance", "poliza", "policy",
            "prestamo", "loan", "hipoteca", "mortgage", "credito", "credit",
            "jubilacion", "pension", "retirement", "dividendo", "dividend",
            "declaracion of renta", "tax return", "impuesto", "tax",
            "extracto bancario", "bank statement", "IBAN", "SWIFT",
        ],
        patterns=[
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",  # IBAN
            r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b",              # tarjeta
            r"\$[\d,]+(\.\d{2})?|\[\d,]+(\.\d{2})?",                 # montos
        ],
        weight=Fraction(3),
    ),

    DocCategory.MEDICAL: CategoryProfile(
        category=DocCategory.MEDICAL,
        priority=2,
        keywords=[
            "historial medico", "medical history", "diagnosis", "diagnosis",
            "receta", "prescription", "medicamento", "medication", "dose",
            "hospital", "clinica", "clinic", "medico", "doctor", "physician",
            "cirugia", "surgery", "treatment", "treatment", "vacuna",
            "vaccine", "analysis", "laboratorio", "laboratory",
        ],
        patterns=[
            r"\b(mg|ml|gr)\s*\d+\b",
            r"\b(each\s+\d+\s+horas?|each\s+\d+\s+d[ii]as?)\b",
            r"\b(CIE|ICD)[-\s]\d+\b",
        ],
        weight=Fraction(2),
    ),

    DocCategory.IDENTITY: CategoryProfile(
        category=DocCategory.IDENTITY,
        priority=1,
        keywords=[
            "document nacional", "national identity", "DNI", "pasaporte",
            "passport", "licencia of conducir", "driver license",
            "numero of identificacion", "ID number", "CUIL", "CUIT",
            "RFC", "SSN", "numero of seguridad social",
        ],
        patterns=[
            r"\b[A-Z]{1,3}\d{6,9}[A-Z0-9]?\b",   # formatos comunes of ID
            r"\b\d{3}-\d{2}-\d{4}\b",              # SSN formato US
        ],
        weight=Fraction(3),
    ),

    DocCategory.REAL_ESTATE: CategoryProfile(
        category=DocCategory.REAL_ESTATE,
        priority=2,
        keywords=[
            "property", "property", "inmueble", "vivienda", "house",
            "departamento", "apartment", "terreno", "land", "parcela",
            "hipoteca", "mortgage", "alquiler", "rental", "arriendo",
            "expensas", "HOA", "catastro", "cadastre", "matricula",
            "folio real", "title of property", "deed",
        ],
        patterns=[
            r"\b(lote|parcela|manzana)\s+\d+\b",
            r"\bfolio\s+(real\s+)?\d+\b",
        ],
        weight=Fraction(2),
    ),

    DocCategory.SUBSCRIPTION: CategoryProfile(
        category=DocCategory.SUBSCRIPTION,
        priority=2,
        keywords=[
            "suscripcion", "subscription", "plan mensual", "monthly plan",
            "renovacion automatica", "auto-renewal", "facturacion",
            "billing", "Netflix", "Spotify", "Amazon", "Apple",
            "Google", "Microsoft", "Adobe", "GitHub", "dropbox",
            "iCloud", "OneDrive", "membresia", "membership",
        ],
        patterns=[
            r"\b(is\s+renova|will\s+renew|auto.renew)\b",
            r"\b(cargo\s+mensual|monthly\s+charge|billed\s+monthly)\b",
            r"\b(cancelar\s+in|cancel\s+by|proxima\s+factura|next\s+bill)\b",
        ],
        weight=Fraction(2),
    ),

    DocCategory.PROFESSIONAL: CategoryProfile(
        category=DocCategory.PROFESSIONAL,
        priority=3,
        keywords=[
            "curriculum", "curriculum", "CV", "resume", "title",
            "degree", "certificado", "certificate", "diploma", "acreditacion",
            "proyecto", "project", "cliente", "client", "contract laboral",
            "employment", "empleo", "empresa", "company",
        ],
        patterns=[
            r"\b(ingeniero|medico|abogado|docente|profesor)\b",
            r"\b(licenciado|licenciada|doctor|doctora)\s+in\b",
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
            "querido", "dear", "carta", "letter", "diario",
            "journal", "diary", "recuerdo", "memory", "memoir",
        ],
        patterns=[
            r"^(Querido|Dear|A quien\s+corresponda)\b",
        ],
        weight=Fraction(1),
    ),

    DocCategory.CREDENTIAL: CategoryProfile(
        category=DocCategory.CREDENTIAL,
        priority=2,
        keywords=[
            "contrasena", "password", "usuario", "username",
            "correo electronico", "email", "cuenta", "account",
            "inicio of session", "login", "acceso", "access",
            "autenticacion", "authentication", "2FA", "MFA",
        ],
        patterns=[
            r"\b(login|usuario|user):\s*\S+\b",
        ],
        weight=Fraction(2),
    ),
}

# Implementation note.
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
    ".xls": DocCategory.FINANCIAL,  # probablemente financiero
    ".xlsx": DocCategory.FINANCIAL,
    ".csv": DocCategory.UNKNOWN,
    ".txt": DocCategory.UNKNOWN,
    ".md": DocCategory.PERSONAL,
}
