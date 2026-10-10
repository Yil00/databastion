#!/usr/bin/env python3
"""Held-out evaluation corpus for the Discovery classifiers (phase 2 exit criterion).

Python standard library only. Everything derives from ``SEED``, which differs from the dev seed
(``dev/seed/generate.py``), so running the script twice produces byte-identical files:

- ``dev/holdout/corpus.json``  (git-ignored, regenerated) unlabeled columns: engine, database, container, object, field, values
- ``dev/holdout/labels.json``  one label per column, in the ``dev/ground-truth.json`` location format

This corpus was written WITHOUT looking at the classifier implementation (independence rule, see
README.md). Do not tune classifiers against it; rotate ``SEED`` once per release cycle, before the
release candidate (see RELEASE.md).

All data is FAKE:
- e-mail domains are reserved (RFC 2606 / RFC 6761): example.{com,org,net}, *.example, *.test, *.invalid;
- phone numbers use ranges reserved for fiction where one exists (FR ARCEP, UK Ofcom, US 555-01xx,
  AU ACMA); other countries use random numbers in a plausible range, tied to nobody;
- cards, IBANs, NIRs, SIRET/SIREN, IMEIs, ISBNs and VAT numbers are random with valid check digits;
- AWS access key ids end in ``EXAMPLE`` and secret access keys in ``EXAMPLEKEY`` (AWS documentation
  convention, allowlisted by gitleaks' aws rule);
- password hashes are random bytes in the right encoding, not hashes of any password.

Usage:
    python3 dev/holdout/generate.py           # (re)write corpus.json and labels.json, print counts
    python3 dev/holdout/generate.py --check   # fail if the corpus SHA-256 or labels.json is out of date
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import random
import re
import sys
import unicodedata
import uuid
from collections import Counter
from pathlib import Path

SEED = 159_895_485  # holdout seed; MUST differ from dev/seed/generate.py (20260928). Rotate once per
# release cycle, before the release candidate (see RELEASE.md).
VERSION = 1
ROWS = 200
MIN_NEG_PER_TYPE = 16  # hard-negative columns per negative type
TARGET_POSITIVES = 62  # per classifier, before mixed free-text columns (see README "Sample size")

HERE = Path(__file__).resolve().parent
CORPUS_PATH = HERE / "corpus.json"
LABELS_PATH = HERE / "labels.json"

CLASSIFIERS = (
    "pii.birth_date", "pii.card_number", "pii.email", "pii.iban", "pii.nir", "pii.person_name",
    "pii.phone", "pii.postal_address", "secret.aws_key", "secret.password_hash",
)

# --------------------------------------------------------------------------------------------------
# Reference data (synthetic)
# --------------------------------------------------------------------------------------------------
FIRST = {
    "fr": ("Jean", "Marie", "Camille", "Louis", "Chloé", "Hugo", "Léa", "Mathéo", "Manon", "Théo",
           "Inès", "Maëlys", "Zoé", "Gaëtan", "Élodie", "Raphaël", "Anaïs", "Hélène", "Noémie",
           "Jérôme", "Céline", "François", "Benoît", "Aurélien", "Solène"),
    "en": ("Olivia", "James", "Amelia", "Noah", "Harper", "Liam", "Grace", "Oliver", "Ava", "Ethan",
           "Isla", "George", "Poppy", "Freddie", "Evelyn"),
    "de": ("Lukas", "Jürgen", "Anneliese", "Maximilian", "Björn", "Sören", "Käthe", "Jörg", "Ursula",
           "Wolfgang", "Leonie", "Günther"),
    "es": ("Mateo", "Lucía", "Sofía", "Martín", "Álvaro", "Inés", "Iñaki", "Begoña", "Ramón", "Nuria",
           "Joaquín", "Pilar"),
    "it": ("Giulia", "Alessandro", "Francesca", "Lorenzo", "Chiara", "Niccolò", "Beatrice", "Matteo",
           "Federica", "Gianluca"),
    "nl": ("Daan", "Sanne", "Joris", "Femke", "Pieter"),
}
COMPOUND_FIRST = ("Jean-Pierre", "Marie-Claire", "Anne-Sophie", "Jean-Baptiste", "Pierre-Louis",
                  "Marie-Hélène", "Hans-Jürgen", "Karl-Heinz", "María José", "José Luis", "Gian Marco")
LAST = {
    "fr": ("Martin", "Bernard", "Dubois", "Lefèvre", "Mercier", "Girard", "Bonnet", "Rousseau", "Faure",
           "Gauthier", "Chevalier", "Lemaître", "Barbier", "Brunet", "Guérin", "Perrin", "Morel"),
    "en": ("Walker", "Hughes", "Turner", "Bennett", "Fletcher", "Harrison", "Whitaker", "Morrison"),
    "de": ("Schröder", "Weiß", "Krüger", "Hoffmann", "Wagner", "Becker", "Schäfer", "Köhler", "Groß"),
    "es": ("Fernández", "López", "Martínez", "Sánchez", "Gómez", "Muñoz", "Jiménez", "Ruiz", "Ibáñez"),
    "it": ("Bianchi", "Colombo", "Ricci", "Marino", "Greco", "Bruno", "Galli", "Conti", "Esposito"),
}
PARTICLE_LAST = ("de La Fontaine", "de Villiers", "du Pontavice", "d'Aubigné", "van der Berg",
                 "van Dijk", "von Hohenberg", "zu Stolberg", "O'Connor", "O'Sullivan", "McAllister",
                 "Mac Giolla", "di Stefano", "Dell'Acqua", "De Luca", "Le Goff", "Le Bihan",
                 "Saint-Just", "Lévy-Bruhl", "García-Márquez", "Martín del Río")
ES_SECOND_LAST = ("Pérez", "Rodríguez", "Navarro", "Serrano", "Moreno", "Castillo")
TITLES = ("M.", "Mme", "Dr.", "Mr.", "Mrs.", "Ms.", "Herr", "Frau", "Sr.", "Sra.", "Sig.", "Prof.")

FR_STREETS = ("rue des Acacias", "avenue du Général Leclerc", "boulevard des Belges", "rue de la Gare",
              "impasse des Glycines", "place du Marché", "chemin de la Croix", "allée des Marronniers",
              "quai des Tanneurs", "route de Grenoble", "rue Pasteur", "cours Lafayette")
FR_CITIES = (("75012", "Paris"), ("69007", "Lyon"), ("13008", "Marseille"), ("31400", "Toulouse"),
             ("35000", "Rennes"), ("38000", "Grenoble"), ("21000", "Dijon"), ("64200", "Biarritz"),
             ("20000", "Ajaccio"), ("97400", "Saint-Denis"), ("54000", "Nancy"), ("87000", "Limoges"))
DE_STREETS = ("Hauptstraße", "Bahnhofstraße", "Lindenweg", "Gartenstraße", "Schillerstraße",
              "Am Mühlbach", "Kirchplatz", "Waldweg", "Rosenstraße")
DE_CITIES = (("10405", "Berlin"), ("80331", "München"), ("50667", "Köln"), ("20095", "Hamburg"),
             ("04109", "Leipzig"), ("70173", "Stuttgart"))
ES_STREETS = ("Calle Mayor", "Avenida de la Constitución", "Calle del Sol", "Paseo de las Acacias",
              "Plaza de España", "Calle Real")
ES_CITIES = (("28013", "Madrid"), ("08002", "Barcelona"), ("41004", "Sevilla"), ("46002", "Valencia"),
             ("50001", "Zaragoza"))
IT_STREETS = ("Via Roma", "Via Garibaldi", "Corso Italia", "Via dei Mille", "Piazza Dante",
              "Viale Europa", "Via Mazzini")
IT_CITIES = (("00184", "Roma", "RM"), ("20121", "Milano", "MI"), ("10121", "Torino", "TO"),
             ("50122", "Firenze", "FI"), ("80133", "Napoli", "NA"))
UK_STREETS = ("High Street", "Station Road", "Church Lane", "Victoria Road", "Mill Lane", "Park Avenue")
UK_CITIES = (("SW1A 2AA", "London"), ("M1 1AE", "Manchester"), ("LS1 4AP", "Leeds"),
             ("EH1 1YZ", "Edinburgh"), ("BS1 4DJ", "Bristol"))
US_STREETS = ("Maple Avenue", "Oak Street", "Washington Boulevard", "Pine Road", "Lakeview Drive",
              "Cedar Lane")
US_CITIES = (("Springfield", "IL", "62704"), ("Riverside", "CA", "92501"), ("Franklin", "TN", "37064"),
             ("Madison", "WI", "53703"), ("Salem", "OR", "97301"))
NL_STREETS = ("Kerkstraat", "Dorpsstraat", "Molenweg", "Stationsplein")
NL_CITIES = (("1012 AB", "Amsterdam"), ("3011 CD", "Rotterdam"), ("3511 EF", "Utrecht"))

EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "mail.example.com", "corp.example",
                 "shop.test", "firma.test", "azienda.test", "empresa.invalid", "entreprise.invalid",
                 "clients.example.org")
IDN_DOMAINS = ("exämple.test", "bücher.test", "españa.test", "société.example", "città.test")
RESERVED_EMAIL_SUFFIXES = (".example", ".test", ".invalid", "example.com", "example.org", "example.net")

# ARCEP numbers reserved for audiovisual fiction (FR national format, 10 digits).
FR_FICTION = ("019900", "026191", "035301", "046571", "053649", "063998", "097210")
AU_FICTION_MOBILE = ("0491570006", "0491570156", "0491570157", "0491570158", "0491570159",
                     "0491570110", "0491570313", "0491570737")

AWS_ID_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
CRYPT64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BCRYPT64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

MONTHS = {
    "fr": ("janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre",
           "octobre", "novembre", "décembre"),
    "en": ("January", "February", "March", "April", "May", "June", "July", "August", "September",
           "October", "November", "December"),
    "de": ("Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September",
           "Oktober", "November", "Dezember"),
    "es": ("enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre",
           "octubre", "noviembre", "diciembre"),
    "it": ("gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto",
           "settembre", "ottobre", "novembre", "dicembre"),
}

# IBAN BBAN layouts: (country, [(kind, length)]) with kind n=digits, a=upper letters, c=alnum upper.
IBAN_LAYOUTS = {
    "FR": None,  # built with a valid RIB key, see Gen.iban_fr
    "DE": (("n", 18),),
    "ES": (("n", 20),),
    "IT": (("a", 1), ("n", 10), ("c", 12)),
    "BE": (("n", 12),),
    "NL": (("a", 4), ("n", 10)),
    "GB": (("a", 4), ("n", 14)),
    "CH": (("n", 5), ("c", 12)),
    "LU": (("n", 3), ("c", 13)),
    "PT": (("n", 21),),
    "AT": (("n", 16),),
    "MC": None,  # same layout as FR
}
IBAN_LENGTHS = {"FR": 27, "DE": 22, "ES": 24, "IT": 27, "BE": 16, "NL": 18, "GB": 22, "CH": 21,
                "LU": 20, "PT": 25, "AT": 20, "MC": 27}


# --------------------------------------------------------------------------------------------------
# Check-digit builders (used to GENERATE values)
# --------------------------------------------------------------------------------------------------
def luhn_digit(partial: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(partial)):
        d = int(ch) * (2 if i % 2 == 0 else 1)
        total += d - 9 if d > 9 else d
    return str((10 - total % 10) % 10)


def mod97_check(country: str, bban: str) -> str:
    n = int("".join(str(int(c, 36)) for c in bban + country + "00"))
    return f"{98 - n % 97:02d}"


def nir_key_of(first13: str) -> str:
    s = first13.replace("2A", "19").replace("2B", "18")
    return f"{97 - int(s) % 97:02d}"


# --------------------------------------------------------------------------------------------------
# Independent validators (used ONLY to CHECK values; written differently on purpose)
# --------------------------------------------------------------------------------------------------
_LUHN_DOUBLE = (0, 2, 4, 6, 8, 1, 3, 5, 7, 9)


def check_luhn(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if len(digits) < 9 or any(c not in "0123456789 -" for c in s):
        return False
    odd = False
    total = 0
    for d in reversed(digits):
        total += _LUHN_DOUBLE[d] if odd else d
        odd = not odd
    return total % 10 == 0


def check_iban(s: str) -> bool:
    t = re.sub(r"[\s-]", "", s).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", t) or IBAN_LENGTHS.get(t[:2]) != len(t):
        return False
    rem = 0
    for ch in t[4:] + t[:4]:  # piecewise mod 97, one character at a time
        v = ord(ch) - 55 if ch.isalpha() else ord(ch) - 48
        rem = (rem * (100 if v > 9 else 10) + v) % 97
    return rem == 1


def check_nir(s: str) -> bool:
    t = s.replace(" ", "").replace("-", "").replace(".", "").upper()
    if not re.fullmatch(r"[12]\d{4}(\d{2}|2A|2B)\d{6}\d{2}", t):
        return False
    body = t[:13]
    corsica = {"2A": 1_000_000, "2B": 2_000_000}  # 2A -> 19, 2B -> 18 (offset from "20")
    dept = body[5:7]
    if dept in corsica:
        num = int(body[:5] + "20" + body[7:]) - corsica[dept]
    else:
        num = int(body)
    return (num + int(t[13:])) % 97 == 0


def check_ean13(s: str) -> bool:
    t = s.replace("-", "").replace(" ", "")
    if not re.fullmatch(r"\d{13}", t):
        return False
    return sum(int(c) * (3 if i % 2 else 1) for i, c in enumerate(t)) % 10 == 0


def check_fr_vat(s: str) -> bool:
    t = s.replace(" ", "")
    m = re.fullmatch(r"FR(\d{2})(\d{9})", t)
    return bool(m) and int(m.group(1)) == (12 + 3 * (int(m.group(2)) % 97)) % 97


# --------------------------------------------------------------------------------------------------
# Generator
# --------------------------------------------------------------------------------------------------
def ascii_fold(s: str) -> str:
    s = s.replace("ß", "ss").replace("Æ", "AE").replace("æ", "ae").replace("Œ", "OE").replace("œ", "oe")
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


class Gen:
    def __init__(self, seed: int) -> None:
        self.r = random.Random(seed)

    # -- primitives -------------------------------------------------------------------------------
    def digits(self, n: int) -> str:
        return "".join(self.r.choice("0123456789") for _ in range(n))

    def chars(self, alphabet: str, n: int) -> str:
        return "".join(self.r.choice(alphabet) for _ in range(n))

    def rbytes(self, n: int) -> bytes:
        return bytes(self.r.getrandbits(8) for _ in range(n))

    def pick(self, seq):
        return self.r.choice(seq)

    def chance(self, p: float) -> bool:
        return self.r.random() < p

    # -- people -----------------------------------------------------------------------------------
    def first(self, lang: str | None = None) -> str:
        if lang is None:
            if self.chance(0.12):
                return self.pick(COMPOUND_FIRST)
            lang = self.pick(tuple(FIRST))
        return self.pick(FIRST[lang])

    def last(self, lang: str | None = None) -> str:
        if lang is None:
            if self.chance(0.15):
                return self.pick(PARTICLE_LAST)
            lang = self.pick(tuple(LAST))
        name = self.pick(LAST[lang])
        if lang == "es" and self.chance(0.5):
            name += " " + self.pick(ES_SECOND_LAST)
        return name

    def person(self, profile: str) -> str:
        f, ln = self.first(), self.last()
        if profile == "full":
            return f"{f} {ln}"
        if profile == "first":
            return f
        if profile == "last":
            return ln
        if profile == "last_first":
            return f"{ln.upper()}, {f}" if self.chance(0.5) else f"{ln.upper()} {f}"
        if profile == "title":
            return f"{self.pick(TITLES)} {f} {ln}"
        if profile == "nfd":
            return unicodedata.normalize("NFD", f"{f} {ln}")
        if profile == "upper":
            return f"{f} {ln}".upper()
        if profile == "initial":
            return f"{f[0]}. {ln}"
        raise ValueError(profile)

    # -- e-mail -----------------------------------------------------------------------------------
    def email(self, profile: str) -> str:
        f = ascii_fold(self.first()).lower().replace(" ", "").replace("'", "")
        ln = ascii_fold(self.last()).lower().replace(" ", "").replace("'", "")
        dom = self.pick(EMAIL_DOMAINS)
        local = self.pick((f"{f}.{ln}", f"{f[0]}{ln}", f"{f}_{ln}", f"{f}{ln}{self.r.randint(1, 99)}",
                           f"{ln}.{f}", f"{f}-{ln}"))
        if profile == "plain":
            return f"{local}@{dom}"
        if profile == "subaddress":
            return f"{local}+{self.pick(('news', 'shop', 'promo2024', 'billing', 'x', 'spam'))}@{dom}"
        if profile == "upper":
            return f"{local}@{dom}".upper()
        if profile == "mixedcase":
            return f"{f.capitalize()}.{ln.capitalize()}@{dom.capitalize()}"
        if profile == "idn":
            idn = self.pick(IDN_DOMAINS)
            roll = self.r.random()
            if roll < 0.35:  # EAI: non-ASCII local part
                local = unicodedata.normalize("NFC", f"{self.first('fr').lower()}.{ln}")
                return f"{local}@{idn}"
            if roll < 0.7:
                return f"{local}@{idn}"
            return f"{local}@{idn.encode('idna').decode('ascii')}"
        if profile == "mixed":
            return self.email(self.pick(("plain", "plain", "subaddress", "upper", "mixedcase", "idn")))
        raise ValueError(profile)

    # -- phone ------------------------------------------------------------------------------------
    def fr_national(self) -> str:
        return self.pick(FR_FICTION) + self.digits(4)

    def phone_fr(self, fmt: str) -> str:
        n = self.fr_national()
        pairs = [n[i:i + 2] for i in range(0, 10, 2)]
        intl = n[1:]
        if fmt == "spaces":
            return " ".join(pairs)
        if fmt == "compact":
            return n
        if fmt == "dots":
            return ".".join(pairs)
        if fmt == "dashes":
            return "-".join(pairs)
        if fmt == "e164":
            return "+33" + intl
        if fmt == "intl_spaces":
            return "+33 " + intl[0] + " " + " ".join(intl[i:i + 2] for i in range(1, 9, 2))
        if fmt == "intl_paren0":
            return "+33 (0)" + intl[0] + " " + " ".join(intl[i:i + 2] for i in range(1, 9, 2))
        if fmt == "00":
            return "0033 " + intl[0] + " " + " ".join(intl[i:i + 2] for i in range(1, 9, 2))
        if fmt == "00compact":
            return "0033" + intl
        raise ValueError(fmt)

    def phone_intl(self, country: str) -> str:
        d = self.digits
        if country == "GB":
            return self.pick((f"+44 7700 900{d(3)}", f"07700 900{d(3)}", f"+44 20 7946 0{d(3)}",
                              f"020 7946 0{d(3)}", f"+44 (0)113 496 0{d(3)}"))
        if country == "US":
            area = self.pick(("202", "312", "415", "617", "503"))
            return self.pick((f"+1 {area}-555-01{d(2)}", f"({area}) 555-01{d(2)}", f"{area}.555.01{d(2)}",
                              f"+1 ({area}) 555 01{d(2)}", f"1-{area}-555-01{d(2)}"))
        if country == "AU":
            n = self.pick(AU_FICTION_MOBILE)
            return self.pick((f"+61 {n[1:4]} {n[4:7]} {n[7:]}", f"{n[:4]} {n[4:7]} {n[7:]}", "+61" + n[1:]))
        if country == "DE":
            return self.pick((f"+49 30 {d(4)} {d(4)}", f"+49 (0)171 {d(7)}", f"0151 {d(8)}",
                              f"+49 89 {d(3)}-{d(4)}"))
        if country == "ES":
            return self.pick((f"+34 6{d(2)} {d(2)} {d(2)} {d(2)}", f"6{d(2)} {d(3)} {d(3)}",
                              f"+34 91 {d(3)} {d(2)} {d(2)}"))
        if country == "IT":
            return self.pick((f"+39 3{d(2)} {d(3)} {d(4)}", f"+39 06 {d(4)} {d(4)}", f"3{d(2)} {d(7)}"))
        if country == "BE":
            return self.pick((f"+32 4{d(2)} {d(2)} {d(2)} {d(2)}", f"04{d(2)}/{d(2)}.{d(2)}.{d(2)}"))
        if country == "CH":
            return self.pick((f"+41 7{self.pick('6789')} {d(3)} {d(2)} {d(2)}", f"07{self.pick('6789')} {d(3)} {d(2)} {d(2)}"))
        if country == "FR":
            return self.phone_fr(self.pick(("spaces", "e164", "intl_spaces", "intl_paren0", "00")))
        raise ValueError(country)

    def phone(self, profile: str) -> str:
        if profile.startswith("fr_"):
            return self.phone_fr(profile[3:])
        if profile == "frmix":
            return self.phone_fr(self.pick(("spaces", "compact", "dots", "dashes", "e164", "intl_spaces",
                                            "intl_paren0", "00", "00compact")))
        if profile == "intl":
            return self.phone_intl(self.pick(("GB", "US", "AU", "DE", "ES", "IT", "BE", "CH", "FR")))
        if profile in ("GB", "US", "AU", "DE", "ES", "IT", "BE", "CH"):
            return self.phone_intl(profile)
        raise ValueError(profile)

    # -- IBAN -------------------------------------------------------------------------------------
    def bban(self, country: str) -> str:
        if country in ("FR", "MC"):
            bank, branch = self.digits(5), self.digits(5)
            account = self.digits(11)
            key = 97 - (89 * int(bank) + 15 * int(branch) + 3 * int(account)) % 97
            return f"{bank}{branch}{account}{key:02d}"
        out = []
        for kind, n in IBAN_LAYOUTS[country]:
            alphabet = {"n": "0123456789", "a": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                        "c": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"}[kind]
            out.append(self.chars(alphabet, n))
        return "".join(out)

    def iban(self, country: str, fmt: str) -> str:
        bban = self.bban(country)
        raw = country + mod97_check(country, bban) + bban
        if fmt == "print":
            return " ".join(raw[i:i + 4] for i in range(0, len(raw), 4))
        if fmt == "compact":
            return raw
        if fmt == "lower":
            return raw.lower()
        if fmt == "lower_print":
            return " ".join(raw[i:i + 4] for i in range(0, len(raw), 4)).lower()
        if fmt == "dashes":
            return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))
        if fmt == "odd":
            if country in ("FR", "MC"):  # RIB-style grouping: IBAN key, bank, branch, account, key
                return f"{raw[:4]} {raw[4:9]} {raw[9:14]} {raw[14:25]} {raw[25:]}"
            step = self.pick((3, 5, 6))
            return raw[:4] + " " + " ".join(raw[i:i + step] for i in range(4, len(raw), step))
        raise ValueError(fmt)

    # -- cards ------------------------------------------------------------------------------------
    CARD_BRANDS = ("visa", "mastercard", "mastercard2", "amex", "discover", "jcb", "diners",
                   "unionpay", "maestro")

    def card_raw(self, brand: str) -> str:
        if brand == "visa":
            prefix, length = "4", 16
        elif brand == "mastercard":
            prefix, length = str(self.r.randint(51, 55)), 16
        elif brand == "mastercard2":
            prefix, length = str(self.r.randint(2221, 2720)), 16
        elif brand == "amex":
            prefix, length = self.pick(("34", "37")), 15
        elif brand == "discover":
            prefix, length = self.pick(("6011", "65", str(self.r.randint(644, 649)))), 16
        elif brand == "jcb":
            prefix, length = str(self.r.randint(3528, 3589)), 16
        elif brand == "diners":
            prefix, length = self.pick(("36", "38", str(self.r.randint(300, 305)))), 14
        elif brand == "unionpay":
            prefix, length = "62" + self.digits(2), self.pick((16, 19))
        elif brand == "maestro":
            prefix, length = self.pick(("6759", "5018", "5020", "6304")), self.pick((16, 19))
        else:
            raise ValueError(brand)
        partial = prefix + self.digits(length - len(prefix) - 1)
        return partial + luhn_digit(partial)

    @staticmethod
    def card_format(raw: str, sep: str) -> str:
        if sep == "":
            return raw
        if len(raw) == 15:
            groups = (raw[:4], raw[4:10], raw[10:])
        elif len(raw) == 14:
            groups = (raw[:4], raw[4:10], raw[10:])
        else:
            groups = tuple(raw[i:i + 4] for i in range(0, len(raw), 4))
        return sep.join(groups)

    def card(self, brand: str, sep: str) -> str:
        if brand == "mixed":
            brand = self.pick(self.CARD_BRANDS)
        if sep == "mixed":
            sep = self.pick(("", " ", "-"))
        return self.card_format(self.card_raw(brand), sep)

    # -- NIR --------------------------------------------------------------------------------------
    def nir_raw(self, corsica: bool = False, dom: bool = False, foreign: bool = False) -> str:
        sex = self.pick("12")
        yy = f"{self.r.randint(0, 99):02d}"
        mm = f"{self.r.randint(1, 12):02d}"
        if corsica:
            place = self.pick(("2A", "2B")) + self.digits(3)
        elif dom:
            place = str(self.r.randint(971, 976)) + self.digits(2)
        elif foreign:
            place = "99" + str(self.r.randint(100, 499))
        else:
            dept = self.r.randint(1, 95)
            while dept == 20:
                dept = self.r.randint(1, 95)
            place = f"{dept:02d}" + f"{self.r.randint(1, 990):03d}"
        order = f"{self.r.randint(1, 999):03d}"
        first13 = sex + yy + mm + place + order
        return first13 + nir_key_of(first13)

    def nir(self, profile: str) -> str:
        kind = self.r.random()
        if profile == "corsica":
            raw = self.nir_raw(corsica=True)
        else:
            raw = self.nir_raw(corsica=kind < 0.12, dom=0.12 <= kind < 0.2, foreign=0.2 <= kind < 0.25)
        fmt = profile if profile in ("spaced", "compact", "keydash", "keyspace") else self.pick(
            ("spaced", "compact", "keyspace"))
        if fmt == "compact":
            return raw
        if fmt == "keydash":
            return raw[:13] + "-" + raw[13:]
        if fmt == "keyspace":
            return raw[:13] + " " + raw[13:]
        return " ".join((raw[0], raw[1:3], raw[3:5], raw[5:7], raw[7:10], raw[10:13], raw[13:]))

    # -- dates ------------------------------------------------------------------------------------
    def rand_date(self, y0: int, y1: int) -> dt.date:
        start = dt.date(y0, 1, 1).toordinal()
        end = dt.date(y1, 12, 31).toordinal()
        return dt.date.fromordinal(self.r.randint(start, end))

    def fmt_date(self, d: dt.date, fmt: str) -> str:
        if fmt == "iso":
            return d.isoformat()
        if fmt == "fr":
            return d.strftime("%d/%m/%Y")
        if fmt == "fr_dash":
            return d.strftime("%d-%m-%Y")
        if fmt == "de":
            return d.strftime("%d.%m.%Y")
        if fmt == "us":
            return d.strftime("%m/%d/%Y")
        if fmt == "compact":
            return d.strftime("%Y%m%d")
        if fmt == "iso_midnight":
            return d.isoformat() + "T00:00:00"
        if fmt == "long_fr":
            day = "1er" if d.day == 1 and self.chance(0.5) else str(d.day)
            return f"{day} {MONTHS['fr'][d.month - 1]} {d.year}"
        if fmt == "long_en":
            return self.pick((f"{d.day} {MONTHS['en'][d.month - 1]} {d.year}",
                              f"{MONTHS['en'][d.month - 1]} {d.day}, {d.year}"))
        if fmt == "long_de":
            return f"{d.day}. {MONTHS['de'][d.month - 1]} {d.year}"
        if fmt == "long_es":
            return f"{d.day} de {MONTHS['es'][d.month - 1]} de {d.year}"
        if fmt == "long_it":
            return f"{d.day} {MONTHS['it'][d.month - 1]} {d.year}"
        if fmt == "mixed":
            return self.fmt_date(d, self.pick(("iso", "fr", "de", "long_fr", "long_en")))
        raise ValueError(fmt)

    def birth_date(self, fmt: str) -> str:
        return self.fmt_date(self.rand_date(1938, 2007), fmt)

    # -- addresses --------------------------------------------------------------------------------
    def address(self, profile: str) -> str:
        n = self.r.randint(1, 180)
        if profile == "fr":
            cp, city = self.pick(FR_CITIES)
            num = f"{n}{self.pick(('', '', '', ' bis', ' ter'))}"
            extra = self.pick(("", "", "", "Bât. B, ", "Appt 12, ", "Résidence Les Pins, "))
            return f"{extra}{num} {self.pick(FR_STREETS)}, {cp} {city}"
        if profile == "fr_street":
            return f"{n}{self.pick(('', '', ' bis'))} {self.pick(FR_STREETS)}"
        if profile == "fr_multiline":
            cp, city = self.pick(FR_CITIES)
            return f"{n} {self.pick(FR_STREETS)}\n{cp} {city.upper()}\nFRANCE"
        if profile == "de":
            cp, city = self.pick(DE_CITIES)
            return f"{self.pick(DE_STREETS)} {n}{self.pick(('', '', 'a'))}, {cp} {city}"
        if profile == "es":
            cp, city = self.pick(ES_CITIES)
            return f"{self.pick(ES_STREETS)}, {n}, {self.r.randint(1, 9)}.º {self.pick('ABCD')}, {cp} {city}"
        if profile == "it":
            cp, city, prov = self.pick(IT_CITIES)
            return f"{self.pick(IT_STREETS)} {n}, {cp} {city} {prov}"
        if profile == "uk":
            pc, city = self.pick(UK_CITIES)
            return f"{n}{self.pick(('', '', 'B'))} {self.pick(UK_STREETS)}, {city} {pc}"
        if profile == "us":
            city, st, z = self.pick(US_CITIES)
            apt = self.pick(("", "", f", Apt {self.r.randint(1, 40)}"))
            return f"{n * 10 + self.r.randint(0, 9)} {self.pick(US_STREETS)}{apt}, {city}, {st} {z}"
        if profile == "nl":
            pc, city = self.pick(NL_CITIES)
            return f"{self.pick(NL_STREETS)} {n}, {pc} {city}"
        if profile == "street_intl":
            return self.pick((f"{self.pick(DE_STREETS)} {n}", f"{self.pick(IT_STREETS)} {n}",
                              f"{self.pick(ES_STREETS)} {n}", f"{n} {self.pick(UK_STREETS)}",
                              f"{n} {self.pick(FR_STREETS)}"))
        if profile == "mixed":
            return self.address(self.pick(("fr", "de", "es", "it", "uk", "us", "nl")))
        raise ValueError(profile)

    # -- AWS --------------------------------------------------------------------------------------
    def aws_id(self) -> str:
        return self.pick(("AKIA", "AKIA", "AKIA", "ASIA")) + self.chars(AWS_ID_CHARS, 9) + "EXAMPLE"

    def aws_secret(self) -> str:
        return self.chars(B64, 30) + "EXAMPLEKEY"

    def aws(self, profile: str) -> str:
        if profile == "id":
            return self.aws_id()
        if profile == "secret":
            return self.aws_secret()
        if profile == "pair":
            return f"{self.aws_id()}:{self.aws_secret()}"
        if profile == "mixed":
            return self.aws_id() if self.chance(0.5) else self.aws_secret()
        raise ValueError(profile)

    # -- password hashes --------------------------------------------------------------------------
    def b64nopad(self, n: int) -> str:
        return base64.b64encode(self.rbytes(n)).decode().rstrip("=")

    def pwhash(self, scheme: str) -> str:
        if scheme == "bcrypt":
            return f"${self.pick(('2a', '2b', '2y'))}${self.pick(('10', '11', '12', '13'))}$" + self.chars(BCRYPT64, 53)
        if scheme == "argon2id":
            params = self.pick(("m=65536,t=3,p=4", "m=19456,t=2,p=1", "m=47104,t=1,p=1"))
            return f"$argon2id$v=19${params}${self.b64nopad(16)}${self.b64nopad(32)}"
        if scheme == "scrypt":
            if self.chance(0.5):
                return f"$scrypt$ln=16,r=8,p=1${self.b64nopad(16)}${self.b64nopad(32)}"
            return f"scrypt${self.chars(ALNUM, 22)}$16384$8$1${base64.b64encode(self.rbytes(64)).decode()}"
        if scheme == "pbkdf2":
            iters = self.pick(("600000", "720000", "870000", "260000"))
            return f"pbkdf2_sha256${iters}${self.chars(ALNUM, 22)}${base64.b64encode(self.rbytes(32)).decode()}"
        if scheme == "sha512crypt":
            rounds = self.pick(("", "", "rounds=656000$", "rounds=5000$"))
            return f"$6${rounds}{self.chars(CRYPT64, 16)}${self.chars(CRYPT64, 86)}"
        if scheme == "ssha":
            return "{SSHA}" + base64.b64encode(self.rbytes(20) + self.rbytes(self.pick((4, 8)))).decode()
        if scheme == "md5crypt":
            return f"$1${self.chars(CRYPT64, 8)}${self.chars(CRYPT64, 22)}"
        if scheme == "sha256crypt":
            return f"$5${self.chars(CRYPT64, 16)}${self.chars(CRYPT64, 43)}"
        if scheme == "yescrypt":
            return f"$y$j9T${self.chars(CRYPT64, 22)}${self.chars(CRYPT64, 43)}"
        if scheme == "migration":
            return self.pwhash(self.pick(("bcrypt", "pbkdf2", "argon2id", "sha512crypt", "md5crypt")))
        raise ValueError(scheme)

    # -- negatives --------------------------------------------------------------------------------
    def siren(self) -> str:
        p = self.pick("3456789") + self.digits(7)
        return p + luhn_digit(p)

    def siret(self) -> str:
        p = self.siren() + self.digits(4)
        return p + luhn_digit(p)

    def imei(self) -> str:
        p = self.pick(("35", "86", "01", "99")) + self.digits(12)
        return p + luhn_digit(p)

    def not_luhn(self, n: int) -> str:
        while True:
            v = self.pick("123456789") + self.digits(n - 1)
            if not check_luhn(v):
                return v

    def ean13(self, prefix: str) -> str:
        p = prefix + self.digits(12 - len(prefix))
        s = sum(int(c) * (3 if i % 2 else 1) for i, c in enumerate(p))
        return p + str((10 - s % 10) % 10)

    def isbn(self) -> str:
        if self.chance(0.25):  # ISBN-10 with mod-11 check
            p = self.digits(9)
            c = (11 - sum((10 - i) * int(x) for i, x in enumerate(p)) % 11) % 11
            return f"{p[0]}-{p[1:4]}-{p[4:9]}-{'X' if c == 10 else c}"
        raw = self.ean13(self.pick(("978", "979")))
        return raw if self.chance(0.3) else f"{raw[:3]}-{raw[3]}-{raw[4:7]}-{raw[7:12]}-{raw[12]}"

    def fr_vat(self) -> str:
        siren = self.siren()
        key = (12 + 3 * (int(siren) % 97)) % 97
        return f"FR{key:02d}{siren}" if self.chance(0.5) else f"FR {key:02d} {siren}"

    def nir_like_order(self) -> str:
        while True:  # 15 digits starting with 1 or 2 that FAIL the NIR key
            v = self.pick("12") + self.digits(14)
            if not check_nir(v):
                return v

    def timestamp(self) -> str:
        t = dt.datetime(2019, 1, 1) + dt.timedelta(seconds=self.r.randint(0, 6 * 365 * 86400))
        return self.pick((t.strftime("%Y-%m-%dT%H:%M:%SZ"), t.strftime("%Y-%m-%d %H:%M:%S"),
                          t.strftime("%Y-%m-%dT%H:%M:%S.") + self.digits(3) + "+00:00"))

    def epoch(self) -> str:
        s = self.r.randint(1_546_300_800, 1_735_689_600)
        return str(s) if self.chance(0.6) else str(s * 1000 + self.r.randint(0, 999))

    def uuid4(self) -> str:
        return str(uuid.UUID(bytes=self.rbytes(16), version=4))

    def hexs(self, n: int) -> str:
        return self.chars("0123456789abcdef", n)

    def price(self) -> str:
        v = self.r.randint(99, 499_999)
        e, c = divmod(v, 100)
        return self.pick((f"{e}.{c:02d}", f"{e},{c:02d} €", f"${e:,}.{c:02d}", f"EUR {e}.{c:02d}",
                          f"{e:,}.{c:02d}".replace(",", " ") + " EUR"))

    def base64_token(self) -> str:
        # Never exactly 40 characters of the standard alphabet (that is the AWS secret key shape).
        n = self.pick((16, 24, 33, 48, 64))
        s = base64.b64encode(self.rbytes(n)).decode()
        if self.chance(0.4):
            s = base64.urlsafe_b64encode(self.rbytes(n)).decode().rstrip("=")
        assert len(s) != 40
        return s

    def version(self) -> str:
        return self.pick((f"{self.r.randint(0, 12)}.{self.r.randint(0, 30)}.{self.r.randint(0, 99)}",
                          f"v{self.r.randint(1, 5)}.{self.r.randint(0, 20)}.{self.r.randint(0, 9)}-rc.{self.r.randint(1, 4)}",
                          f"{self.r.randint(2019, 2025)}.{self.r.randint(1, 12):02d}.{self.r.randint(0, 9)}",
                          f"10.0.{self.r.randint(10000, 22631)}.{self.r.randint(100, 4000)}",
                          f"{self.r.randint(1, 9)}.{self.r.randint(0, 9)}"))


# --------------------------------------------------------------------------------------------------
# Column naming
# --------------------------------------------------------------------------------------------------
def render(tokens: tuple[str, ...], style: str) -> str:
    if style == "snake":
        return "_".join(tokens)
    if style == "camel":
        return tokens[0] + "".join(t.capitalize() for t in tokens[1:])
    if style == "upper":
        return "_".join(tokens).upper()
    if style == "pascal":
        return "".join(t.capitalize() for t in tokens)
    if style == "flat":
        return "".join(tokens)
    raise ValueError(style)


STYLES = ("snake", "snake", "camel", "upper", "pascal", "flat")
OPAQUE = ("c1", "c2", "c3", "c4", "c5", "c7", "c9", "c11", "c12", "col_3", "col_8", "col_17", "col_21",
          "col_42", "attr_x", "attr_y", "attr_7", "data", "data2", "field1", "field6", "f_09", "f12",
          "x1", "x3", "val", "val2", "value", "misc", "info", "extra", "raw", "blob", "tmp_1", "tmp_col",
          "column_a", "column_b", "COL5", "COL_11", "V3", "a1", "b2", "z", "k", "prop_4", "ext_1",
          "custom_1", "custom_field_3", "cf_12", "udf_2", "user_defined_5", "legacy_col")

POS_NAMES = {
    "pii.email": (
        ("email",), ("e", "mail"), ("mail",), ("courriel",), ("adresse", "mail"), ("adresse", "email"),
        ("adresse", "electronique"), ("mel",), ("email", "address"), ("contact", "email"),
        ("user", "email"), ("billing", "email"), ("work", "email"), ("personal", "email"),
        ("e", "mail", "adresse"), ("mailadresse",), ("email", "adresse"), ("kontakt", "email"),
        ("correo",), ("correo", "electronico"), ("email", "contacto"), ("posta", "elettronica"),
        ("indirizzo", "email"), ("email", "utente"), ("recipient",), ("reply", "to"), ("notify", "email"),
        ("owner", "email"), ("cc",), ("email", "pro"), ("mail", "perso"), ("courriel", "client"),
        ("destinataire",), ("email", "fatturazione"), ("empfaenger",), ("adresse", "électronique"),
    ),
    "pii.phone": (
        ("phone",), ("telephone",), ("tel",), ("mobile",), ("portable",), ("numero", "telephone"),
        ("num", "tel"), ("phone", "number"), ("cell",), ("cell", "phone"), ("mobile", "phone"), ("fax",),
        ("telefon",), ("telefonnummer",), ("handy",), ("handynummer",), ("rufnummer",), ("telefono",),
        ("movil",), ("numero", "telefono"), ("telefono", "cellulare"), ("cellulare",),
        ("recapito", "telefonico"), ("contact", "phone"), ("home", "phone"), ("work", "phone"),
        ("tel", "fixe"), ("tel", "mobile"), ("gsm",), ("msisdn",), ("phone", "e164"),
        ("emergency", "phone"), ("sms", "number"), ("whatsapp",), ("téléphone",), ("tel", "domicile"),
    ),
    "pii.iban": (
        ("iban",), ("iban", "number"), ("bank", "account"), ("account", "iban"), ("compte", "bancaire"),
        ("rib", "iban"), ("iban", "client"), ("coordonnees", "bancaires"), ("bankverbindung",),
        ("kontonummer", "iban"), ("iban", "nummer"), ("cuenta", "bancaria"), ("numero", "cuenta"),
        ("iban", "cuenta"), ("conto", "corrente"), ("iban", "conto"), ("coordinate", "bancarie"),
        ("payout", "account"), ("sepa", "account"), ("debtor", "iban"), ("creditor", "iban"),
        ("refund", "iban"), ("salary", "account"), ("bank", "details"), ("iban", "fournisseur"),
        ("compte", "virement"), ("mandat", "sepa", "iban"), ("empfaenger", "iban"), ("beneficiary", "account"),
    ),
    "pii.card_number": (
        ("card", "number"), ("cc", "number"), ("pan",), ("credit", "card"), ("numero", "carte"),
        ("carte", "bancaire"), ("num", "cb"), ("cb",), ("kartennummer",), ("kreditkarte",),
        ("numero", "tarjeta"), ("tarjeta", "credito"), ("numero", "carta"), ("carta", "di", "credito"),
        ("payment", "card"), ("card", "pan"), ("primary", "account", "number"), ("cc", "num"),
        ("card", "no"), ("debit", "card"), ("carte", "paiement"), ("stored", "card"), ("pay", "instrument"),
        ("creditcard",), ("kk", "nummer"), ("tarjeta",), ("carta",), ("cardnumber",), ("card",),
    ),
    "pii.nir": (
        ("nir",), ("numero", "securite", "sociale"), ("num", "secu"), ("secu",), ("insee",),
        ("numero", "insee"), ("nss",), ("social", "security", "number"), ("ssn",), ("ss", "number"),
        ("matricule", "secu"), ("n", "ss"), ("securite", "sociale"), ("sozialversicherungsnummer",),
        ("numero", "seguridad", "social"), ("numero", "previdenza"), ("assure", "nir"), ("nir", "assure"),
        ("patient", "nir"), ("ins",), ("matricule", "ins"), ("carte", "vitale"), ("num", "vitale"),
        ("no", "secu"), ("nir", "beneficiaire"), ("numero", "ss"), ("n", "insee"), ("sv", "nummer"),
    ),
    "pii.birth_date": (
        ("birth", "date"), ("date", "of", "birth"), ("dob",), ("birthday",), ("date", "naissance"),
        ("date", "de", "naissance"), ("naissance",), ("ne", "le"), ("geburtsdatum",), ("geburtstag",),
        ("geb", "datum"), ("fecha", "nacimiento"), ("fecha", "de", "nacimiento"), ("nacimiento",),
        ("data", "nascita"), ("data", "di", "nascita"), ("nato", "il"), ("birthdate",), ("born", "on"),
        ("dt", "naiss"), ("d", "naissance"), ("bday",), ("patient", "dob"), ("date", "naiss", "assure"),
        ("employee", "birth", "date"), ("ddn",), ("fec", "nac"), ("date", "anniversaire"),
    ),
    "pii.person_name": (
        ("name",), ("full", "name"), ("first", "name"), ("last", "name"), ("surname",), ("given", "name"),
        ("family", "name"), ("nom",), ("prenom",), ("nom", "complet"), ("nom", "famille"), ("nom", "usage"),
        ("vorname",), ("nachname",), ("familienname",), ("nombre",), ("apellidos",), ("nombre", "completo"),
        ("primer", "apellido"), ("nome",), ("cognome",), ("nome", "completo"), ("titular",),
        ("cardholder",), ("holder", "name"), ("contact", "name"), ("customer", "name"), ("patient", "name"),
        ("employee", "name"), ("beneficiary",), ("signataire",), ("titulaire",), ("manager",),
        ("interlocuteur",), ("prénom",), ("nom", "de", "naissance"), ("ansprechpartner",),
    ),
    "pii.postal_address": (
        ("address",), ("street",), ("street", "address"), ("address", "line1"), ("adresse",),
        ("adresse", "postale"), ("rue",), ("voie",), ("adresse", "livraison"), ("adresse", "facturation"),
        ("anschrift",), ("strasse",), ("wohnanschrift",), ("direccion",), ("domicilio",), ("calle",),
        ("indirizzo",), ("indirizzo", "residenza"), ("recapito",), ("shipping", "address"),
        ("billing", "address"), ("home", "address"), ("mailing", "address"), ("postal", "address"),
        ("addr",), ("addr1",), ("lieferadresse",), ("direccion", "envio"), ("domicile",), ("straße",),
    ),
    "secret.aws_key": (
        ("aws", "access", "key", "id"), ("access", "key", "id"), ("aws", "secret", "access", "key"),
        ("secret", "access", "key"), ("aws", "key"), ("aws", "secret"), ("iam", "key"), ("s3", "access", "key"),
        ("s3", "secret"), ("aws", "credentials"), ("cle", "acces", "aws"), ("cle", "secrete", "aws"),
        ("zugangsschluessel",), ("clave", "acceso", "aws"), ("chiave", "accesso", "aws"), ("access", "key"),
        ("secret", "key"), ("backup", "key", "id"), ("backup", "secret"), ("ci", "aws", "key"),
        ("aws", "id"), ("key", "id"), ("iam", "secret"), ("uploader", "key"), ("bucket", "creds"),
        ("aws", "access", "key"), ("aws", "sak"), ("akid",),
    ),
    "secret.password_hash": (
        ("password",), ("password", "hash"), ("passwd",), ("pwd",), ("mot", "de", "passe"), ("mdp",),
        ("hash", "mdp"), ("passwort",), ("kennwort",), ("passwort", "hash"), ("contrasena",), ("clave",),
        ("password", "digest"), ("pass", "hash"), ("hashed", "password"), ("user", "password"),
        ("encrypted", "password"), ("crypted", "password"), ("pw", "hash"), ("login", "hash"),
        ("credential",), ("secret", "hash"), ("hash", "password"), ("userpassword",), ("shadow",),
        ("auth", "hash"), ("password", "encoded"), ("mdp", "hache"), ("parola", "chiave"), ("pass",),
    ),
}

# Positive columns under innocent names: only the values tell the type.
INNOCENT_NAMES = {
    "pii.email": (("login",), ("username",), ("contact",), ("ident",), ("user", "ref"), ("sender",)),
    "pii.phone": (("contact",), ("numero",), ("callback",), ("reach", "at"), ("line",), ("tel", "or", "fax")),
    "pii.iban": (("ref",), ("compte",), ("account",), ("payment", "info"), ("destination",), ("konto",)),
    "pii.card_number": (("ref",), ("token",), ("payment", "ref"), ("instrument",), ("numero",), ("pm",)),
    "pii.nir": (("matricule",), ("identifiant",), ("ref", "patient"), ("numero",), ("code",), ("id", "admin")),
    "pii.birth_date": (),  # dates under innocent/opaque names are genuinely ambiguous: see AMBIGUOUS
    "pii.person_name": (("label",), ("who",), ("owner",), ("created", "by"), ("contact",), ("signed", "by")),
    "pii.postal_address": (("location",), ("destination",), ("where",), ("line1",), ("lieu",), ("ship", "to")),
    "secret.aws_key": (("token",), ("key",), ("cred",), ("config", "value"), ("param",), ("secret",)),
    "secret.password_hash": (("digest",), ("hash",), ("secret",), ("token",), ("h",), ("verifier",)),
}

VALUE_PROFILES = {
    "pii.email": ("plain", "plain", "subaddress", "upper", "mixedcase", "idn", "mixed", "mixed"),
    "pii.phone": ("fr_spaces", "fr_compact", "fr_dots", "fr_dashes", "fr_e164", "fr_intl_spaces",
                  "fr_intl_paren0", "fr_00", "fr_00compact", "frmix", "frmix", "intl", "intl", "GB", "US",
                  "AU", "DE", "ES", "IT", "BE", "CH"),
    "pii.iban": ("FR:print", "FR:compact", "FR:odd", "FR:lower", "DE:print", "DE:compact", "DE:dashes",
                 "ES:print", "ES:lower_print", "IT:print", "IT:compact", "BE:print", "NL:compact",
                 "GB:print", "GB:odd", "CH:print", "LU:compact", "PT:odd", "AT:print", "MC:print",
                 "mixed:print", "mixed:compact", "mixed:lower", "mixed:odd", "mixed:mixed"),
    "pii.card_number": ("visa: ", "visa:", "visa:-", "mastercard: ", "mastercard2:", "amex: ", "amex:",
                        "discover: ", "jcb:-", "diners: ", "unionpay:", "maestro: ", "mixed: ", "mixed:",
                        "mixed:-", "mixed:mixed", "mixed:mixed"),
    "pii.nir": ("spaced", "compact", "keydash", "keyspace", "mixed", "corsica", "mixed"),
    "pii.birth_date": ("iso", "iso", "fr", "fr", "fr_dash", "de", "us", "compact", "iso_midnight",
                       "long_fr", "long_en", "long_de", "long_es", "long_it", "mixed"),
    "pii.person_name": ("full", "full", "full", "first", "last", "last_first", "title", "nfd", "upper",
                        "initial"),
    "pii.postal_address": ("fr", "fr", "fr_street", "fr_multiline", "de", "es", "it", "uk", "us", "nl",
                           "street_intl", "mixed", "mixed"),
    "secret.aws_key": ("id", "id", "secret", "secret", "pair", "mixed"),
    "secret.password_hash": ("bcrypt", "bcrypt", "argon2id", "argon2id", "scrypt", "pbkdf2", "pbkdf2",
                             "sha512crypt", "ssha", "md5crypt", "sha256crypt", "yescrypt", "migration"),
}

# Name-driven value profiles (so that a "first_name" column holds first names, etc.).
PERSON_NAME_PROFILE = {
    "first": "first", "prenom": "first", "prénom": "first", "given": "first", "vorname": "first",
    "nombre": "first", "nome": "first",
    "last": "last", "surname": "last", "family": "last", "nachname": "last", "familienname": "last",
    "apellidos": "last", "primer": "last", "cognome": "last",
}


def value_profile_for(cls: str, tokens: tuple[str, ...], g: Gen) -> str:
    if cls == "pii.person_name":
        if tokens in (("nom",), ("nom", "famille"), ("nom", "usage"), ("nom", "de", "naissance")):
            return g.pick(("last", "last", "upper"))
        if tokens in (("nombre", "completo"), ("nome", "completo"), ("full", "name"), ("nom", "complet"),
                      ("cardholder",), ("holder", "name"), ("customer", "name"), ("patient", "name"),
                      ("employee", "name"), ("contact", "name")):
            return g.pick(("full", "full", "nfd", "title", "last_first", "upper"))
        for t in tokens:
            if t in PERSON_NAME_PROFILE:
                return PERSON_NAME_PROFILE[t]
    if cls == "pii.postal_address" and tokens in (("street",), ("rue",), ("voie",), ("strasse",),
                                                  ("straße",), ("calle",), ("addr1",), ("address", "line1")):
        return g.pick(("fr_street", "street_intl"))
    if cls == "secret.aws_key":
        joined = "_".join(tokens)
        if "secret" in joined or "sak" in joined or "secrete" in joined:
            return "secret"
        if joined.endswith("id") or "akid" in joined:
            return "id"
    return g.pick(VALUE_PROFILES[cls])


def positive_value(g: Gen, cls: str, profile: str) -> str:
    if cls == "pii.email":
        return g.email(profile)
    if cls == "pii.phone":
        return g.phone(profile)
    if cls == "pii.iban":
        country, fmt = profile.split(":")
        if country == "mixed":
            country = g.pick(tuple(IBAN_LENGTHS))
        if fmt == "mixed":
            fmt = g.pick(("print", "compact", "lower", "odd", "dashes"))
        return g.iban(country, fmt)
    if cls == "pii.card_number":
        brand, sep = profile.split(":")
        return g.card(brand, sep)
    if cls == "pii.nir":
        return g.nir(profile)
    if cls == "pii.birth_date":
        return g.birth_date(profile)
    if cls == "pii.person_name":
        return g.person(profile)
    if cls == "pii.postal_address":
        return g.address(profile)
    if cls == "secret.aws_key":
        return g.aws(profile)
    if cls == "secret.password_hash":
        return g.pwhash(profile)
    raise ValueError(cls)


# --------------------------------------------------------------------------------------------------
# Negatives: (type, generator, names, opaque_ok, note)
# --------------------------------------------------------------------------------------------------
PETS = ("Rex", "Luna", "Max", "Bella", "Filou", "Nala", "Simba", "Oscar", "Milo", "Caramel", "Pollux")
CITY_LOOKALIKE = ("Florence", "Nancy", "Charlotte", "Victoria", "Adelaide", "Lourdes", "Valence",
                  "Laval", "Albi", "Orange", "Sydney", "Chester", "Austin", "Jackson", "Eugene",
                  "Hamilton", "Salem", "Lincoln", "Madison", "Beaumont")
COMPANIES = ("Martin & Fils SARL", "Dubois Transports SAS", "Schröder GmbH", "Bianchi S.r.l.",
             "Fernández y Asociados S.L.", "Walker Holdings Ltd", "Garage Morel", "Boulangerie Perrin",
             "Weiß & Partner KG", "Conti Logistica S.p.A.", "Bennett Consulting LLC", "Pharmacie Girard")
PRODUCTS = ("lampe Linnea", "bureau Oskar", "fauteuil Clara", "canapé Victor 3 places", "vase Elsa",
            "chaise Hugo chêne", "Margaux rouge 2019", "Camille tote bag", "Jules sneaker 42",
            "Emma matelas 140x190", "Léon suspension laiton", "Alma plaid laine", "Ines tabouret",
            "Oscar bibliothèque", "Lotta desk lamp", "Greta armchair", "Anton shelf", "Nora rug 160x230",
            "Theo bedside table", "Mila cushion cover")
JOBS = ("Comptable", "Ingénieur logiciel", "Sales manager", "Buchhalter", "Técnico de soporte",
        "Responsabile acquisti", "Chef de projet", "Data analyst", "Assistante de direction")
COUNTRY_CODES = ("FR", "DE", "ES", "IT", "BE", "NL", "GB", "US", "CH", "LU", "PT", "AT", "IE", "PL")
DIAL_CODES = ("+33", "+49", "+34", "+39", "+32", "+31", "+44", "+1", "+41", "+352", "+351", "+43")
REGIONS = ("eu-west-1", "eu-west-3", "eu-central-1", "us-east-1", "us-west-2", "ap-southeast-2")
HASH_ALGOS = ("bcrypt", "argon2id", "scrypt", "pbkdf2_sha256", "sha512_crypt", "ssha")
NEG_PROSE = (
    "Le client préfère être contacté par e-mail plutôt que par téléphone.",
    "Relance envoyée, pas de réponse pour l'instant.",
    "Please update the IBAN field before the next payment run.",
    "Customer asked us to remove the phone number from the account.",
    "Colis livré en point relais, RAS.",
    "Bitte die E-Mail-Adresse im Profil prüfen.",
    "Pedido enviado, pendiente de confirmación del número de tarjeta.",
    "Il cliente chiede di aggiornare l'indirizzo di spedizione.",
    "Password reset requested via the self-service portal.",
    "Ticket escalated to tier 2.",
    "Carte bancaire expirée, nouveau moyen de paiement demandé.",
    "Rappel prévu la semaine prochaine.",
)


def neg_generators():
    """Return {type: (fn(g) -> str, names, opaque_ok, note)}."""
    return {
        "boolean_optin": (lambda g: g.pick(("true", "false")), (
            ("email", "opt", "in"), ("sms", "opt", "in"), ("newsletter",), ("accepte", "cgv"),
            ("phone", "verified"), ("email", "verified"), ("einwilligung", "email"), ("acepta", "publicidad"),
            ("consenso", "marketing"), ("has", "iban")), True, "booleans; the name looks sensitive"),
        "boolean_misc": (lambda g: g.pick(("0", "1", "yes", "no", "oui", "non", "Y", "N")), (
            ("card", "on", "file"), ("nir", "present"), ("address", "validated"), ("is", "active"),
            ("password", "expired"), ("mfa", "enabled")), True, "flags; the name looks sensitive"),
        "country_code": (lambda g: g.pick(COUNTRY_CODES), (
            ("phone", "country"), ("iban", "country"), ("country",), ("pays",), ("land",), ("pais",),
            ("paese",), ("card", "country"), ("address", "country"), ("nationality",)), True,
            "ISO 3166 country codes"),
        "dial_code": (lambda g: g.pick(DIAL_CODES), (
            ("phone", "country", "code"), ("indicatif",), ("dial", "code"), ("prefijo", "telefono"),
            ("vorwahl", "land"), ("prefisso", "internazionale"), ("calling", "code")), False,
            "international dialling prefixes only"),
        "phone_extension": (lambda g: g.digits(g.pick((3, 4))), (
            ("phone", "extension"), ("poste",), ("durchwahl",), ("extension",), ("ext",), ("interno",),
            ("tel", "poste")), False, "3-4 digit internal extensions"),
        "siret": (lambda g: (lambda s: s if g.chance(0.5) else f"{s[:3]} {s[3:6]} {s[6:9]} {s[9:]}")(g.siret()), (
            ("siret",), ("numero", "siret"), ("siret", "etablissement"), ("company", "siret"),
            ("siret", "fournisseur"), ("n", "siret"), ("establishment", "id"), ("siret", "client")), False,
            "SIRET, 14 digits, Luhn-valid"),
        "siren": (lambda g: (lambda s: s if g.chance(0.5) else f"{s[:3]} {s[3:6]} {s[6:]}")(g.siren()), (
            ("siren",), ("numero", "siren"), ("siren", "entreprise"), ("company", "id"),
            ("registre", "commerce"), ("rcs",), ("siren", "fournisseur")), False, "SIREN, 9 digits, Luhn-valid"),
        "imei": (lambda g: (lambda s: g.pick((s, f"{s[:2]}-{s[2:8]}-{s[8:14]}-{s[14]}",
                                              f"{s[:2]} {s[2:8]} {s[8:14]} {s[14]}")))(g.imei()), (
            ("imei",), ("device", "imei"), ("imei", "terminal"), ("geraete", "imei"), ("imei", "movil"),
            ("handset", "id"), ("imei1",), ("imei", "telefono")), False, "IMEI, 15 digits, Luhn-valid"),
        "order_number": (lambda g: g.pick((f"CMD-{g.r.randint(2019, 2025)}-{g.digits(6)}", f"ORD{g.digits(8)}",
                                           f"#{g.digits(6)}", f"PO-{g.digits(5)}", f"FAC{g.digits(10)}")), (
            ("order", "number"), ("numero", "commande"), ("bestellnummer",), ("numero", "pedido"),
            ("numero", "ordine"), ("invoice", "number"), ("po", "ref"), ("ref", "commande")), False,
            "order and invoice references"),
        "tracking": (lambda g: g.pick((f"1Z{g.chars('0123456789ABCDEFGHJKLMNPRSTUVWXYZ', 16)}",
                                       f"{g.chars('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 2)}{g.digits(9)}FR",
                                       g.not_luhn(16), f"JD{g.digits(18)}")), (
            ("tracking", "number"), ("numero", "suivi"), ("sendungsnummer",), ("numero", "seguimiento"),
            ("tracking", "ref"), ("colis", "id"), ("awb",), ("parcel", "id")), False,
            "parcel tracking numbers; 16-digit ones FAIL Luhn"),
        "luhn_fail_16": (lambda g: g.not_luhn(16), (
            ("loyalty", "ref"), ("ticket", "number"), ("barcode", "internal"), ("voucher", "code")), False,
            "16-digit numbers that FAIL Luhn"),
        "nir_like": (lambda g: g.nir_like_order(), (
            ("dossier", "number"), ("numero", "dossier"), ("aktenzeichen",), ("expediente",),
            ("pratica",), ("case", "ref")), False, "15-digit references starting with 1 or 2 that FAIL the NIR key"),
        "uuid": (lambda g: g.uuid4() if g.chance(0.8) else g.uuid4().upper(), (
            ("id",), ("uuid",), ("customer", "uuid"), ("request", "id"), ("correlation", "id"),
            ("session", "id"), ("tenant", "id"), ("external", "id")), True, "random UUIDs"),
        "sha256": (lambda g: g.hexs(64), (
            ("sha256",), ("checksum",), ("file", "hash"), ("content", "digest"), ("integrity",),
            ("empreinte",), ("pruefsumme",), ("blob", "sha")), True, "hex SHA-256 digests of files"),
        "git_sha": (lambda g: g.hexs(40) if g.chance(0.7) else g.hexs(7), (
            ("commit",), ("git", "sha"), ("revision",), ("build", "commit"), ("deployed", "rev"),
            ("source", "version")), True, "git commit SHAs (full or short)"),
        "timestamp": (lambda g: g.timestamp(), (
            ("created", "at"), ("updated", "at"), ("date", "creation"), ("last", "login"),
            ("password", "changed", "at"), ("erstellt", "am"), ("fecha", "alta"), ("data", "modifica"),
            ("email", "sent", "at")), True, "event timestamps with a time of day"),
        "epoch": (lambda g: g.epoch(), (
            ("ts",), ("created", "epoch"), ("last", "seen"), ("event", "time"), ("horodatage",)), False,
            "Unix epoch seconds / milliseconds"),
        "business_date": (lambda g: g.fmt_date(g.rand_date(2018, 2026), g.pick(("iso", "fr", "de"))), (
            ("order", "date"), ("date", "commande"), ("hire", "date"), ("date", "embauche"),
            ("eintrittsdatum",), ("fecha", "factura"), ("data", "consegna"), ("expiry", "date"),
            ("date", "echeance"), ("contract", "start")), False, "business dates, not birth dates"),
        "card_expiry": (lambda g: f"{g.r.randint(1, 12):02d}/{g.r.randint(25, 32)}", (
            ("card", "expiry"), ("exp", "date"), ("date", "expiration", "carte"), ("ablaufdatum",),
            ("caducidad",)), False, "MM/YY expiry dates"),
        "card_last4": (lambda g: g.digits(4), (
            ("card", "last4"), ("last", "four"), ("cb", "4", "derniers"), ("pan", "suffix")), False,
            "last four digits only"),
        "card_brand": (lambda g: g.pick(("VISA", "Mastercard", "AMEX", "CB", "Discover", "JCB")), (
            ("card", "brand"), ("card", "type"), ("reseau", "carte"), ("kartentyp",)), False, "brand names"),
        "price": (lambda g: g.price(), (
            ("price",), ("prix",), ("preis",), ("precio",), ("prezzo",), ("amount",), ("total", "ttc"),
            ("unit", "price")), True, "prices and amounts"),
        "sku": (lambda g: g.pick((f"SKU-{g.chars('ABCDEFGHJKLMNPQRSTUVWXYZ', 3)}-{g.pick(('XS', 'S', 'M', 'L', 'XL'))}-{g.digits(4)}",
                                  f"{g.chars('ABCDEFGHJKLMNPQRSTUVWXYZ', 3)}-{g.digits(5)}-{g.digits(1)}",
                                  f"REF{g.digits(7)}")), (
            ("sku",), ("reference", "produit"), ("artikelnummer",), ("referencia",), ("codice", "articolo"),
            ("product", "code")), True, "product SKUs"),
        "postcode": (lambda g: g.pick((g.pick(FR_CITIES)[0], g.pick(DE_CITIES)[0], g.pick(UK_CITIES)[0],
                                       g.pick(NL_CITIES)[0], g.pick(US_CITIES)[2], g.pick(ES_CITIES)[0])), (
            ("postcode",), ("code", "postal"), ("cp",), ("plz",), ("postleitzahl",), ("codigo", "postal"),
            ("cap",), ("zip",), ("zip", "code")), False, "postcodes alone, not an address"),
        "city": (lambda g: g.pick([c for _, c in FR_CITIES] + [c for _, c in DE_CITIES] +
                                  [c for c, _, _ in US_CITIES] + list(CITY_LOOKALIKE)), (
            ("city",), ("ville",), ("stadt",), ("ciudad",), ("citta",), ("commune",), ("town",),
            ("ort",), ("delivery", "city")), False, "city names alone (some are also first names)"),
        "product_name": (lambda g: g.pick(PRODUCTS), (
            ("product", "name"), ("nom", "produit"), ("produktname",), ("nombre", "producto"),
            ("nome", "prodotto"), ("item", "title"), ("libelle",), ("designation",)), False,
            "product names built on first names"),
        "pet_name": (lambda g: g.pick(PETS), (
            ("pet", "name"), ("nom", "animal"), ("tiername",), ("nombre", "mascota")), False,
            "pet names"),
        "company": (lambda g: g.pick(COMPANIES), (
            ("company", "name"), ("raison", "sociale"), ("firmenname",), ("razon", "social"),
            ("ragione", "sociale"), ("supplier",), ("employer",)), False,
            "legal entity names built on surnames"),
        "job_title": (lambda g: g.pick(JOBS), (
            ("job", "title"), ("poste", "occupe"), ("fonction",), ("berufsbezeichnung",), ("cargo",)), False,
            "job titles"),
        "isbn": (lambda g: g.isbn(), (
            ("isbn",), ("isbn13",), ("ean",), ("book", "id"), ("code", "barre")), False,
            "ISBN-10/13 with valid check digits"),
        "ean": (lambda g: g.ean13(g.pick(("30", "40", "50", "76", "80", "84"))), (
            ("gtin",), ("ean13",), ("barcode",), ("code", "ean")), False, "EAN-13 barcodes"),
        "base64_token": (lambda g: g.base64_token(), (
            ("api", "nonce"), ("csrf",), ("state", "param"), ("etag",), ("cursor",), ("upload", "id"),
            ("payload", "b64"), ("challenge",)), True, "random base64 tokens, NOT AWS keys (length != 40)"),
        "version": (lambda g: g.version(), (
            ("version",), ("app", "version"), ("firmware",), ("os", "build"), ("schema", "version"),
            ("client", "version")), True, "version strings"),
        "ip": (lambda g: g.pick((f"192.0.2.{g.r.randint(1, 254)}", f"198.51.100.{g.r.randint(1, 254)}",
                                 f"203.0.113.{g.r.randint(1, 254)}", f"2001:db8::{g.hexs(4)}")), (
            ("ip",), ("ip", "address"), ("last", "ip"), ("adresse", "ip"), ("client", "ip")), True,
            "documentation IP addresses (RFC 5737 / 3849)"),
        "bic": (lambda g: g.chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 4) + g.pick(COUNTRY_CODES) +
                g.chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 2) + g.pick(("", "XXX")), (
            ("bic",), ("swift",), ("bic", "code"), ("code", "swift"), ("bank", "bic")), False,
            "BIC / SWIFT codes, not account numbers"),
        "vat": (lambda g: g.fr_vat(), (
            ("vat", "number"), ("tva", "intracom"), ("ust", "idnr"), ("nif", "iva"), ("partita", "iva")), False,
            "FR intra-community VAT numbers (valid key)"),
        "aws_region": (lambda g: g.pick(REGIONS), (
            ("aws", "region"), ("region",), ("s3", "region"), ("aws", "zone")), False, "AWS region names"),
        "aws_account": (lambda g: g.digits(12), (
            ("aws", "account", "id"), ("account", "id"), ("aws", "account")), False,
            "12-digit AWS account ids (not credentials)"),
        "aws_arn": (lambda g: f"arn:aws:iam::{g.digits(12)}:role/{g.pick(('deploy', 'reader', 'backup', 'ci'))}", (
            ("role", "arn"), ("aws", "arn"), ("iam", "role")), False, "IAM role ARNs"),
        "hash_algo": (lambda g: g.pick(HASH_ALGOS), (
            ("hash", "algorithm"), ("password", "scheme"), ("algo", "mdp"), ("hash", "type")), False,
            "hash algorithm names only"),
        "email_domain": (lambda g: g.pick(EMAIL_DOMAINS), (
            ("email", "domain"), ("domaine", "mail"), ("mail", "domain")), False, "domains without local part"),
        "package_ref": (lambda g: g.pick((f"lodash@4.17.{g.r.randint(10, 21)}", f"@babel/core@7.{g.r.randint(0, 24)}.0",
                                          f"react@18.{g.r.randint(0, 3)}.{g.r.randint(0, 9)}",
                                          f"git@git.example.test:team/repo{g.r.randint(1, 40)}.git",
                                          f"@types/node@20.{g.r.randint(0, 14)}.{g.r.randint(0, 9)}")), (
            ("dependency",), ("package",), ("repo", "url"), ("module", "ref")), False,
            "package@version and scp-like git remotes; contain '@' but are not e-mails"),
        "geo": (lambda g: f"{g.r.uniform(42.0, 51.0):.5f}, {g.r.uniform(-4.5, 8.0):.5f}", (
            ("coordinates",), ("geo",), ("latlng",), ("coordonnees", "gps")), False,
            "GPS coordinates, not a postal address"),
        "neg_prose": (lambda g: g.pick(NEG_PROSE), (
            ("comment",), ("remarque",), ("bemerkung",), ("observaciones",), ("note", "interne")), False,
            "free text that mentions sensitive types as words only"),
        "percent": (lambda g: f"{g.r.uniform(0, 100):.1f}%", (("discount",), ("taux",), ("ratio",)), True,
                    "percentages"),
    }


# --------------------------------------------------------------------------------------------------
# Mixed free text
# --------------------------------------------------------------------------------------------------
PROSE_EMAIL = (
    "Merci de renvoyer la facture à {email} avant vendredi.",
    "Nouvelle adresse de contact : {email}, l'ancienne est supprimée.",
    "Please reach out at {email} regarding the refund.",
    "Customer wants all receipts sent to {email} from now on.",
    "Bitte an {email} antworten, nicht an die alte Adresse.",
    "Enviar presupuesto a {email} lo antes posible.",
    "Inviare conferma a {email}.",
    "cc {email} on the next reply",
)
PROSE_PHONE = (
    "Client joignable au {phone} après 18h.",
    "Demande de rappel : {phone}",
    "Customer asked for a callback on {phone}.",
    "Rückruf erbeten unter {phone}.",
    "Llamar al {phone} por la mañana.",
    "Richiamare al {phone}, chiede del rimborso.",
    "Tel. {phone} (répondeur)",
)
PROSE_BOTH = (
    "Contact : {email} / {phone}",
    "Reach me at {email} or {phone}, whichever is faster.",
    "Kontakt: {phone}, E-Mail {email}",
)
PROSE_FILLER = (
    "Colis livré, RAS.", "Relance envoyée.", "Ticket escalated to tier 2.", "Left voicemail.",
    "Rückfrage beantwortet.", "Pedido entregado.", "Pratica chiusa.", "Dossier complet.",
    "Waiting for the warehouse.", "Remboursement effectué.",
)
PROSE_NAMES = (("notes",), ("commentaire",), ("remarks",), ("bemerkungen",), ("notas",), ("note",),
               ("description",), ("message",), ("body",), ("free", "text"), ("observations",), ("memo",),
               ("nachricht",), ("mensaje",), ("messaggio",), ("history",))


# --------------------------------------------------------------------------------------------------
# Placement (engine / database / container / object / field)
# --------------------------------------------------------------------------------------------------
PLACEMENT = {
    "postgresql": {"databases": ("boutique", "clinique", "logistik"),
                   "containers": ("public", "ventes", "personal", "billing", "legacy", "rh")},
    "mysql": {"databases": ("erp", "tienda", "anagrafica", "kundendaten")},
    "mongodb": {"databases": ("appdb", "marketplace", "iot")},
}
TABLES = ("customers", "clients", "kunden", "clientes", "clienti", "users", "accounts", "orders",
          "commandes", "bestellungen", "pedidos", "ordini", "invoices", "factures", "employees", "salaries",
          "mitarbeiter", "empleados", "dipendenti", "patients", "contacts", "suppliers", "fournisseurs",
          "payments", "paiements", "zahlungen", "pagos", "pagamenti", "profiles", "leads", "tickets",
          "subscriptions", "abonnements", "shipments", "livraisons", "devices", "import_2023", "staging_raw",
          "t_data", "tbl_misc", "archive", "sync_buffer", "etl_tmp", "export_q3", "partners", "members")
MONGO_PREFIXES = ("", "", "", "profile.", "contact.", "billing.", "meta.", "items[].", "history[].",
                  "payload.", "data.attributes.")
DYNAMIC_KEYS = (("devices", "deviceId"), ("sessions", "sessionId"), ("byDay", "yyyymmdd"),
                ("i18n", "locale"), ("accounts", "accountId"))


class Corpus:
    def __init__(self, g: Gen) -> None:
        self.g = g
        self.columns: list[dict] = []
        self.labels: list[dict] = []
        self.keys: set[tuple] = set()

    def place(self, tokens: tuple[str, ...] | str, style: str | None, engine: str | None = None):
        g = self.g
        engine = engine or g.pick(("postgresql", "postgresql", "mysql", "mongodb"))
        if isinstance(tokens, str):
            base = tokens
        else:
            if engine == "mongodb" and style in ("snake", "upper", "flat") and g.chance(0.6):
                style = "camel"
            base = render(tokens, style or "snake")
        spec = PLACEMENT[engine]
        for _ in range(200):
            database = g.pick(spec["databases"])
            container = g.pick(spec["containers"]) if "containers" in spec else None
            obj = g.pick(TABLES)
            field = base
            normalized = None
            if engine == "mongodb":
                roll = g.r.random()
                if roll < 0.12:
                    parent, key = g.pick(DYNAMIC_KEYS)
                    field = f"{parent}.<{key}>.{base}"
                    normalized = f"{parent}.*.{base}"
                else:
                    field = g.pick(MONGO_PREFIXES) + base
            key = (engine, database, container, obj, field)
            if key not in self.keys:
                self.keys.add(key)
                return engine, database, container, obj, field, normalized
        raise RuntimeError(f"could not place {base}")

    def add(self, tokens, style, values: list[str], expected: list[str], *, negative_control: bool,
            tags: list[str], note: str | None = None, ambiguous: str | None = None,
            engine: str | None = None) -> None:
        engine, database, container, obj, field, normalized = self.place(tokens, style, engine)
        cid = f"h{len(self.columns) + 1:04d}"
        self.columns.append({"id": cid, "engine": engine, "database": database, "container": container,
                             "object": obj, "field": field, "values": values})
        label = {"id": cid, "engine": engine, "database": database, "container": container, "object": obj,
                 "field": field, "expected_classifiers": sorted(expected),
                 "negative_control": negative_control, "name_contains_value": False,
                 "ambiguous": ambiguous is not None, "tags": sorted(set(tags))}
        if normalized:
            label["expected_normalized_name"] = normalized
            label["tags"] = sorted(set(label["tags"]) | {"dynamic_key"})
        if note:
            label["note"] = note
        if ambiguous:
            label["ambiguity"] = ambiguous
        self.labels.append(label)


def sprinkle(g: Gen, values: list[str], rate: float) -> list[str]:
    """Replace a fraction of values with empty / placeholder cells (sparse real-world columns)."""
    return [g.pick(("", "", "N/A", "-")) if g.chance(rate) else v for v in values]


def build(seed: int = SEED) -> tuple[dict, dict]:
    g = Gen(seed)
    c = Corpus(g)

    # ---- positives -------------------------------------------------------------------------------
    for cls in CLASSIFIERS:
        names = POS_NAMES[cls]
        plan: list[tuple[tuple[str, ...] | str, str | None, str]] = []
        for tokens in names:
            plan.append((tokens, g.pick(STYLES), "explicit"))
        for tokens in INNOCENT_NAMES[cls]:
            plan.append((tokens, g.pick(STYLES), "innocent_name"))
        n_opaque = 0 if cls == "pii.birth_date" else 10
        for name in g.r.sample(OPAQUE, n_opaque):
            plan.append((name, None, "opaque"))
        i = 0
        while len(plan) < TARGET_POSITIVES:  # re-use explicit names in another style / table
            tokens = names[i % len(names)]
            plan.append((tokens, g.pick(("camel", "upper", "pascal")), "explicit"))
            i += 1
        for tokens, style, naming in plan:
            if isinstance(tokens, tuple):
                profile = value_profile_for(cls, tokens, g)
            else:
                profile = g.pick(VALUE_PROFILES[cls])
            values = [positive_value(g, cls, profile) for _ in range(ROWS)]
            tags = [f"naming:{naming}", f"format:{profile}"]
            if naming != "opaque" and style:
                tags.append(f"style:{style}")
            if g.chance(0.15):
                values = sprinkle(g, values, 0.08)
                tags.append("sparse")
            c.add(tokens, style, values, [cls], negative_control=False, tags=tags)

    # ---- mixed free text (positives for pii.email and/or pii.phone) ------------------------------
    mixed_plan = ([("email", 0.4)] * 6 + [("phone", 0.4)] * 6 + [("both", 0.4)] * 4 +
                  [("email", 0.05), ("phone", 0.05), ("both", 0.05)])
    for kind, rate in mixed_plan:
        tokens = g.pick(PROSE_NAMES)
        vals = []
        present = set()
        for i in range(ROWS):
            force = i == ROWS // 2  # guarantee at least one embedded value
            if force or g.chance(rate):
                k = kind if kind != "both" else g.pick(("email", "phone", "both"))
                if force and kind == "both":
                    k = "both"
                tpl = g.pick({"email": PROSE_EMAIL, "phone": PROSE_PHONE, "both": PROSE_BOTH}[k])
                vals.append(tpl.format(email=g.email("mixed"), phone=g.phone(g.pick(("frmix", "intl")))))
                present |= {"pii.email"} if "{email}" in tpl else set()
                present |= {"pii.phone"} if "{phone}" in tpl else set()
            else:
                vals.append(g.pick(PROSE_FILLER))
        tags = ["naming:explicit", "free_text", f"embedded:{kind}"]
        if rate < 0.1:
            tags.append("low_prevalence")
        c.add(tokens, g.pick(STYLES), vals, sorted(present), negative_control=False, tags=tags,
              note=f"free text; about {int(rate * 100)} % of rows embed a value")

    # contact columns mixing e-mails and phones row by row
    for tokens in (("contact",), ("contact", "info"), ("kontakt",), ("recapito",)):
        vals = [g.email("mixed") if g.chance(0.5) else g.phone("frmix") for _ in range(ROWS)]
        c.add(tokens, g.pick(STYLES), vals, ["pii.email", "pii.phone"], negative_control=False,
              tags=["naming:explicit", "mixed_types"], note="each row is either an e-mail or a phone number")

    # ---- hard negatives --------------------------------------------------------------------------
    for ntype, (fn, names, opaque_ok, note) in neg_generators().items():
        plan = [(t, g.pick(STYLES), "misleading" if ntype.startswith(("boolean", "country", "dial", "phone_ext",
                                                                         "card_", "hash_algo", "email_domain"))
                 else "explicit") for t in names]
        # every name a second time, other style, other placement
        plan += [(t, g.pick(("camel", "upper", "pascal")), p[2]) for t, p in zip(names, plan)]
        if opaque_ok:
            plan += [(n, None, "opaque") for n in g.r.sample(OPAQUE, 3)]
        i = 0
        while len(plan) < MIN_NEG_PER_TYPE:  # third placement of the same names, other style
            t = names[i % len(names)]
            plan.append((t, g.pick(("snake", "flat", "camel")), plan[i % len(names)][2]))
            i += 1
        for tokens, style, naming in plan:
            values = [fn(g) for _ in range(ROWS)]
            tags = [f"naming:{naming}", f"negative:{ntype}"]
            if naming != "opaque" and style:
                tags.append(f"style:{style}")
            c.add(tokens, style, values, [], negative_control=True, tags=tags, note=note)

    # ---- ambiguous columns (excluded from scoring, never silently) -------------------------------
    for name in g.r.sample(OPAQUE, 4):
        vals = [g.birth_date(g.pick(("iso", "fr"))) for _ in range(ROWS)]
        c.add(name, None, vals, ["pii.birth_date"], negative_control=False,
              tags=["naming:opaque", "ambiguous"],
              ambiguous="dates between 1938 and 2007 under an opaque name: plausible birth dates, but "
                        "nothing proves it (could be hire, contract or event dates)")
    for tokens in (("birth", "year"), ("annee", "naissance")):
        c.add(tokens, g.pick(STYLES), [str(g.r.randint(1938, 2007)) for _ in range(ROWS)], [],
              negative_control=True, tags=["naming:explicit", "ambiguous"],
              ambiguous="year of birth only: personal data, but not a full birth date")
    for tokens in (("username",), ("pseudo",)):
        vals = []
        for _ in range(ROWS):
            f = ascii_fold(g.first()).lower().replace(" ", "").replace("'", "")
            ln = ascii_fold(g.last()).lower().replace(" ", "").replace("'", "")
            vals.append(g.pick((f"{f[0]}{ln}", f"{f}{g.r.randint(1, 99)}", f"{ln}_{f[:3]}", f"{f}.{ln[0]}")))
        c.add(tokens, g.pick(STYLES), vals, [], negative_control=True, tags=["naming:explicit", "ambiguous"],
              ambiguous="handles derived from person names: arguably pii.person_name")
    for tokens in (("password",), ("pwd", "hash")):
        c.add(tokens, g.pick(STYLES), [g.hexs(64) for _ in range(ROWS)], ["secret.password_hash"],
              negative_control=False, tags=["naming:explicit", "ambiguous"],
              ambiguous="unsalted hex SHA-256 under a password name: a (weak) password hash or a plain digest")
    for tokens in (("card", "masked"), ("pan", "masque")):
        vals = []
        for _ in range(ROWS):
            raw = g.card_raw(g.pick(Gen.CARD_BRANDS))
            vals.append(raw[:4] + " **** **** " + raw[-4:])
        c.add(tokens, g.pick(STYLES), vals, [], negative_control=True, tags=["naming:explicit", "ambiguous"],
              ambiguous="truncated PAN (first 4 + last 4): PCI-DSS allows it; whether it counts as a card "
                        "number is a policy choice")
    c.add(g.pick(OPAQUE[:10]) + "_x", None, [g.pick(CITY_LOOKALIKE) for _ in range(ROWS)], [],
          negative_control=True, tags=["naming:opaque", "ambiguous"],
          ambiguous="single words that are both city names and first names (Florence, Nancy, Charlotte...)")
    c.add(("fediverse",), "snake",
          [f"@{ascii_fold(g.first()).lower()}{g.r.randint(1, 99)}@social.example" for _ in range(ROWS)], [],
          negative_control=True, tags=["naming:explicit", "ambiguous"],
          ambiguous="fediverse handles (@user@host) share the e-mail shape")

    corpus = {"generator": "dev/holdout/generate.py", "seed": seed, "version": VERSION, "rows_per_column": ROWS,
              "columns": c.columns}
    labels = {
        "generator": "dev/holdout/generate.py", "seed": seed, "version": VERSION,
        "classifiers": list(CLASSIFIERS),
        "notes": [
            "FAKE data only. Regenerate with `python3 dev/holdout/generate.py`; never edit by hand.",
            "Held-out set: never tune classifiers against it (see dev/holdout/README.md).",
            "Same location format as dev/ground-truth.json, plus: id, ambiguous, ambiguity, tags.",
            "Values live in corpus.json (joined on id), not here. corpus.json is NOT committed: run "
            "`python3 dev/holdout/generate.py` to produce it; its SHA-256 is corpus_sha256.",
            "ambiguous: true columns are excluded from scoring; their expected_classifiers is a best guess.",
            "negative_control: expected_classifiers is empty and the column is a deliberate hard negative.",
        ],
        "locations": c.labels,
    }
    labels["corpus_sha256"] = corpus_sha256(corpus)
    return corpus, labels


def corpus_sha256(corpus: dict) -> str:
    """SHA-256 of the exact bytes written to corpus.json (UTF-8)."""
    return hashlib.sha256(dump(corpus).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------------------
EMAIL_IN_TEXT = re.compile(r"[^\s@<>(),;:/]+@([^\s@<>(),;:/]+\.[^\s@<>(),;:/.]+)")


def validate(corpus: dict, labels: dict) -> list[str]:
    errors: list[str] = []
    cols = {c["id"]: c for c in corpus["columns"]}
    if len(cols) != len(corpus["columns"]) or len(labels["locations"]) != len(cols):
        errors.append("column / label count mismatch or duplicate ids")
    keys = set()
    for lab in labels["locations"]:
        col = cols[lab["id"]]
        k = (lab["engine"], lab["database"], lab["container"], lab["object"], lab["field"])
        if k in keys:
            errors.append(f"duplicate location {k}")
        keys.add(k)
        if k != (col["engine"], col["database"], col["container"], col["object"], col["field"]):
            errors.append(f"{lab['id']}: label and corpus disagree on location")
        if not all(isinstance(v, str) for v in col["values"]) or len(col["values"]) != ROWS:
            errors.append(f"{lab['id']}: values must be {ROWS} strings")
        if not set(lab["expected_classifiers"]) <= set(CLASSIFIERS):
            errors.append(f"{lab['id']}: unknown classifier")
        exp = set(lab["expected_classifiers"])
        vals = [v for v in col["values"] if v not in ("", "N/A", "-")]
        tags = set(lab["tags"])
        neg = next((t.split(":", 1)[1] for t in tags if t.startswith("negative:")), None)
        if exp == {"pii.card_number"}:
            for v in vals:
                d = re.sub(r"[ -]", "", v)
                if not (check_luhn(v) and 13 <= len(d) <= 19):
                    errors.append(f"{lab['id']}: card fails Luhn/length: {v!r}")
        if exp == {"pii.iban"}:
            errors += [f"{lab['id']}: IBAN fails mod-97: {v!r}" for v in vals if not check_iban(v)]
        if exp == {"pii.nir"}:
            errors += [f"{lab['id']}: NIR fails key: {v!r}" for v in vals if not check_nir(v)]
        if exp == {"secret.aws_key"}:
            for v in vals:
                for part in v.split(":"):
                    ok = (re.fullmatch(r"(AKIA|ASIA)[A-Z2-7]{9}EXAMPLE", part) or
                          re.fullmatch(r"[A-Za-z0-9+/]{30}EXAMPLEKEY", part))
                    if not ok:
                        errors.append(f"{lab['id']}: AWS value not in the EXAMPLE convention: {v!r}")
        if exp == {"pii.birth_date"} and not lab["ambiguous"]:
            if not any(re.search(r"(19[3-9]\d|200[0-7])", v) for v in vals):
                errors.append(f"{lab['id']}: no birth year in range")
        if neg in ("siret", "siren", "imei"):
            want = {"siret": 14, "siren": 9, "imei": 15}[neg]
            for v in vals:
                if not (check_luhn(v) and len(re.sub(r"[ -]", "", v)) == want):
                    errors.append(f"{lab['id']}: {neg} fails Luhn/length: {v!r}")
        if neg == "luhn_fail_16":
            errors += [f"{lab['id']}: should fail Luhn: {v!r}" for v in vals if check_luhn(v)]
        if neg == "tracking":
            errors += [f"{lab['id']}: 16-digit tracking passes Luhn: {v!r}"
                       for v in vals if re.fullmatch(r"\d{16}", v) and check_luhn(v)]
        if neg == "nir_like":
            errors += [f"{lab['id']}: NIR-like value has a valid key: {v!r}" for v in vals if check_nir(v)]
        if neg == "vat":
            errors += [f"{lab['id']}: VAT key: {v!r}" for v in vals if not check_fr_vat(v)]
        if neg == "ean":
            errors += [f"{lab['id']}: EAN check: {v!r}" for v in vals if not check_ean13(v)]
        if neg == "isbn":
            for v in vals:
                t = v.replace("-", "")
                if len(t) == 13 and not check_ean13(t):
                    errors.append(f"{lab['id']}: ISBN-13 check: {v!r}")
                if len(t) == 10:
                    s = sum((10 - i) * (10 if ch == "X" else int(ch)) for i, ch in enumerate(t))
                    if s % 11:
                        errors.append(f"{lab['id']}: ISBN-10 check: {v!r}")
        if neg == "base64_token":
            errors += [f"{lab['id']}: 40-char base64 token (AWS shape): {v!r}" for v in vals
                       if re.fullmatch(r"[A-Za-z0-9+/]{40}", v)]
        # reserved e-mail domains everywhere
        for v in col["values"]:
            for m in EMAIL_IN_TEXT.finditer(v):
                dom = m.group(1).lower().rstrip(".")
                try:
                    uni = dom.encode("ascii").decode("idna") if "xn--" in dom else dom
                except UnicodeError:
                    uni = dom
                if (neg in ("package_ref",) or "ambiguous" in tags) and dom.endswith((".test", ".example")):
                    continue
                if not uni.endswith(RESERVED_EMAIL_SUFFIXES) and not re.fullmatch(r"\d+\.\d+\.\d+", dom):
                    if neg != "package_ref":
                        errors.append(f"{lab['id']}: non-reserved e-mail domain {dom!r}")
    return errors


def counts(labels: dict) -> tuple[Counter, Counter, Counter, int]:
    pos, amb, neg_types = Counter(), Counter(), Counter()
    negatives = 0
    for lab in labels["locations"]:
        if lab["ambiguous"]:
            for cls in lab["expected_classifiers"] or ["(none)"]:
                amb[cls] += 1
            continue
        if not lab["expected_classifiers"]:
            negatives += 1
            neg_types[next(t.split(":", 1)[1] for t in lab["tags"] if t.startswith("negative:"))] += 1
        for cls in lab["expected_classifiers"]:
            pos[cls] += 1
    return pos, amb, neg_types, negatives


def dump(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail if committed outputs are out of date")
    args = ap.parse_args()

    corpus, labels = build()
    errors = validate(corpus, labels)
    if errors:
        for e in errors[:50]:
            print("ERROR", e, file=sys.stderr)
        print(f"{len(errors)} validation error(s)", file=sys.stderr)
        return 1
    corpus_s, labels_s = dump(corpus), dump(labels)
    again_c, again_l = build()
    if dump(again_c) != corpus_s or dump(again_l) != labels_s:
        print("ERROR generator is not deterministic", file=sys.stderr)
        return 1

    if args.check:
        # corpus.json is not committed: regenerate it in memory and compare its SHA-256 with the one
        # recorded in the committed labels.json, then compare labels.json byte for byte.
        problems = []
        try:
            committed = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            committed = {}
            problems.append(f"labels.json unreadable: {e}")
        recorded = committed.get("corpus_sha256")
        actual = hashlib.sha256(corpus_s.encode("utf-8")).hexdigest()
        if recorded != actual:
            problems.append(f"corpus SHA-256 {actual} differs from labels.json corpus_sha256 {recorded}")
        if LABELS_PATH.exists() and LABELS_PATH.read_text(encoding="utf-8") != labels_s:
            problems.append("labels.json is out of date")
        if problems:
            for msg in problems:
                print("ERROR", msg, file=sys.stderr)
            print("run python3 dev/holdout/generate.py and commit labels.json", file=sys.stderr)
            return 1
        print(f"check OK: corpus sha256 {actual}")
    else:
        CORPUS_PATH.write_text(corpus_s, encoding="utf-8")
        LABELS_PATH.write_text(labels_s, encoding="utf-8")

    pos, amb, neg_types, negatives = counts(labels)
    print(f"columns: {len(labels['locations'])} (rows per column: {ROWS})")
    print("positive columns per classifier (non-ambiguous):")
    for cls in CLASSIFIERS:
        print(f"  {cls:24s} {pos[cls]:4d}")
    print(f"hard-negative columns: {negatives}")
    for t, n in sorted(neg_types.items()):
        print(f"  {t:24s} {n:4d}")
    print(f"ambiguous columns (excluded): {sum(1 for x in labels['locations'] if x['ambiguous'])} {dict(amb)}")
    print("checksums (Luhn, mod-97, NIR key, EAN/ISBN, VAT) verified independently: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
