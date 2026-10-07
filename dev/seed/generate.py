#!/usr/bin/env python3
"""Deterministic generator of FAKE sensitive data for the DataBastion dev environment.

Python standard library only. Everything is derived from a fixed seed, so running it twice produces
byte-identical files. Outputs:

- ``dev/seed/out/postgres.sql``  PostgreSQL database ``shop``
- ``dev/seed/out/mysql.sql``     MySQL database ``hr``
- ``dev/seed/out/mariadb.sql``   MariaDB database ``support``
- ``dev/seed/out/mongo.json``    MongoDB database ``app`` (loaded by ``dev/mongo/initdb/10-seed.js``)
- ``dev/seed/out/openldap.ldif`` OpenLDAP suffix ``dc=example,dc=org``
- ``dev/cas/services/*.json``    Apereo CAS JSON service registry (opt-in service ``cas``)
- ``dev/ground-truth.json``      every seeded location and the classifiers expected on it

All values are fictitious by construction:
- e-mail domains are the reserved ``example.com`` / ``example.org`` / ``example.net`` (RFC 2606);
- French phone numbers come from the ARCEP ranges reserved for fiction, UK numbers from the Ofcom
  drama range (07700 900xxx), US numbers from 555-01xx;
- IBANs use bank codes starting with ``99`` (FR) / ``999`` (DE) and have valid mod-97 check digits;
- NIRs have a valid key but random components;
- card numbers use the well-known test prefixes 411111 (Visa) and 555555 (Mastercard), Luhn-valid;
- AWS-shaped keys always contain ``EXAMPLE``;
- CAS client secrets and the REST Authorization header start with ``dev-only``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import sys
from pathlib import Path

SEED = 20260928
DEV_DIR = Path(__file__).resolve().parent.parent
OUT_DIR = DEV_DIR / "seed" / "out"
GROUND_TRUTH = DEV_DIR / "ground-truth.json"

EMAIL_DOMAINS = ("example.com", "example.org", "example.net")

# ARCEP numbers reserved for audiovisual fiction (10 digits, national format).
FR_FICTION_PREFIXES = ("0199 00", "0261 91", "0353 01", "0465 71", "0536 49", "0639 98", "0972 10")

FR_FIRST = ("Jean", "Marie", "Camille", "Louis", "Chloé", "Hugo", "Léa", "Lucas", "Manon", "Théo",
            "Inès", "Nathan", "Zoé", "Gabriel", "Élodie", "Raphaël", "Anaïs", "Arthur", "Jade", "Noé")
FR_LAST = ("Martin", "Bernard", "Dubois", "Thomas", "Robert", "Richard", "Petit", "Durand", "Leroy",
           "Moreau", "Simon", "Laurent", "Lefèvre", "Michel", "Garcia", "David", "Bertrand", "Roux",
           "Vincent", "Fournier")
INTL_FIRST = ("Olivia", "James", "Amelia", "Noah", "Sophia", "Liam", "Emma", "Oliver", "Ava", "Elijah",
              "Hannah", "Lukas", "Mia", "Mateo", "Sofia", "Aiden")
INTL_LAST = ("Smith", "Johnson", "O'Connor", "Williams", "Brown", "Müller", "Schmidt", "Rossi",
             "García", "Novak", "Jansen", "Kowalski", "Nielsen", "Silva", "Taylor", "Evans")
FR_STREETS = ("rue des Lilas", "avenue de la République", "boulevard Victor Hugo", "rue du Moulin",
              "impasse des Tilleuls", "place de l'Église", "chemin des Vignes", "allée des Peupliers")
FR_CITIES = (("75011", "Paris"), ("69003", "Lyon"), ("13006", "Marseille"), ("31000", "Toulouse"),
             ("33000", "Bordeaux"), ("44000", "Nantes"), ("59000", "Lille"), ("67000", "Strasbourg"))
INTL_ADDR = (("GB", "Baker Street", "NW1 6XE", "London"), ("DE", "Musterstraße", "10115", "Berlin"),
             ("US", "Elm Street", "90210", "Springfield"), ("NL", "Voorbeeldstraat", "1011 AB", "Amsterdam"))

AKIA_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B64_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
BCRYPT_CHARSET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


# --------------------------------------------------------------------------------------------------
# Validators (mirrors of what the classifiers will check in P2-A)
# --------------------------------------------------------------------------------------------------
def luhn_check_digit(partial: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(partial)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def luhn_valid(number: str) -> bool:
    digits = number.replace(" ", "")
    return digits.isdigit() and len(digits) >= 12 and luhn_check_digit(digits[:-1]) == digits[-1]


def _iban_numeric(s: str) -> int:
    return int("".join(str(int(c, 36)) for c in s))


def iban_check_digits(country: str, bban: str) -> str:
    return f"{98 - _iban_numeric(bban + country + '00') % 97:02d}"


def iban_valid(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    return len(s) >= 15 and s[:2].isalpha() and _iban_numeric(s[4:] + s[:4]) % 97 == 1


def fr_rib_key(bank: str, branch: str, account: str) -> str:
    return f"{97 - (89 * int(bank) + 15 * int(branch) + 3 * int(account)) % 97:02d}"


def nir_key(first13: str) -> str:
    return f"{97 - int(first13) % 97:02d}"


def nir_valid(nir: str) -> bool:
    s = nir.replace(" ", "")
    return len(s) == 15 and s.isdigit() and nir_key(s[:13]) == s[13:]


# --------------------------------------------------------------------------------------------------
# Fake data
# --------------------------------------------------------------------------------------------------
class Fake:
    def __init__(self, seed: int) -> None:
        self.r = random.Random(seed)
        self._used_emails: set[str] = set()

    def digits(self, n: int) -> str:
        return "".join(self.r.choice("0123456789") for _ in range(n))

    def chars(self, charset: str, n: int) -> str:
        return "".join(self.r.choice(charset) for _ in range(n))

    def fr_phone(self) -> str:
        p = self.r.choice(FR_FICTION_PREFIXES).replace(" ", "")
        d = p + self.digits(4)
        return " ".join(d[i:i + 2] for i in range(0, 10, 2))

    def intl_phone(self, country: str) -> str:
        if country == "GB":
            return f"+44 7700 900{self.digits(3)}"
        if country == "US":
            return f"+1 {self.r.choice(('202', '312', '415'))} 555 01{self.digits(2)}"
        # Other countries: French fiction range in international format.
        return "+33 " + self.fr_phone()[1:]

    @staticmethod
    def _ascii(s: str) -> str:
        table = str.maketrans("éèêëàâäîïôöùûüçÉÈÀÖÜß'", "eeeeaaaiioouuucEEAOUs-")
        return s.translate(table).lower().replace(" ", "")

    def email(self, first: str, last: str) -> str:
        base = f"{self._ascii(first)}.{self._ascii(last)}"
        n = 0
        while True:
            local = base if n == 0 else f"{base}{n}"
            addr = f"{local}@{self.r.choice(EMAIL_DOMAINS)}"
            if addr not in self._used_emails:
                self._used_emails.add(addr)
                return addr
            n += 1

    def fr_iban(self) -> str:
        bank = "99" + self.digits(3)
        branch = self.digits(5)
        account = self.digits(11)
        bban = bank + branch + account + fr_rib_key(bank, branch, account)
        raw = "FR" + iban_check_digits("FR", bban) + bban
        return " ".join(raw[i:i + 4] for i in range(0, len(raw), 4))

    def de_iban(self) -> str:
        bban = "999" + self.digits(5) + self.digits(10)
        raw = "DE" + iban_check_digits("DE", bban) + bban
        return " ".join(raw[i:i + 4] for i in range(0, len(raw), 4))

    def nir(self, sex: int, birth_year: int, birth_month: int) -> str:
        # Mainland departments only (Corsica "2A"/"2B" would need the 19/18 substitution).
        dept = f"{self.r.choice([d for d in range(1, 96) if d != 20]):02d}"
        commune = f"{self.r.randint(1, 999):03d}"
        order = f"{self.r.randint(1, 999):03d}"
        first13 = f"{sex}{birth_year % 100:02d}{birth_month:02d}{dept}{commune}{order}"
        key = nir_key(first13)
        return f"{first13[0]} {first13[1:3]} {first13[3:5]} {first13[5:7]} {first13[7:10]} {first13[10:13]} {key}"

    def card(self) -> tuple[str, str]:
        brand, prefix = self.r.choice((("VISA", "411111"), ("MASTERCARD", "555555")))
        partial = prefix + self.digits(9)
        number = partial + luhn_check_digit(partial)
        return brand, " ".join(number[i:i + 4] for i in range(0, 16, 4))

    def not_luhn(self, n: int = 16) -> str:
        while True:
            s = "9" + self.digits(n - 1)
            if not luhn_valid(s):
                return s

    def aws_key_pair(self) -> tuple[str, str]:
        access = "AKIA" + self.chars(AKIA_CHARSET, 9) + "EXAMPLE"
        secret = self.chars(B64_CHARSET, 30) + "EXAMPLEKEY"
        return access, secret

    def bcrypt_like(self) -> str:
        return "$2b$12$" + self.chars(BCRYPT_CHARSET, 53)

    def date(self, y0: int, y1: int) -> str:
        return f"{self.r.randint(y0, y1)}-{self.r.randint(1, 12):02d}-{self.r.randint(1, 28):02d}"

    def timestamp(self) -> str:
        return f"{self.date(2023, 2026)}T{self.r.randint(0, 23):02d}:{self.r.randint(0, 59):02d}:00Z"

    def person(self) -> dict:
        fr = self.r.random() < 0.7
        if fr:
            first, last = self.r.choice(FR_FIRST), self.r.choice(FR_LAST)
            postal, city = self.r.choice(FR_CITIES)
            street = f"{self.r.randint(1, 180)} {self.r.choice(FR_STREETS)}"
            country, phone = "FR", self.fr_phone()
        else:
            first, last = self.r.choice(INTL_FIRST), self.r.choice(INTL_LAST)
            country, sname, postal, city = self.r.choice(INTL_ADDR)
            street = f"{self.r.randint(1, 250)} {sname}"
            phone = self.intl_phone(country)
        birth = self.date(1950, 2004)
        sex = self.r.choice((1, 2))
        brand, card = self.card()
        return {
            "first": first, "last": last, "email": self.email(first, last), "phone": phone,
            "birth_date": birth, "street": street, "postal_code": postal, "city": city,
            "country": country,
            "nir": self.nir(sex, int(birth[:4]), int(birth[5:7])) if fr else None,
            "iban": self.fr_iban() if fr or self.r.random() < 0.5 else self.de_iban(),
            "card_brand": brand, "card": card,
        }


# --------------------------------------------------------------------------------------------------
# Ground truth
# --------------------------------------------------------------------------------------------------
class Truth:
    def __init__(self) -> None:
        self.locations: list[dict] = []

    def add(self, engine: str, database: str, container: str | None, obj: str, field: str | None,
            classifiers: list[str], values: list[str] | None = None, *, negative_control: bool = False,
            name_values: list[str] | None = None, name_value_classifiers: list[str] | None = None,
            normalized: str | None = None, note: str | None = None,
            never_sampled: bool = False) -> None:
        loc: dict = {
            "engine": engine, "database": database, "container": container, "object": obj,
            "field": field, "expected_classifiers": sorted(classifiers),
            "negative_control": negative_control, "name_contains_value": bool(name_values),
        }
        if name_values:
            loc["name_values"] = name_values
            loc["name_value_classifiers"] = sorted(name_value_classifiers or [])
        if normalized:
            loc["expected_normalized_name"] = normalized
        if note:
            loc["note"] = note
        if never_sampled:
            loc["never_sampled"] = True
        if values is not None and (classifiers or never_sampled):
            loc["values"] = sorted({v for v in values if v})
        self.locations.append(loc)


# --------------------------------------------------------------------------------------------------
# SQL helpers
# --------------------------------------------------------------------------------------------------
def sql_lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("\\", "\\\\").replace("'", "''") + "'"


def pg_lit(v) -> str:
    if isinstance(v, str):
        return "'" + v.replace("'", "''") + "'"
    return sql_lit(v)


def inserts(table: str, cols: list[str], rows: list[tuple], lit, q: str) -> str:
    out = []
    for i in range(0, len(rows), 50):
        chunk = rows[i:i + 50]
        values = ",\n  ".join("(" + ", ".join(lit(v) for v in row) + ")" for row in chunk)
        out.append(f"INSERT INTO {table} ({', '.join(q + c + q for c in cols)}) VALUES\n  {values};")
    return "\n".join(out) + "\n"


HEADER = "-- GENERATED by dev/seed/generate.py (seed {seed}). FAKE data only. Do not edit by hand.\n"


# --------------------------------------------------------------------------------------------------
# PostgreSQL: database shop
# --------------------------------------------------------------------------------------------------
def gen_postgres(f: Fake, t: Truth) -> str:
    E, DB = "postgresql", "shop"
    people = [f.person() for _ in range(150)]
    s = [HEADER.format(seed=SEED), "SET client_min_messages = warning;\n",
         "CREATE SCHEMA crm;\nCREATE SCHEMA billing;\nCREATE SCHEMA ops;\n\n"]

    s.append("""CREATE TABLE crm.customers (
  id integer PRIMARY KEY, first_name text NOT NULL, last_name text NOT NULL, email text NOT NULL,
  phone text, birth_date date, street text, postal_code text, city text, country_code char(2),
  nir text, email_opt_in boolean NOT NULL, phone_verified boolean NOT NULL, created_at timestamptz NOT NULL
);
""")
    rows = [(i + 1, p["first"], p["last"], p["email"], p["phone"], p["birth_date"], p["street"],
             p["postal_code"], p["city"], p["country"], p["nir"], f.r.random() < 0.5, f.r.random() < 0.5,
             f.timestamp()) for i, p in enumerate(people)]
    s.append(inserts("crm.customers", ["id", "first_name", "last_name", "email", "phone", "birth_date",
                                       "street", "postal_code", "city", "country_code", "nir",
                                       "email_opt_in", "phone_verified", "created_at"], rows, pg_lit, ""))
    c = ("crm", "customers")
    t.add(E, DB, *c, "first_name", ["pii.person_name"], [p["first"] for p in people])
    t.add(E, DB, *c, "last_name", ["pii.person_name"], [p["last"] for p in people])
    t.add(E, DB, *c, "email", ["pii.email"], [p["email"] for p in people])
    t.add(E, DB, *c, "phone", ["pii.phone"], [p["phone"] for p in people])
    t.add(E, DB, *c, "birth_date", ["pii.birth_date"], [p["birth_date"] for p in people])
    t.add(E, DB, *c, "street", ["pii.postal_address"], [p["street"] for p in people])
    t.add(E, DB, *c, "nir", ["pii.nir"], [p["nir"] for p in people])
    t.add(E, DB, *c, "email_opt_in", [], negative_control=True, note="boolean; name looks sensitive")
    t.add(E, DB, *c, "phone_verified", [], negative_control=True, note="boolean; name looks sensitive")
    t.add(E, DB, *c, "created_at", [], negative_control=True, note="timestamp, not a birth date")

    # Free text with embedded identifiers.
    notes, note_emails, note_phones = [], [], []
    for i in range(60):
        p = f.r.choice(people)
        ph, em = f.fr_phone(), f.email(p["first"], p["last"])
        note_phones.append(ph)
        note_emails.append(em)
        notes.append((i + 1, people.index(p) + 1,
                      f"Customer called from {ph} and asked to use {em} for invoices."))
    s.append("\nCREATE TABLE crm.customer_notes (id integer PRIMARY KEY, customer_id integer NOT NULL, note text NOT NULL);\n")
    s.append(inserts("crm.customer_notes", ["id", "customer_id", "note"], notes, pg_lit, ""))
    t.add(E, DB, "crm", "customer_notes", "note", ["pii.email", "pii.phone"], note_emails + note_phones,
          note="free text; values are embedded tokens")

    # Payment methods.
    s.append("""
CREATE TABLE billing.payment_methods (
  id integer PRIMARY KEY, customer_id integer NOT NULL, card_brand text NOT NULL, card_number text NOT NULL,
  card_holder text NOT NULL, card_expiry text NOT NULL, iban text NOT NULL, iban_country char(2) NOT NULL,
  tracking_ref text NOT NULL
);
""")
    rows, trk = [], []
    for i, p in enumerate(people[:120]):
        ref = f.not_luhn(16)
        trk.append(ref)
        rows.append((i + 1, i + 1, p["card_brand"], p["card"], f"{p['first']} {p['last']}".upper(),
                     f"{f.r.randint(1, 12):02d}/{f.r.randint(27, 31)}", p["iban"], p["iban"][:2], ref))
    s.append(inserts("billing.payment_methods", ["id", "customer_id", "card_brand", "card_number",
                                                 "card_holder", "card_expiry", "iban", "iban_country",
                                                 "tracking_ref"], rows, pg_lit, ""))
    c = ("billing", "payment_methods")
    t.add(E, DB, *c, "card_number", ["pii.card_number"], [r[3] for r in rows])
    t.add(E, DB, *c, "card_holder", ["pii.person_name"], [r[4] for r in rows])
    t.add(E, DB, *c, "iban", ["pii.iban"], [r[6] for r in rows])
    t.add(E, DB, *c, "card_brand", [], negative_control=True, note="brand name, not a card number")
    t.add(E, DB, *c, "iban_country", [], negative_control=True, note="country code only")
    t.add(E, DB, *c, "tracking_ref", [], negative_control=True,
          note="16-digit numbers that FAIL the Luhn check")

    # Invoices: only look-alikes.
    s.append("""
CREATE TABLE billing.invoices (
  id integer PRIMARY KEY, customer_id integer NOT NULL, invoice_number text NOT NULL,
  amount_cents integer NOT NULL, email_template_id integer NOT NULL
);
""")
    rows = [(i + 1, f.r.randint(1, 150), f"INV-2026-{i + 1:06d}", f.r.randint(500, 250000), f.r.randint(1, 9))
            for i in range(200)]
    s.append(inserts("billing.invoices", ["id", "customer_id", "invoice_number", "amount_cents",
                                          "email_template_id"], rows, pg_lit, ""))
    for col in ("invoice_number", "amount_cents", "email_template_id"):
        t.add(E, DB, "billing", "invoices", col, [], negative_control=True)

    # Secrets.
    s.append("""
CREATE TABLE ops.app_credentials (
  id integer PRIMARY KEY, service text NOT NULL, aws_access_key_id text NOT NULL,
  aws_secret_access_key text NOT NULL, owner_email text NOT NULL, password_hash text NOT NULL
);
""")
    rows = []
    for i, svc in enumerate(("billing-export", "crm-sync", "backup", "analytics", "mailer", "search")):
        a, k = f.aws_key_pair()
        p = f.r.choice(people)
        rows.append((i + 1, svc, a, k, p["email"], f.bcrypt_like()))
    s.append(inserts("ops.app_credentials", ["id", "service", "aws_access_key_id", "aws_secret_access_key",
                                             "owner_email", "password_hash"], rows, pg_lit, ""))
    c = ("ops", "app_credentials")
    t.add(E, DB, *c, "aws_access_key_id", ["secret.aws_key"], [r[2] for r in rows])
    t.add(E, DB, *c, "aws_secret_access_key", ["secret.aws_key"], [r[3] for r in rows])
    t.add(E, DB, *c, "owner_email", ["pii.email"], [r[4] for r in rows])
    t.add(E, DB, *c, "password_hash", ["secret.password_hash"], [r[5] for r in rows])
    t.add(E, DB, *c, "service", [], negative_control=True)

    # Value-bearing table names (ADR-0009, security review M2).
    phone_token = f.fr_phone().replace(" ", "")
    tname = f"export_client_{phone_token}"
    p = people[0]
    s.append(f"\nCREATE TABLE crm.{tname} (id integer PRIMARY KEY, email text NOT NULL);\n")
    s.append(inserts(f"crm.{tname}", ["id", "email"], [(1, p["email"])], pg_lit, ""))
    t.add(E, DB, "crm", tname, "email", ["pii.email"], [p["email"]], name_values=[phone_token],
          name_value_classifiers=["pii.phone"], normalized="*",
          note="table name embeds a phone number")
    p = people[1]
    tname = f"archive_{Fake._ascii(p['first'])}_{Fake._ascii(p['last'])}"
    s.append(f"\nCREATE TABLE crm.{tname} (id integer PRIMARY KEY, amount_cents integer NOT NULL);\n")
    s.append(inserts(f"crm.{tname}", ["id", "amount_cents"], [(1, 4200), (2, 1300)], pg_lit, ""))
    t.add(E, DB, "crm", tname, "amount_cents", [], negative_control=True,
          name_values=[Fake._ascii(p["first"]), Fake._ascii(p["last"])],
          name_value_classifiers=["pii.person_name"], normalized="*",
          note="table name embeds a person name; its content is not sensitive")
    return "".join(s)


# --------------------------------------------------------------------------------------------------
# MySQL: database hr
# --------------------------------------------------------------------------------------------------
def gen_mysql(f: Fake, t: Truth) -> str:
    E, DB = "mysql", "hr"
    people = [f.person() for _ in range(120)]
    # SET NAMES: the MySQL image entrypoint loads this file with a client whose default character set
    # follows the container locale (latin1): without it, every non-ASCII value is double-encoded.
    s = [HEADER.format(seed=SEED), "SET NAMES utf8mb4;\nCREATE DATABASE hr CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;\nUSE hr;\n\n"]
    s.append("""CREATE TABLE employees (
  id INT PRIMARY KEY, full_name VARCHAR(120) NOT NULL, work_email VARCHAR(160) NOT NULL,
  mobile_phone VARCHAR(32), birth_date DATE, home_address VARCHAR(255), nir VARCHAR(32),
  iban VARCHAR(42), salary_eur INT NOT NULL, badge_id CHAR(8) NOT NULL, phone_extension CHAR(4) NOT NULL
);
""")
    rows = []
    for i, p in enumerate(people):
        rows.append((i + 1, f"{p['first']} {p['last']}", p["email"], p["phone"], p["birth_date"],
                     f"{p['street']}, {p['postal_code']} {p['city']}", p["nir"], p["iban"],
                     f.r.randint(28000, 95000), f.digits(8), f.digits(4)))
    s.append(inserts("employees", ["id", "full_name", "work_email", "mobile_phone", "birth_date",
                                   "home_address", "nir", "iban", "salary_eur", "badge_id",
                                   "phone_extension"], rows, sql_lit, "`"))
    c = (None, "employees")
    t.add(E, DB, *c, "full_name", ["pii.person_name"], [r[1] for r in rows])
    t.add(E, DB, *c, "work_email", ["pii.email"], [r[2] for r in rows])
    t.add(E, DB, *c, "mobile_phone", ["pii.phone"], [r[3] for r in rows])
    t.add(E, DB, *c, "birth_date", ["pii.birth_date"], [r[4] for r in rows])
    t.add(E, DB, *c, "home_address", ["pii.postal_address"], [r[5] for r in rows])
    t.add(E, DB, *c, "nir", ["pii.nir"], [r[6] for r in rows])
    t.add(E, DB, *c, "iban", ["pii.iban"], [r[7] for r in rows])
    t.add(E, DB, *c, "salary_eur", [], negative_control=True)
    t.add(E, DB, *c, "badge_id", [], negative_control=True, note="8 random digits")
    t.add(E, DB, *c, "phone_extension", [], negative_control=True, note="4 digits; name looks sensitive")

    # Digit-only column names that are NOT values (years).
    s.append("\nCREATE TABLE bonus_by_year (employee_id INT PRIMARY KEY, `2024` INT NOT NULL, `2025` INT NOT NULL);\n")
    rows = [(i + 1, f.r.randint(0, 5000), f.r.randint(0, 5000)) for i in range(40)]
    s.append(inserts("bonus_by_year", ["employee_id", "2024", "2025"], rows, sql_lit, "`"))
    for col in ("2024", "2025"):
        t.add(E, DB, None, "bonus_by_year", col, [], negative_control=True,
              note="digit-only column name that is a year, not a value")

    s.append("\nCREATE TABLE settings (key_name VARCHAR(64) PRIMARY KEY, value VARCHAR(255) NOT NULL);\n")
    rows = [("smtp_sender_domain", "example.com"), ("iban_validation", "strict"),
            ("phone_format", "E.164"), ("password_min_length", "14")]
    s.append(inserts("settings", ["key_name", "value"], rows, sql_lit, "`"))
    t.add(E, DB, None, "settings", "value", [], negative_control=True,
          note="configuration strings mentioning sensitive types")
    return "".join(s)


# --------------------------------------------------------------------------------------------------
# MariaDB: database support
# --------------------------------------------------------------------------------------------------
def gen_mariadb(f: Fake, t: Truth) -> str:
    E, DB = "mariadb", "support"
    people = [f.person() for _ in range(100)]
    s = [HEADER.format(seed=SEED), "SET NAMES utf8mb4;\nCREATE DATABASE support CHARACTER SET utf8mb4;\nUSE support;\n\n"]
    s.append("""CREATE TABLE tickets (
  id INT PRIMARY KEY, requester_name VARCHAR(120) NOT NULL, requester_email VARCHAR(160) NOT NULL,
  requester_phone VARCHAR(32), subject VARCHAR(200) NOT NULL, body TEXT NOT NULL, status VARCHAR(16) NOT NULL
);
""")
    subjects = ("Refund request", "Card declined", "Update my e-mail address", "Change of IBAN",
                "Phone number change", "Account closure")
    rows, body_ibans, body_cards = [], [], []
    for i, p in enumerate(people):
        if i % 2 == 0:
            body = f"Please refund to IBAN {p['iban']} as soon as possible."
            body_ibans.append(p["iban"])
        else:
            body = f"My card {p['card']} was charged twice."
            body_cards.append(p["card"])
        rows.append((i + 1, f"{p['first']} {p['last']}", p["email"], p["phone"], f.r.choice(subjects), body,
                     f.r.choice(("open", "pending", "closed"))))
    s.append(inserts("tickets", ["id", "requester_name", "requester_email", "requester_phone", "subject",
                                 "body", "status"], rows, sql_lit, "`"))
    c = (None, "tickets")
    t.add(E, DB, *c, "requester_name", ["pii.person_name"], [r[1] for r in rows])
    t.add(E, DB, *c, "requester_email", ["pii.email"], [r[2] for r in rows])
    t.add(E, DB, *c, "requester_phone", ["pii.phone"], [r[3] for r in rows])
    t.add(E, DB, *c, "body", ["pii.card_number", "pii.iban"], body_ibans + body_cards,
          note="free text; values are embedded tokens")
    t.add(E, DB, *c, "subject", [], negative_control=True, note="mentions e-mail / IBAN / phone as words")
    t.add(E, DB, *c, "status", [], negative_control=True)

    # Value-bearing table name: an e-mail address.
    p = people[0]
    tname = f"escalations_{p['email']}"
    s.append(f"\nCREATE TABLE `{tname}` (id INT PRIMARY KEY, ticket_id INT NOT NULL, reason VARCHAR(200) NOT NULL);\n")
    s.append(inserts(f"`{tname}`", ["id", "ticket_id", "reason"], [(1, 1, "Customer asked for a manager")],
                     sql_lit, "`"))
    t.add(E, DB, None, tname, "reason", [], negative_control=True, name_values=[p["email"]],
          name_value_classifiers=["pii.email"], normalized="*", note="table name embeds an e-mail address")
    return "".join(s)


# --------------------------------------------------------------------------------------------------
# MongoDB: database app
# --------------------------------------------------------------------------------------------------
def gen_mongo(f: Fake, t: Truth) -> str:
    E, DB = "mongodb", "app"
    people = [f.person() for _ in range(100)]
    users = []
    for i, p in enumerate(people):
        brand, card = p["card_brand"], p["card"]
        users.append({
            "_id": f"u{i + 1:04d}",
            "name": {"first": p["first"], "last": p["last"]},
            "email": p["email"], "email_verified": f.r.random() < 0.5,
            "phones": [p["phone"]] + ([f.fr_phone()] if i % 3 == 0 else []),
            "phone_country": p["country"],
            "address": {"street": p["street"], "postalCode": p["postal_code"], "city": p["city"],
                        "country": p["country"]},
            "cards": [{"brand": brand, "number": card, "holder": f"{p['first']} {p['last']}"}],
            "iban": p["iban"],
            "createdAt": f.timestamp(),
        })
    col = "users"
    t.add(E, DB, None, col, "name.first", ["pii.person_name"], [u["name"]["first"] for u in users])
    t.add(E, DB, None, col, "name.last", ["pii.person_name"], [u["name"]["last"] for u in users])
    t.add(E, DB, None, col, "email", ["pii.email"], [u["email"] for u in users])
    t.add(E, DB, None, col, "phones[]", ["pii.phone"], [x for u in users for x in u["phones"]])
    t.add(E, DB, None, col, "address.street", ["pii.postal_address"], [u["address"]["street"] for u in users])
    t.add(E, DB, None, col, "cards[].number", ["pii.card_number"], [u["cards"][0]["number"] for u in users])
    t.add(E, DB, None, col, "cards[].holder", ["pii.person_name"], [u["cards"][0]["holder"] for u in users])
    t.add(E, DB, None, col, "iban", ["pii.iban"], [u["iban"] for u in users])
    t.add(E, DB, None, col, "email_verified", [], negative_control=True)
    t.add(E, DB, None, col, "phone_country", [], negative_control=True)
    t.add(E, DB, None, col, "cards[].brand", [], negative_control=True)

    # Dynamic keys that are e-mail addresses (ADR-0009: contacts.<email>.phone -> contacts.*.phone).
    books, key_emails, book_phones, book_names = [], [], [], []
    for i in range(30):
        contacts = {}
        for _ in range(3):
            c = f.r.choice(people)
            key = f.email(c["first"], c["last"])
            ph = f.fr_phone()
            contacts[key] = {"name": f"{c['first']} {c['last']}", "phone": ph}
            key_emails.append(key)
            book_phones.append(ph)
            book_names.append(contacts[key]["name"])
        books.append({"_id": f"ab{i + 1:04d}", "owner": f"u{i + 1:04d}", "contacts": contacts})
    t.add(E, DB, None, "address_books", "contacts.<email>.phone", ["pii.phone"], book_phones,
          name_values=key_emails, name_value_classifiers=["pii.email"], normalized="contacts.*.phone",
          note="dynamic keys are e-mail addresses")
    t.add(E, DB, None, "address_books", "contacts.<email>.name", ["pii.person_name"], book_names,
          name_values=key_emails, name_value_classifiers=["pii.email"], normalized="contacts.*.name",
          note="dynamic keys are e-mail addresses")

    # Digit-only dynamic keys that are phone numbers.
    loyalty, key_phones = [], []
    for i in range(20):
        members = {}
        for _ in range(4):
            k = "33" + f.fr_phone().replace(" ", "")[1:]
            members[k] = {"points": f.r.randint(0, 5000), "tier": f.r.choice(("silver", "gold"))}
            key_phones.append(k)
        loyalty.append({"_id": f"lp{i + 1:04d}", "program": f"store-{i + 1:02d}", "members": members})
    t.add(E, DB, None, "loyalty", "members.<phone>.points", [], negative_control=True,
          name_values=key_phones, name_value_classifiers=["pii.phone"], normalized="members.*.points",
          note="digit-only dynamic keys are phone numbers (E.164 without +)")

    # Digit-only keys that are NOT values (hours of the day).
    stats = [{"_id": f"d2026-09-{d:02d}", "hourly": {str(h): f.r.randint(0, 99) for h in range(24)}}
             for d in range(1, 15)]
    t.add(E, DB, None, "daily_stats", "hourly.<hour>", [], negative_control=True,
          normalized="hourly.*", note="digit-only keys 0..23, not values")

    integrations = []
    for i, svc in enumerate(("s3-archive", "ses-mailer", "athena")):
        a, k = f.aws_key_pair()
        integrations.append({"_id": f"int{i + 1}", "service": svc,
                             "credentials": {"accessKeyId": a, "secretAccessKey": k}})
    t.add(E, DB, None, "integrations", "credentials.accessKeyId", ["secret.aws_key"],
          [x["credentials"]["accessKeyId"] for x in integrations])
    t.add(E, DB, None, "integrations", "credentials.secretAccessKey", ["secret.aws_key"],
          [x["credentials"]["secretAccessKey"] for x in integrations])

    doc = {"_generated": f"dev/seed/generate.py (seed {SEED}); FAKE data only",
           "collections": {"users": users, "address_books": books, "loyalty": loyalty,
                           "daily_stats": stats, "integrations": integrations}}
    return json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


# --------------------------------------------------------------------------------------------------
# OpenLDAP: suffix dc=example,dc=org
# --------------------------------------------------------------------------------------------------
def ssha(f: Fake, password: str) -> str:
    import base64
    salt = bytes(f.r.randrange(256) for _ in range(8))
    return "{SSHA}" + base64.b64encode(hashlib.sha1(password.encode() + salt).digest() + salt).decode()


def ldif_attr(name: str, value: str) -> str:
    if value.isascii() and not value.startswith((" ", ":", "<")):
        return f"{name}: {value}"
    import base64
    return f"{name}:: {base64.b64encode(value.encode()).decode()}"


def gen_openldap(f: Fake, t: Truth) -> str:
    E, SUFFIX = "openldap", "dc=example,dc=org"
    people = [f.person() for _ in range(80)]
    out = [f"# GENERATED by dev/seed/generate.py (seed {SEED}). FAKE data only. Do not edit by hand.",
           "# The service account cn=databastion,ou=services is added by the container entrypoint.", "",
           f"dn: {SUFFIX}", "objectClass: dcObject", "objectClass: organization", "dc: example",
           "o: Example Org (DataBastion dev)", ""]
    for ou in ("people", "teams", "groups", "services"):
        out += [f"dn: ou={ou},{SUFFIX}", "objectClass: organizationalUnit", f"ou: {ou}", ""]

    lead = people[0]
    lead_ou = f"{lead['first']} {lead['last']}"
    out += [ldif_attr("dn", f"ou={lead_ou},ou=teams,{SUFFIX}"), "objectClass: organizationalUnit",
            ldif_attr("ou", lead_ou), "description: Direct reports", ""]

    uids, mails, phones, mobiles, cns, addrs = [], [], [], [], [], []
    team_mails = []
    for i, p in enumerate(people):
        uid = f"{Fake._ascii(p['first'])[0]}{Fake._ascii(p['last'])}{i + 1:03d}"
        container = f"ou={lead_ou},ou=teams,{SUFFIX}" if 1 <= i <= 10 else f"ou=people,{SUFFIX}"
        cn = f"{p['first']} {p['last']}"
        addr = f"{p['street']}${p['postal_code']} {p['city']}"
        mobile = f.fr_phone()
        entry = [ldif_attr("dn", f"uid={uid},{container}"), "objectClass: inetOrgPerson", f"uid: {uid}",
                 ldif_attr("cn", cn), ldif_attr("sn", p["last"]), ldif_attr("givenName", p["first"]),
                 f"mail: {p['email']}", ldif_attr("telephoneNumber", p["phone"]), f"mobile: {mobile}",
                 ldif_attr("postalAddress", addr), f"employeeNumber: E{i + 1:05d}",
                 f"title: {f.r.choice(('Engineer', 'Accountant', 'Sales', 'Support'))}",
                 "description: Prefers e-mail contact over phone",
                 f"userPassword: {ssha(f, 'dev-only-user-' + uid)}", ""]
        out += entry
        uids.append(uid)
        cns.append(cn)
        addrs.append(addr)
        mobiles.append(mobile)
        phones.append(p["phone"])
        mails.append(p["email"])
        if container.startswith("ou=" + lead_ou):
            team_mails.append(p["email"])
    members = [f"member: uid={u},ou=people,{SUFFIX}" for i, u in enumerate(uids) if not 1 <= i <= 10][:15]
    out += [f"dn: cn=finance,ou=groups,{SUFFIX}", "objectClass: groupOfNames", "cn: finance", *members, ""]

    base = f"ou=people,{SUFFIX}"
    t.add(E, SUFFIX, base, "inetOrgPerson", "cn", ["pii.person_name"], cns)
    t.add(E, SUFFIX, base, "inetOrgPerson", "sn", ["pii.person_name"], [p["last"] for p in people])
    t.add(E, SUFFIX, base, "inetOrgPerson", "givenname", ["pii.person_name"], [p["first"] for p in people])
    t.add(E, SUFFIX, base, "inetOrgPerson", "mail", ["pii.email"], mails)
    t.add(E, SUFFIX, base, "inetOrgPerson", "telephonenumber", ["pii.phone"], phones)
    t.add(E, SUFFIX, base, "inetOrgPerson", "mobile", ["pii.phone"], mobiles)
    t.add(E, SUFFIX, base, "inetOrgPerson", "postaladdress", ["pii.postal_address"], addrs)
    t.add(E, SUFFIX, base, "inetOrgPerson", "employeenumber", [], negative_control=True)
    t.add(E, SUFFIX, base, "inetOrgPerson", "description", [], negative_control=True,
          note="mentions e-mail and phone as words")
    t.add(E, SUFFIX, base, "inetOrgPerson", "userpassword", [], note=(
        "SSHA hashes exist but the databastion service DN has no read access to userPassword "
        "(least privilege): expected to be invisible to Discovery"))
    t.add(E, SUFFIX, f"ou=groups,{SUFFIX}", "groupOfNames", "member", [],
          name_values=[], note="member values are entry DNs (uid=...); must be reduced per ADR-0009")
    t.add(E, SUFFIX, f"ou={lead_ou},ou=teams,{SUFFIX}", "inetOrgPerson", "mail", ["pii.email"], team_mails,
          name_values=[lead_ou], name_value_classifiers=["pii.person_name"],
          normalized=f"ou=*,ou=teams,{SUFFIX}", note="container ou= is a person name")

    # Custom schema (dev/openldap/config.ldif, cn=databastion-dev): a structural class with
    # sensitive custom attributes (phase 6: Discovery of custom attributes). Drawn last, so every
    # value above is unchanged.
    contractors = f"ou=contractors,{SUFFIX}"
    out += [f"dn: {contractors}", "objectClass: organizationalUnit", "ou: contractors", ""]
    nirs, ibans = [], []
    for i in range(20):
        sex, year, month = f.r.choice((1, 2)), f.r.randint(1955, 2002), f.r.randint(1, 12)
        nir = f.nir(sex, year, month)
        iban = f.fr_iban() if f.r.random() < 0.7 else f.de_iban()
        code = f"CTR-{f.digits(5)}"
        out += [f"dn: cn=contractor-{i + 1:03d},{contractors}", "objectClass: databastionContractor",
                f"cn: contractor-{i + 1:03d}", f"databastionContractorNir: {nir}",
                f"databastionContractorIban: {iban}", f"databastionContractorCode: {code}",
                "description: Contract record (fixed term)", ""]
        nirs.append(nir)
        ibans.append(iban)
    obj = "databastionContractor"
    t.add(E, SUFFIX, contractors, obj, "databastioncontractornir", ["pii.nir"], nirs,
          note="custom attribute (dev schema cn=databastion-dev)")
    t.add(E, SUFFIX, contractors, obj, "databastioncontractoriban", ["pii.iban"], ibans,
          note="custom attribute (dev schema cn=databastion-dev)")
    t.add(E, SUFFIX, contractors, obj, "databastioncontractorcode", [], negative_control=True,
          note="custom attribute: contract reference, not personal data")
    t.add(E, SUFFIX, contractors, obj, "cn", [], negative_control=True,
          note="record names, not person names")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------------------------------
# Apereo CAS: JSON service registry (dev/cas/services, opt-in service `cas`, ADR-0041)
# --------------------------------------------------------------------------------------------------
# Accepted users of the CAS dev service (dev/cas/config/cas.properties, `cas.authn.accept.users`;
# password CAS_DEV_USER_PASSWORD). E-mail-shaped logins, as many deployments use: their `who` in
# the audit log is classified (ADR-0041 decision 4) and always fingerprinted in events (decision 7).
CAS_USERS = ("camille.martin@example.org", "hugo.durand@example.net", "olivia.smith@example.com")
# A service account login (not personal data): the e2e can list it in `cas.clear_principals`.
CAS_SERVICE_USER = "svc-monitoring"
CAS_SERVICES = "cas/services"
CAS_CLASS = {
    "cas": "org.apereo.cas.services.CasRegisteredService",
    "saml": "org.apereo.cas.support.saml.services.SamlRegisteredService",
    "oidc": "org.apereo.cas.services.OidcRegisteredService",
}


def cas_object(name: str) -> str:
    """The Discovery object of a service name, as connector-cas reports it: ADR-0009 normalization
    keeps these names as they are (`HR-Portal`), checked against the connector's own parser."""
    return name


def cas_contacts(f: Fake, n: int, department: str) -> tuple[list, list[dict]]:
    """`contacts` in the CAS JSON form ([class, [items]]) and the people drawn."""
    people = [f.person() for _ in range(n)]
    items = [{"@class": "org.apereo.cas.services.DefaultRegisteredServiceContact",
              "name": f"{p['first']} {p['last']}", "email": p["email"], "phone": p["phone"],
              "department": department, "type": "TECHNICAL" if i == 0 else "ADMINISTRATIVE"}
             for i, p in enumerate(people)]
    return ["java.util.ArrayList", items], people


def gen_cas(f: Fake, t: Truth) -> dict[str, str]:
    """Service definitions (one file per service, `<name>-<id>.json` as CAS names them) and their
    ground-truth locations, as connector-cas reports them: database `service_registry`, schema the
    service type, object the normalized service name when every value of the location comes from
    services of that name, else `*` (values are pooled per service type and field path, ADR-0041
    decision 4), field the normalized path."""
    E, DB = "cas", "service_registry"
    services: list[dict] = []
    contacts: dict[str, list[dict]] = {}

    def add(kind: str, definition: dict, people: list[dict]) -> None:
        services.append(definition)
        contacts.setdefault(kind, []).extend(people)

    c, people = cas_contacts(f, 2, "IT")
    add("cas", {
        "@class": CAS_CLASS["cas"], "id": 1001, "name": "Intranet", "evaluationOrder": 10,
        "serviceId": "^https://intranet\\.example\\.org(/.*)?$",
        "description": "Staff intranet (DataBastion dev fixture, FAKE data)",
        "informationUrl": "https://intranet.example.org/about",
        "logoutType": "BACK_CHANNEL",
        "contacts": c,
        "attributeReleasePolicy": {
            "@class": "org.apereo.cas.services.ReturnAllowedAttributeReleasePolicy",
            "allowedAttributes": ["java.util.ArrayList", ["mail", "cn", "telephoneNumber"]]},
        "properties": {"@class": "java.util.HashMap", "costCenter": {
            "@class": "org.apereo.cas.services.DefaultRegisteredServiceProperty",
            "values": ["java.util.HashSet", ["CC-1042"]]}},
    }, people)

    # Required-attribute values: an allow-list of e-mail addresses (a small application).
    c, people = cas_contacts(f, 2, "Facilities")
    allowed = [f.email(p["first"], p["last"]) for p in (f.person() for _ in range(4))]
    # RESTful attribute release with an Authorization header: never sampled (header maps are
    # skipped whole), listed below as a value that must never reach the console.
    rest_auth = "Basic " + base64.b64encode(
        f"dev-only-badge-sync:{f.chars(B64_CHARSET, 24)}".encode()).decode()
    add("cas", {
        "@class": CAS_CLASS["cas"], "id": 1005, "name": "Badge-Sync", "evaluationOrder": 50,
        "serviceId": "^https://badges\\.example\\.org/.*",
        "description": "Badge printing; attributes released through a REST endpoint (FAKE data)",
        "contacts": c,
        "accessStrategy": {
            "@class": "org.apereo.cas.services.DefaultRegisteredServiceAccessStrategy",
            "requiredAttributes": {"@class": "java.util.HashMap",
                                   "mail": ["java.util.HashSet", allowed]}},
        "attributeReleasePolicy": {
            "@class": "org.apereo.cas.services.ReturnRestfulAttributeReleasePolicy",
            "endpoint": "https://badges.example.org/api/cas/release", "method": "POST",
            "headers": {"@class": "java.util.LinkedHashMap", "Authorization": rest_auth}},
    }, people)

    c, people = cas_contacts(f, 2, "Payroll")
    add("saml", {
        "@class": CAS_CLASS["saml"], "id": 1002, "name": "Payroll-SP", "evaluationOrder": 20,
        "serviceId": "https://payroll.example.net/shibboleth",
        "description": "Payroll service provider (FAKE data; the dev image has no SAML2 IdP module)",
        "metadataLocation": "https://payroll.example.net/Shibboleth.sso/Metadata",
        "contacts": c,
    }, people)

    # OIDC: one client secret in clear (counted as `security.client_secrets_in_clear`, never read),
    # one in the cipher executor's `{cipher}` form. Static release values: hotline numbers.
    c, people = cas_contacts(f, 2, "Human Resources")
    clear_secret = "dev-only-cas-oidc-client-secret-" + f.chars(B64_CHARSET, 24)
    hotlines = [f.fr_phone() for _ in range(3)]
    add("oidc", {
        "@class": CAS_CLASS["oidc"], "id": 1003, "name": "HR-Portal", "evaluationOrder": 30,
        "serviceId": "^https://hr\\.example\\.com/oidc/callback$",
        "clientId": "hr-portal", "clientSecret": clear_secret,
        "supportedGrantTypes": ["java.util.HashSet", ["authorization_code"]],
        "supportedResponseTypes": ["java.util.HashSet", ["code"]],
        "scopes": ["java.util.HashSet", ["openid", "profile", "email"]],
        "description": "HR portal (FAKE data; its client secret is a dev-only value in clear)",
        "contacts": c,
        "attributeReleasePolicy": {
            "@class": "org.apereo.cas.services.ReturnStaticAttributeReleasePolicy",
            "allowedAttributes": {"@class": "java.util.LinkedHashMap",
                                  "hotline": ["java.util.ArrayList", hotlines]}},
    }, people)
    c, people = cas_contacts(f, 1, "Finance")
    jwe = ".".join(["eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0", ""] +
                   [f.chars(B64_CHARSET, n) for n in (16, 48, 22)])
    encrypted_secret = "{cipher}" + jwe
    add("oidc", {
        "@class": CAS_CLASS["oidc"], "id": 1004, "name": "Expenses", "evaluationOrder": 40,
        "serviceId": "^https://expenses\\.example\\.org/oidc/callback$",
        "clientId": "expenses", "clientSecret": encrypted_secret,
        "supportedGrantTypes": ["java.util.HashSet", ["authorization_code"]],
        "supportedResponseTypes": ["java.util.HashSet", ["code"]],
        "scopes": ["java.util.HashSet", ["openid", "email"]],
        "description": "Expense reports (FAKE data; its client secret is in the {cipher} form)",
        "contacts": c,
    }, people)

    files = {f"{CAS_SERVICES}/{s['name']}-{s['id']}.json":
             json.dumps(s, ensure_ascii=False, indent=2) + "\n" for s in services}

    for kind, people in sorted(contacts.items()):
        names = {s["name"] for s in services if s["@class"] == CAS_CLASS[kind]}
        obj = cas_object(next(iter(names))) if len(names) == 1 else "*"
        note = None if obj != "*" else "values of every service of the type, pooled (ADR-0041 decision 4)"
        t.add(E, DB, kind, obj, "contacts[].name", ["pii.person_name"],
              [f"{p['first']} {p['last']}" for p in people], note=note)
        t.add(E, DB, kind, obj, "contacts[].email", ["pii.email"], [p["email"] for p in people],
              note=note)
        t.add(E, DB, kind, obj, "contacts[].phone", ["pii.phone"], [p["phone"] for p in people],
              note=note)
        t.add(E, DB, kind, obj, "contacts[].department", [], negative_control=True, note=note)
    t.add(E, DB, "cas", cas_object("Badge-Sync"), "access_strategy.required_attributes.*[]",
          ["pii.email"], allowed, note="required-attribute values (an e-mail allow-list)")
    t.add(E, DB, "oidc", cas_object("HR-Portal"), "attribute_release_policy.allowed_attributes.*[]",
          ["pii.phone"], hotlines, note="static attribute release values")
    t.add(E, DB, "cas", cas_object("Intranet"), "attribute_release_policy.allowed_attributes[]", [],
          negative_control=True, note="attribute names, not values")
    t.add(E, DB, "cas", cas_object("Intranet"), "properties.*.values[]", [], negative_control=True,
          note="cost center code")
    # Credentials: never sampled, masked nor fingerprinted (ADR-0041 decision 4); listed so that
    # the I2 checks search for them (none may reach the console, the agent logs or the spool).
    t.add(E, DB, "oidc", cas_object("HR-Portal"), "client_secret", [], [clear_secret],
          never_sampled=True, note="OIDC client secret in clear: never sampled; counted as "
          "security.client_secrets_in_clear")
    t.add(E, DB, "oidc", cas_object("Expenses"), "client_secret", [], [encrypted_secret],
          never_sampled=True, note="OIDC client secret in the {cipher} form: never sampled")
    t.add(E, DB, "cas", cas_object("Badge-Sync"), "attribute_release_policy.headers.authorization",
          [], [rest_auth], never_sampled=True,
          note="Authorization header of the RESTful release policy: never sampled")
    # The audit log (decision 4): the `who` of successful authentications. Records exist once a
    # user logged in (dev/cas/smoke.sh, the e2e scenario); the service account is not personal.
    t.add(E, "audit_trail", None, "audit_log", "who", ["pii.email"], list(CAS_USERS),
          note="logins of the accepted users (cas.authn.accept.users); present once they logged in")
    return files


# --------------------------------------------------------------------------------------------------
def build(seed: int = SEED) -> dict[str, str]:
    f = Fake(seed)
    t = Truth()
    files = {
        "seed/out/postgres.sql": gen_postgres(f, t),
        "seed/out/mysql.sql": gen_mysql(f, t),
        "seed/out/mariadb.sql": gen_mariadb(f, t),
        "seed/out/mongo.json": gen_mongo(f, t),
        "seed/out/openldap.ldif": gen_openldap(f, t),
    }
    # Own random stream: the outputs above stay byte-identical.
    files.update(gen_cas(Fake(seed + 41), t))
    truth = {
        "version": 1,
        "generator": "dev/seed/generate.py",
        "seed": seed,
        "notes": [
            "FAKE data only. Regenerate with `make seed`; never edit by hand.",
            "Classifier ids are provisional until the classifier set is frozen in P2-A.",
            "A (database, container, object, field) not listed here is expected to produce no finding.",
            "negative_control: the location looks sensitive (name or shape) but holds no sensitive data.",
            "name_contains_value: the object, container or key names embed values (ADR-0009, security "
            "review M2). name_values must never reach the console (invariant I2 test, P2-E).",
            "expected_normalized_name: name expected on the uplink after normalization (ADR-0009).",
            "values: every distinct seeded value of the location; none may appear in clear text in the "
            "console database (P2-E).",
            "MySQL / MariaDB: Discovery excludes the system schemas mysql, information_schema, "
            "performance_schema and sys (docs/05-security.md).",
            "never_sampled: a credential (CAS client secret, Authorization header) the connector "
            "never samples, masks nor fingerprints; expects no classifier, and its values must "
            "never reach the console, the agent logs or the spool (ADR-0041 decision 14).",
            "cas: locations as connector-cas reports them (ADR-0041 decision 4); the registry is "
            "dev/cas/services, the audit log dev/.state/logs/cas/cas_audit.log.",
        ],
        "targets": {
            "postgresql": {"service": "postgres", "databases": ["shop"]},
            "mysql": {"service": "mysql", "databases": ["hr"]},
            "mariadb": {"service": "mariadb", "databases": ["support"]},
            "mongodb": {"service": "mongo", "databases": ["app"]},
            "openldap": {"service": "openldap", "databases": ["dc=example,dc=org"]},
            "cas": {"service": "cas", "databases": ["service_registry", "audit_trail"]},
        },
        "locations": t.locations,
    }
    files["ground-truth.json"] = json.dumps(truth, ensure_ascii=False, indent=1, sort_keys=True) + "\n"
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if committed outputs are out of date")
    args = ap.parse_args()
    files = build()
    stale = []
    for rel, content in files.items():
        path = DEV_DIR / rel
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(rel)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    if stale:
        print("out of date (run `make seed`): " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
