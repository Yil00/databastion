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
- ``dev/seed/out/sqlserver.sql`` SQL Server database ``retail`` (opt-in service ``sqlserver``)
- ``dev/seed/out/redis.txt``     Redis / Valkey keyspace, databases 0 and 1 (opt-in profile ``redis``)
- ``dev/seed/out/sqlite-*.sql``  SQLite files ``crm.db``, ``app.db``, ``intl.db`` and their manifest
                                 ``sqlite.json`` (built by ``dev/sqlite/build.py``, opt-in profile ``sqlite``)
- ``dev/seed/out/firebird.sql``  Firebird database ``crm`` (opt-in profile ``firebird``)
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
            never_sampled: bool = False, file: str | None = None,
            requires: str | None = None) -> None:
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
        if file:
            loc["file"] = file
        if requires:
            loc["requires"] = requires
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
        # `client_credentials`: the e2e CAS scenario's token-only grant (ADR-0044).
        "supportedGrantTypes": ["java.util.HashSet", ["authorization_code", "client_credentials"]],
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
# Microsoft SQL Server: database retail (opt-in service `sqlserver`, ADR-0051 decision 9)
# --------------------------------------------------------------------------------------------------
def mssql_lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return str(v)
    return "N'" + str(v).replace("'", "''") + "'"


def gen_sqlserver(f: Fake, t: Truth) -> str:
    """T-SQL run by sqlcmd as `sa` in the container (dev/sqlserver/entrypoint.sh), batches split by
    GO. Schemas `crm` and `finance` hold the PII; the fixtures of ADR-0051 decision 9 (masked
    column, Always Encrypted column with a fake key, temporal table, row-level security, computed
    column calling a function, synonym to a linked server on an unresolvable `.invalid` host, CAS
    JPA ticket table, value-bearing table name) are seeded next to them. The agent account and the
    audit setup are in dev/sqlserver/initdb/."""
    E, DB = "sqlserver", "retail"
    people = [f.person() for _ in range(100)]
    s = [HEADER.format(seed=SEED), "SET NOCOUNT ON;\nGO\nCREATE DATABASE retail;\nGO\nUSE retail;\nGO\n"]
    for schema in ("crm", "finance", "cas", "security"):
        s.append(f"CREATE SCHEMA {schema};\nGO\n")

    s.append("""CREATE TABLE crm.customers (
  id int PRIMARY KEY, first_name nvarchar(60) NOT NULL, last_name nvarchar(60) NOT NULL,
  email nvarchar(160) NOT NULL, phone nvarchar(32) NULL, birth_date date NULL, street nvarchar(200) NULL,
  postal_code nvarchar(16) NULL, city nvarchar(80) NULL, country_code char(2) NULL, nir varchar(32) NULL,
  secondary_email nvarchar(160) MASKED WITH (FUNCTION = 'email()') NULL,
  email_opt_in bit NOT NULL, created_at datetime2(0) NOT NULL
);
""")
    rows = []
    for i, p in enumerate(people):
        rows.append((i + 1, p["first"], p["last"], p["email"], p["phone"], p["birth_date"], p["street"],
                     p["postal_code"], p["city"], p["country"], p["nir"],
                     f.email(p["first"], p["last"]), f.r.random() < 0.5, f.timestamp()[:19].replace("T", " ")))
    s.append(inserts("crm.customers", ["id", "first_name", "last_name", "email", "phone", "birth_date",
                                       "street", "postal_code", "city", "country_code", "nir",
                                       "secondary_email", "email_opt_in", "created_at"], rows, mssql_lit, ""))
    s.append("GO\n")
    c = ("crm", "customers")
    t.add(E, DB, *c, "first_name", ["pii.person_name"], [r[1] for r in rows])
    t.add(E, DB, *c, "last_name", ["pii.person_name"], [r[2] for r in rows])
    t.add(E, DB, *c, "email", ["pii.email"], [r[3] for r in rows])
    t.add(E, DB, *c, "phone", ["pii.phone"], [r[4] for r in rows])
    t.add(E, DB, *c, "birth_date", ["pii.birth_date"], [r[5] for r in rows])
    t.add(E, DB, *c, "street", ["pii.postal_address"], [r[6] for r in rows])
    t.add(E, DB, *c, "nir", ["pii.nir"], [r[10] for r in rows])
    t.add(E, DB, *c, "secondary_email", [], note=(
        "dynamic data masking (email()): the agent's account has no UNMASK and reads the masked form; "
        "counted in coverage.masked_columns, a finding is not expected"))
    t.add(E, DB, *c, "email_opt_in", [], negative_control=True, note="bit; name looks sensitive")
    t.add(E, DB, *c, "created_at", [], negative_control=True, note="timestamp, not a birth date")

    notes, note_emails, note_phones = [], [], []
    for i in range(40):
        p = f.r.choice(people)
        ph, em = f.fr_phone(), f.email(p["first"], p["last"])
        note_phones.append(ph)
        note_emails.append(em)
        notes.append((i + 1, people.index(p) + 1, f"Customer called from {ph} and asked to use {em} for invoices."))
    s.append("CREATE TABLE crm.customer_notes (id int PRIMARY KEY, customer_id int NOT NULL, note nvarchar(max) NOT NULL);\n")
    s.append(inserts("crm.customer_notes", ["id", "customer_id", "note"], notes, mssql_lit, ""))
    s.append("GO\n")
    t.add(E, DB, "crm", "customer_notes", "note", ["pii.email", "pii.phone"], note_emails + note_phones,
          note="free text (nvarchar(max)); values are embedded tokens")

    # A computed column calling a scalar function (user code on read): never sampled.
    s.append("""CREATE FUNCTION finance.fn_iban_prefix (@iban nvarchar(42)) RETURNS nvarchar(8)
WITH SCHEMABINDING AS BEGIN RETURN LEFT(@iban, 4) + N'****'; END;
GO
CREATE TABLE finance.payment_cards (
  id int PRIMARY KEY, customer_id int NOT NULL, card_brand varchar(16) NOT NULL, card_number varchar(24) NOT NULL,
  card_holder nvarchar(120) NOT NULL, iban varchar(42) NOT NULL, tracking_ref varchar(16) NOT NULL,
  iban_prefix AS finance.fn_iban_prefix(iban)
);
""")
    rows = []
    for i, p in enumerate(people[:80]):
        rows.append((i + 1, i + 1, p["card_brand"], p["card"], f"{p['first']} {p['last']}".upper(), p["iban"],
                     f.not_luhn(16)))
    s.append(inserts("finance.payment_cards", ["id", "customer_id", "card_brand", "card_number", "card_holder",
                                               "iban", "tracking_ref"], rows, mssql_lit, ""))
    s.append("GO\n")
    c = ("finance", "payment_cards")
    t.add(E, DB, *c, "card_number", ["pii.card_number"], [r[3] for r in rows])
    t.add(E, DB, *c, "card_holder", ["pii.person_name"], [r[4] for r in rows])
    t.add(E, DB, *c, "iban", ["pii.iban"], [r[5] for r in rows])
    t.add(E, DB, *c, "card_brand", [], negative_control=True, note="brand name, not a card number")
    t.add(E, DB, *c, "tracking_ref", [], negative_control=True, note="16-digit numbers that FAIL the Luhn check")
    t.add(E, DB, *c, "iban_prefix", [], note=(
        "computed column calling finance.fn_iban_prefix (user code on read): never sampled, "
        "coverage.computed_columns_not_sampled"))

    # A system-versioned temporal table: the history table holds the values before the update.
    s.append("""CREATE TABLE finance.salaries (
  employee_id int PRIMARY KEY, employee_email nvarchar(160) NOT NULL, salary_eur int NOT NULL,
  valid_from datetime2 GENERATED ALWAYS AS ROW START NOT NULL,
  valid_to datetime2 GENERATED ALWAYS AS ROW END NOT NULL,
  PERIOD FOR SYSTEM_TIME (valid_from, valid_to)
) WITH (SYSTEM_VERSIONING = ON (HISTORY_TABLE = finance.salaries_history));
""")
    staff = [f.person() for _ in range(30)]
    rows = [(i + 1, p["email"], f.r.randint(28000, 95000)) for i, p in enumerate(staff)]
    s.append(inserts("finance.salaries", ["employee_id", "employee_email", "salary_eur"], rows, mssql_lit, ""))
    s.append("GO\nUPDATE finance.salaries SET salary_eur = salary_eur + 1000;\nGO\n")
    t.add(E, DB, "finance", "salaries", "employee_email", ["pii.email"], [r[1] for r in rows])
    t.add(E, DB, "finance", "salaries", "salary_eur", [], negative_control=True)
    t.add(E, DB, "finance", "salaries_history", "employee_email", ["pii.email"], [r[1] for r in rows],
          note="history table of the temporal table finance.salaries (rows from the seed's UPDATE)")

    # Row-level security: the predicate is user code; the table is skipped.
    s.append("""CREATE TABLE crm.regional_contacts (id int PRIMARY KEY, region char(2) NOT NULL, contact_email nvarchar(160) NOT NULL);
""")
    rows = [(i + 1, f.r.choice(("FR", "GB", "DE")), f.person()["email"]) for i in range(20)]
    s.append(inserts("crm.regional_contacts", ["id", "region", "contact_email"], rows, mssql_lit, ""))
    s.append("""GO
CREATE FUNCTION security.fn_region_predicate (@region char(2)) RETURNS TABLE WITH SCHEMABINDING AS
RETURN SELECT 1 AS allowed WHERE @region = 'FR' OR USER_NAME() = N'dbo';
GO
CREATE SECURITY POLICY security.regional_contacts_policy
  ADD FILTER PREDICATE security.fn_region_predicate(region) ON crm.regional_contacts WITH (STATE = ON);
GO
""")
    t.add(E, DB, "crm", "regional_contacts", "contact_email", [], note=(
        "row-level security (security.regional_contacts_policy): skipped, skipped_row_level_security / "
        "coverage.relations_rls_skipped"))

    # Always Encrypted with a fake column master key (no key material: nothing can decrypt it).
    s.append("""CREATE COLUMN MASTER KEY dev_only_cmk WITH (
  KEY_STORE_PROVIDER_NAME = N'MSSQL_JAVA_KEYSTORE', KEY_PATH = N'dev-only-fake-keystore/dev-only-cmk');
GO
CREATE COLUMN ENCRYPTION KEY dev_only_cek WITH VALUES (
  COLUMN_MASTER_KEY = dev_only_cmk, ALGORITHM = 'RSA_OAEP',
  ENCRYPTED_VALUE = 0x01700000016400650076002D006F006E006C0079);
GO
CREATE TABLE crm.patients_ae (
  id int PRIMARY KEY,
  nir varchar(32) COLLATE Latin1_General_BIN2 ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = dev_only_cek,
    ENCRYPTION_TYPE = DETERMINISTIC, ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256') NULL
);
GO
""")
    t.add(E, DB, "crm", "patients_ae", "nir", [], note=(
        "Always Encrypted column with a fake key, no rows: never sampled, coverage.encrypted_columns"))

    # A linked server on an unresolvable host and a synonym to it: never read (I5).
    s.append("""EXEC master.dbo.sp_addlinkedserver @server = N'DEV_ARCHIVE', @srvproduct = N'',
  @provider = N'MSOLEDBSQL', @datasrc = N'archive.invalid';
GO
CREATE SYNONYM crm.archived_customers FOR DEV_ARCHIVE.retail.crm.customers;
GO
""")
    t.add(E, DB, "crm", "archived_customers", None, [], note=(
        "synonym to the linked server DEV_ARCHIVE (archive.invalid): never read (I5), never sampled"))

    # CAS JPA ticket registry shape (ADR-0041 decisions 5 and 6): counted per type, never sampled.
    s.append("""CREATE TABLE cas.cas_tickets (
  id nvarchar(768) PRIMARY KEY, type nvarchar(255) NOT NULL, body nvarchar(max) NULL, parent_id nvarchar(768) NULL,
  principal_id nvarchar(768) NULL, service nvarchar(max) NULL, attributes nvarchar(max) NULL,
  creation_time datetime2 NOT NULL, expiration_time datetime2 NULL, last_used_time datetime2 NULL
);
""")
    tickets = []
    for i in range(6):
        kind = ("TGT", "org.apereo.cas.ticket.TicketGrantingTicketImpl") if i % 2 == 0 else \
            ("ST", "org.apereo.cas.ticket.ServiceTicketImpl")
        tid = f"{kind[0]}-{i + 1}-dev-only-{f.chars(B64_CHARSET, 24)}"
        tickets.append((tid, kind[1], "{}", None, f.person()["email"], None, None,
                        f"2026-09-{i + 1:02d} 10:00:00", None, None))
    s.append(inserts("cas.cas_tickets", ["id", "type", "body", "parent_id", "principal_id", "service",
                                         "attributes", "creation_time", "expiration_time", "last_used_time"],
                     tickets, mssql_lit, ""))
    s.append("GO\n")
    t.add(E, DB, "cas", "cas_tickets", "id", [], [r[0] for r in tickets], never_sampled=True,
          note="CAS ticket registry (ADR-0041): counted per type, never sampled; the agent holds SELECT "
               "on type, creation_time and expiration_time only")
    t.add(E, DB, "cas", "cas_tickets", "principal_id", [], [r[4] for r in tickets], never_sampled=True,
          note="CAS ticket registry: not readable by the agent's account")

    # Secrets.
    s.append("""CREATE TABLE finance.app_credentials (
  id int PRIMARY KEY, service varchar(32) NOT NULL, aws_access_key_id varchar(32) NOT NULL,
  aws_secret_access_key varchar(64) NOT NULL, owner_email nvarchar(160) NOT NULL
);
""")
    rows = []
    for i, svc in enumerate(("erp-export", "warehouse-sync", "backup")):
        a, k = f.aws_key_pair()
        rows.append((i + 1, svc, a, k, f.r.choice(people)["email"]))
    s.append(inserts("finance.app_credentials", ["id", "service", "aws_access_key_id", "aws_secret_access_key",
                                                 "owner_email"], rows, mssql_lit, ""))
    s.append("GO\n")
    c = ("finance", "app_credentials")
    t.add(E, DB, *c, "aws_access_key_id", ["secret.aws_key"], [r[2] for r in rows])
    t.add(E, DB, *c, "aws_secret_access_key", ["secret.aws_key"], [r[3] for r in rows])
    t.add(E, DB, *c, "owner_email", ["pii.email"], [r[4] for r in rows])
    t.add(E, DB, *c, "service", [], negative_control=True)

    # Invoices: only look-alikes.
    s.append("CREATE TABLE finance.invoices (id int PRIMARY KEY, invoice_number varchar(20) NOT NULL, "
             "amount_cents int NOT NULL, email_template_id int NOT NULL);\n")
    rows = [(i + 1, f"INV-2026-{i + 1:06d}", f.r.randint(500, 250000), f.r.randint(1, 9)) for i in range(100)]
    s.append(inserts("finance.invoices", ["id", "invoice_number", "amount_cents", "email_template_id"], rows,
                     mssql_lit, ""))
    s.append("GO\n")
    for col in ("invoice_number", "amount_cents", "email_template_id"):
        t.add(E, DB, "finance", "invoices", col, [], negative_control=True)

    # Value-bearing table name: an e-mail address in a bracketed name.
    p = people[2]
    tname = f"export_{p['email']}"
    s.append(f"CREATE TABLE crm.[{tname}] (id int PRIMARY KEY, phone nvarchar(32) NOT NULL);\n")
    s.append(inserts(f"crm.[{tname}]", ["id", "phone"], [(1, p["phone"])], mssql_lit, ""))
    s.append("GO\n")
    t.add(E, DB, "crm", tname, "phone", ["pii.phone"], [p["phone"]], name_values=[p["email"]],
          name_value_classifiers=["pii.email"], normalized="*", note="table name embeds an e-mail address")
    return "".join(s)


# --------------------------------------------------------------------------------------------------
# Redis and Valkey: one keyspace (opt-in profile `redis`, ADR-0052 decision 13)
# --------------------------------------------------------------------------------------------------
REDIS_ENGINES = ("valkey", "redis")
# Read patterns of the second ACL user `databastion_scoped` (dev/redis/entrypoint.sh), declared in
# agent.yaml as `redis.key_patterns` (ADR-0052 decision 4: narrowed patterns, H3 tests).
REDIS_SCOPED_PATTERNS = ("customer:*", "user:*")


def redis_arg(v) -> str:
    """One argument in the line syntax redis-cli / valkey-cli reads from stdin (sdssplitargs)."""
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def gen_redis(f: Fake, t: Truth) -> str:
    """Commands loaded by the admin user with `valkey-cli` / `redis-cli` (dev/redis/entrypoint.sh),
    one per line. Locations follow ADR-0052 decision 7: database `db<index>`, container the Redis
    type, object the expected key pattern, field `value`, the hash or stream field, `*` for a hash
    keyed by data, `#key` / `#field` for values found in names. Listed once per engine (both
    services load the same file)."""
    cmds: list[list] = []
    locs: list[tuple] = []

    def loc(db: str, typ: str, pattern: str, field: str | None, classifiers: list[str], values=None, **kw):
        locs.append((db, typ, pattern, field, classifiers, values, kw))

    cmds.append(["SELECT", "0"])
    # Strings whose key holds a record id (user:42:email -> customer:*:email).
    people = [f.person() for _ in range(40)]
    for i, p in enumerate(people):
        cmds.append(["SET", f"customer:{1000 + i}:email", p["email"]])
    loc("db0", "string", "customer:*:email", "value", ["pii.email"], [p["email"] for p in people])

    # Hashes whose key embeds an e-mail address (the I2 check on key names).
    people = [f.person() for _ in range(30)]
    for p in people:
        cmds.append(["HSET", f"user:{p['email']}:profile", "first_name", p["first"], "last_name", p["last"],
                     "phone", p["phone"], "iban", p["iban"], "plan", f.r.choice(("free", "pro"))])
    emails = [p["email"] for p in people]
    kw = dict(name_values=emails, name_value_classifiers=["pii.email"], normalized="user:*:profile",
              note="key names embed e-mail addresses")
    loc("db0", "hash", "user:*:profile", "first_name", ["pii.person_name"], [p["first"] for p in people], **kw)
    loc("db0", "hash", "user:*:profile", "last_name", ["pii.person_name"], [p["last"] for p in people], **kw)
    loc("db0", "hash", "user:*:profile", "phone", ["pii.phone"], [p["phone"] for p in people], **kw)
    loc("db0", "hash", "user:*:profile", "iban", ["pii.iban"], [p["iban"] for p in people], **kw)
    loc("db0", "hash", "user:*:profile", "#key", ["pii.email"], emails, **kw)
    loc("db0", "hash", "user:*:profile", "plan", [], negative_control=True)

    # Digit-only key segments that are phone numbers (E.164 without +).
    phones, names = [], []
    for _ in range(25):
        p = f.person()
        k = "33" + f.fr_phone().replace(" ", "")[1:]
        phones.append(k)
        names.append(f"{p['first']} {p['last']}")
        cmds.append(["SET", f"phone:{k}", names[-1]])
    loc("db0", "string", "phone:*", "value", ["pii.person_name"], names, name_values=phones,
        name_value_classifiers=["pii.phone"], normalized="*:*",
        note="key names are phone numbers; `phone` and `addressbook` precede the same suffix `*`, so the "
             "record-id rule masks the first segment too (ADR-0052 decision 7)")

    # Hashes keyed by data: field names are e-mail addresses, values phone numbers.
    field_emails, field_phones = [], []
    for i in range(10):
        args = ["HSET", f"addressbook:{i + 1}"]
        for _ in range(3):
            p = f.person()
            em, ph = f.email(p["first"], p["last"]), f.fr_phone()
            args += [em, ph]
            field_emails.append(em)
            field_phones.append(ph)
        cmds.append(args)
    kw = dict(name_values=field_emails, name_value_classifiers=["pii.email"], normalized="*:*",
              note="hash field names are e-mail addresses; first segment masked as for `phone:*`")
    loc("db0", "hash", "addressbook:*", "*", ["pii.phone"], field_phones, **kw)
    loc("db0", "hash", "addressbook:*", "#field", ["pii.email"], field_emails, **kw)

    # A set, a sorted set, a list and a stream.
    subs = [f.person()["email"] for _ in range(60)]
    cmds.append(["SADD", "newsletter:subscribers", *subs])
    # Two-segment names share the first position with `phone:<n>` and `addressbook:<n>`: once
    # that position collapses (record-id rule), `*:subscribers`, `*:leaderboard` and
    # `*:payments` are records too (ADR-0052 decision 7 as written; over-masking accepted).
    two = dict(normalized="*:*")
    loc("db0", "set", "newsletter:subscribers", "value", ["pii.email"], subs, **two)
    board = [f"{p['first']} {p['last']}" for p in (f.person() for _ in range(40))]
    args = ["ZADD", "loyalty:leaderboard"]
    for name in board:
        args += [str(f.r.randint(0, 5000)), name]
    cmds.append(args)
    loc("db0", "zset", "loyalty:leaderboard", "value", ["pii.person_name"], board,
        note="members only; scores are not read", **two)
    sms = []
    for _ in range(30):
        ph = f.fr_phone()
        sms.append(ph)
        cmds.append(["RPUSH", "queue:sms_outbox", json.dumps({"to": ph, "body": f"Your code is {f.digits(6)}"})])
    loc("db0", "list", "queue:sms_outbox", "value", ["pii.phone"], sms, note="JSON strings; phones embedded")
    cards, ibans = [], []
    for _ in range(30):
        p = f.person()
        cards.append(p["card"])
        ibans.append(p["iban"])
        cmds.append(["XADD", "events:payments", "*", "card_number", p["card"], "iban", p["iban"],
                     "amount_cents", str(f.r.randint(500, 90000))])
    loc("db0", "stream", "events:payments", "card_number", ["pii.card_number"], cards, **two)
    loc("db0", "stream", "events:payments", "iban", ["pii.iban"], ibans, **two)
    loc("db0", "stream", "events:payments", "amount_cents", [], negative_control=True, **two)

    # Secrets.
    a, k = f.aws_key_pair()
    cmds.append(["SET", "integration:s3:access_key_id", a])
    cmds.append(["SET", "integration:s3:secret_access_key", k])
    # `s3` holds a digit: a value by the per-key rules (ADR-0052 decision 7).
    loc("db0", "string", "integration:s3:access_key_id", "value", ["secret.aws_key"], [a],
        normalized="integration:*:access_key_id")
    loc("db0", "string", "integration:s3:secret_access_key", "value", ["secret.aws_key"], [k],
        normalized="integration:*:secret_access_key")

    # Look-alikes: many fixed names under one prefix (cardinality collapse), counters, flags.
    for slug in ("home", "about", "contact", "pricing", "faq", "careers", "press", "blog", "terms",
                 "privacy", "cookies", "support", "status", "partners", "shipping", "returns", "gifts"):
        cmds.append(["SET", f"cache:page:{slug}", f"<p>Rendered page {slug} (phone and e-mail support)</p>"])
    loc("db0", "string", "cache:page:*", "value", [], negative_control=True,
        note="17 fixed page names: collapsed by cardinality; text mentions e-mail and phone as words")
    for d in range(1, 15):
        cmds.append(["SET", f"stats:visits:2026-09-{d:02d}", str(f.r.randint(100, 9999))])
    loc("db0", "string", "stats:visits:*", "value", [], negative_control=True, note="dates in names, counters")
    cmds.append(["HSET", "feature:flags", "email_digest", "on", "phone_login", "off", "iban_check", "on"])
    loc("db0", "hash", "feature:flags", "email_digest", [], negative_control=True, note="name looks sensitive")

    # CAS ticket-id shapes in key names (ADR-0052 decision 6, CAS store guard): never read.
    tickets = [f"TGT-{i + 1}-dev-only-{f.chars(B64_CHARSET, 20)}" for i in range(3)]
    for tid in tickets:
        cmds.append(["SET", f"sso:{tid}", f"dev-only-ticket-body-{f.chars(B64_CHARSET, 12)}"])
    loc("db0", "string", "sso:*", "value", [], tickets, never_sampled=True,
        note="key names hold CAS ticket ids: never read, never reported, counted in coverage.cas_guard_tripped")

    # db1: session hashes under a high-entropy key segment.
    cmds.append(["SELECT", "1"])
    sess = []
    for _ in range(20):
        p = f.person()
        sess.append(p["email"])
        cmds.append(["HSET", f"session:{f.chars('0123456789abcdef', 32)}", "email", p["email"],
                     "user_agent", "Mozilla/5.0 (X11; Linux x86_64)"])
    loc("db1", "hash", "session:*", "email", ["pii.email"], sess)
    loc("db1", "hash", "session:*", "user_agent", [], negative_control=True)

    for engine in REDIS_ENGINES:
        for db, typ, pattern, field, classifiers, values, kw in locs:
            t.add(engine, db, typ, pattern, field, classifiers, values, **kw)
    head = [f"# GENERATED by dev/seed/generate.py (seed {SEED}). FAKE data only. Do not edit by hand."]
    # The CLI reads commands, not comments: the header is stripped by dev/redis/entrypoint.sh.
    return "\n".join(head + [" ".join(redis_arg(a) for a in c) for c in cmds]) + "\n"


# --------------------------------------------------------------------------------------------------
# SQLite: three database files (opt-in profile `sqlite`, ADR-0059 decision 10)
# --------------------------------------------------------------------------------------------------
# (file, dev target id, journal mode, text encoding, agent.yaml `sqlite.rollback_mode`). The binary
# files are never committed: dev/sqlite/build.py writes them from the committed SQL below with the
# SQLite of the Python that runs it (dev/.state/sqlite in dev, a volume in e2e, the engine matrix's
# writers), so the same content can be written by several SQLite versions, journal modes and page
# sizes.
SQLITE_FILES = (
    ("crm.db", "sqlite-crm", "delete", "UTF-8", "read"),
    ("app.db", "sqlite-app", "wal", "UTF-8", "skip"),
    ("intl.db", "sqlite-intl", "delete", "UTF-16le", "read"),
)
# Statements between these markers need a module that a writer may lack (the agent's bundled
# library compiles FTS5 out, ADR-0059 decision 1): dev/sqlite/build.py fails without it unless told
# to leave the block out, and the locations it creates are marked `requires` in the ground truth.
SQLITE_REQUIRES = "-- databastion:requires {module}\n"
SQLITE_REQUIRES_END = "-- databastion:end\n"
# Length of the filler that makes a value longer than the 64 KiB the connector samples.
SQLITE_LONG_FILLER = 70_000


def sqlite_lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def sqlite_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def gen_sqlite(f: Fake, t: Truth) -> dict[str, str]:
    """One SQL script per file, run by dev/sqlite/build.py after the file's page size, `auto_vacuum`,
    text encoding and journal mode are set; and the manifest sqlite.json. Locations: database
    `main` (one database per file, ADR-0059 decision 6), no container, `file` the database file
    (one dev target per file). The decision 10 fixtures: rowid, `WITHOUT ROWID` and `STRICT`
    tables; personal data in TEXT and INTEGER columns; value-bearing table and column names; a
    view; `VIRTUAL` and `STORED` generated columns; an FTS5 table whose content is in its shadow
    table; a BLOB holding a value as bytes; a value above 64 KiB; a UTF-16 file."""
    E, DB = "sqlite", "main"
    out: dict[str, str] = {}

    def add(file: str, obj: str, field: str | None, classifiers: list[str], values=None, **kw) -> None:
        t.add(E, DB, None, obj, field, classifiers, values, file=file, **kw)

    def ins(table: str, cols: list[str], rows: list[tuple]) -> str:
        return inserts(table, cols, rows, sqlite_lit, '"')

    # ---------------------------------------------------------------- crm.db (rollback journal)
    F = "crm.db"
    people = [f.person() for _ in range(80)]
    s = [HEADER.format(seed=SEED)]
    s.append("""CREATE TABLE customers (
  id INTEGER PRIMARY KEY, first_name TEXT NOT NULL, last_name TEXT NOT NULL, email TEXT NOT NULL,
  phone TEXT, birth_date TEXT, nir TEXT, contact_card BLOB, email_opt_in INTEGER NOT NULL,
  loyalty_points INTEGER NOT NULL,
  email_lower TEXT GENERATED ALWAYS AS (lower(email)) STORED,
  email_upper TEXT GENERATED ALWAYS AS (upper(email)) VIRTUAL
);
CREATE INDEX customers_email ON customers (email);
""")
    cards = [f.email(p["first"], p["last"]) for p in people[:20]]
    rows = [(i + 1, p["first"], p["last"], p["email"], p["phone"], p["birth_date"], p["nir"],
             f.r.random() < 0.5, f.r.randint(0, 5000)) for i, p in enumerate(people)]
    s.append(ins("customers", ["id", "first_name", "last_name", "email", "phone", "birth_date", "nir",
                               "email_opt_in", "loyalty_points"], rows))
    # BLOB values: the bytes of an e-mail address. The connector samples TEXT and INTEGER values only.
    for i, em in enumerate(cards):
        s.append(f"UPDATE customers SET contact_card = CAST({sqlite_lit(em)} AS BLOB) WHERE id = {i + 1};\n")
    add(F, "customers", "first_name", ["pii.person_name"], [r[1] for r in rows])
    add(F, "customers", "last_name", ["pii.person_name"], [r[2] for r in rows])
    add(F, "customers", "email", ["pii.email"], [r[3] for r in rows])
    add(F, "customers", "phone", ["pii.phone"], [r[4] for r in rows])
    add(F, "customers", "birth_date", ["pii.birth_date"], [r[5] for r in rows])
    add(F, "customers", "nir", ["pii.nir"], [r[6] for r in rows])
    add(F, "customers", "email_lower", ["pii.email"], [r[3].lower() for r in rows],
        note="STORED generated column: stored in the record, sampled")
    add(F, "customers", "email_upper", [], note="VIRTUAL generated column (computed on read): not sampled, "
        "counted as a computed column")
    add(F, "customers", "contact_card", [], cards, never_sampled=True,
        note="BLOB holding e-mail addresses as bytes: BLOB values are not sampled (expected: not found)")
    add(F, "customers", "email_opt_in", [], negative_control=True, note="0 / 1 flag; name looks sensitive")
    add(F, "customers", "loyalty_points", [], negative_control=True)

    # A STRICT table: card numbers and phone numbers in INTEGER columns.
    s.append("""CREATE TABLE payment_cards (
  id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL, card_number INTEGER NOT NULL,
  card_holder TEXT NOT NULL, phone INTEGER NOT NULL, tracking_ref INTEGER NOT NULL
) STRICT;
""")
    rows = []
    for i, p in enumerate(people[:60]):
        phone = int("33" + f.fr_phone().replace(" ", "")[1:])
        rows.append((i + 1, i + 1, int(p["card"].replace(" ", "")), f"{p['first']} {p['last']}", phone,
                     int(f.not_luhn(16))))
    s.append(ins("payment_cards", ["id", "customer_id", "card_number", "card_holder", "phone", "tracking_ref"],
                 rows))
    add(F, "payment_cards", "card_number", ["pii.card_number"], [str(r[2]) for r in rows],
        note="INTEGER column")
    add(F, "payment_cards", "card_holder", ["pii.person_name"], [r[3] for r in rows])
    add(F, "payment_cards", "phone", ["pii.phone"], [str(r[4]) for r in rows],
        note="INTEGER column: E.164 digits without `+`")
    add(F, "payment_cards", "tracking_ref", [], negative_control=True,
        note="16-digit INTEGER values that FAIL the Luhn check")

    # A WITHOUT ROWID table.
    s.append("""CREATE TABLE iban_accounts (
  iban TEXT PRIMARY KEY, holder_email TEXT NOT NULL, opened_on TEXT NOT NULL
) WITHOUT ROWID;
""")
    rows = [(p["iban"], f.email(p["first"], p["last"]), f.date(2015, 2026)) for p in people[:50]]
    s.append(ins("iban_accounts", ["iban", "holder_email", "opened_on"], rows))
    add(F, "iban_accounts", "iban", ["pii.iban"], [r[0] for r in rows], note="WITHOUT ROWID table")
    add(F, "iban_accounts", "holder_email", ["pii.email"], [r[1] for r in rows], note="WITHOUT ROWID table")
    add(F, "iban_accounts", "opened_on", [], negative_control=True, note="dates, not birth dates")

    # A view: never read (its rows are its tables' rows).
    s.append("CREATE VIEW v_customer_contacts AS SELECT email, phone FROM customers;\n")
    add(F, "v_customer_contacts", "email", [], note="view: never read")

    # Value-bearing names: a table named after an e-mail address, a column named after another one.
    p = people[3]
    tname = f"export_{p['email']}"
    phones = [f.fr_phone() for _ in range(5)]
    s.append(f"CREATE TABLE {sqlite_ident(tname)} (id INTEGER PRIMARY KEY, phone TEXT NOT NULL);\n")
    s.append(ins(sqlite_ident(tname), ["id", "phone"], [(i + 1, ph) for i, ph in enumerate(phones)]))
    add(F, tname, "phone", ["pii.phone"], phones, name_values=[p["email"]],
        name_value_classifiers=["pii.email"], normalized="*", note="table name embeds an e-mail address")
    p = people[4]
    cname = p["email"]
    phones = [f.fr_phone() for _ in range(8)]
    s.append(f"CREATE TABLE escalation_contacts (id INTEGER PRIMARY KEY, {sqlite_ident(cname)} TEXT NOT NULL);\n")
    s.append(ins("escalation_contacts", ["id", cname], [(i + 1, ph) for i, ph in enumerate(phones)]))
    add(F, "escalation_contacts", cname, ["pii.phone"], phones, name_values=[cname],
        name_value_classifiers=["pii.email"], normalized="*", note="column name is an e-mail address")

    # A value above 64 KiB: not sampled (the connector reads values of at most 64 KiB).
    hidden = f.email(people[5]["first"], people[5]["last"])
    s.append("CREATE TABLE documents (id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL);\n")
    s.append(ins("documents", ["id", "title", "body"],
                 [(i + 1, f"Quarterly report {2020 + i}", "Draft, no content yet.") for i in range(4)]))
    s.append(f"INSERT INTO documents (id, title, body) VALUES (5, 'Archive', "
             f"replace(hex(zeroblob({SQLITE_LONG_FILLER // 2})), '0', 'x') || ' Contact: ' || "
             f"{sqlite_lit(hidden)});\n")
    add(F, "documents", "body", [], [hidden], never_sampled=True,
        note=f"one value of {SQLITE_LONG_FILLER} characters and more, ending with an e-mail address: above "
             "the 64 KiB the connector samples (expected: not found); the other values hold no data")
    add(F, "documents", "title", [], negative_control=True)

    # FTS5: the text is stored in the shadow table support_notes_content (column c0), an ordinary
    # table the connector samples; the virtual table itself is never read.
    notes, note_emails, note_phones = [], [], []
    for _ in range(40):
        q = f.r.choice(people)
        ph, em = f.fr_phone(), f.email(q["first"], q["last"])
        note_phones.append(ph)
        note_emails.append(em)
        notes.append((f"Customer called from {ph} and asked to use {em} for invoices.",))
    s.append(SQLITE_REQUIRES.format(module="fts5"))
    s.append("CREATE VIRTUAL TABLE support_notes USING fts5(body);\n")
    s.append(ins("support_notes", ["body"], notes))
    s.append(SQLITE_REQUIRES_END)
    add(F, "support_notes_content", "c0", ["pii.email", "pii.phone"], note_emails + note_phones,
        requires="fts5", note="FTS5 shadow table holding the text of support_notes (free text)")
    add(F, "support_notes", "body", [], requires="fts5", note="FTS5 virtual table: never read")

    # Look-alikes.
    s.append("CREATE TABLE invoices (id INTEGER PRIMARY KEY, invoice_number TEXT NOT NULL, "
             "amount_cents INTEGER NOT NULL);\n")
    s.append(ins("invoices", ["id", "invoice_number", "amount_cents"],
                 [(i + 1, f"INV-2026-{i + 1:06d}", f.r.randint(500, 250000)) for i in range(60)]))
    add(F, "invoices", "invoice_number", [], negative_control=True)
    add(F, "invoices", "amount_cents", [], negative_control=True)
    s.append("ANALYZE;\n")
    out["seed/out/sqlite-crm.sql"] = "".join(s)

    # ---------------------------------------------------------------- app.db (WAL)
    F = "app.db"
    people = [f.person() for _ in range(60)]
    s = [HEADER.format(seed=SEED)]
    s.append("""CREATE TABLE users (
  id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, first_name TEXT NOT NULL, last_name TEXT NOT NULL,
  phone TEXT, created_at TEXT NOT NULL
);
""")
    rows = [(i + 1, p["email"], p["first"], p["last"], p["phone"], f.timestamp()) for i, p in enumerate(people)]
    s.append(ins("users", ["id", "email", "first_name", "last_name", "phone", "created_at"], rows))
    add(F, "users", "email", ["pii.email"], [r[1] for r in rows])
    add(F, "users", "first_name", ["pii.person_name"], [r[2] for r in rows])
    add(F, "users", "last_name", ["pii.person_name"], [r[3] for r in rows])
    add(F, "users", "phone", ["pii.phone"], [r[4] for r in rows])
    add(F, "users", "created_at", [], negative_control=True, note="timestamps, not birth dates")
    s.append("""CREATE TABLE sessions (
  token TEXT PRIMARY KEY, user_email TEXT NOT NULL, expires_at TEXT NOT NULL
) WITHOUT ROWID;
""")
    rows = [(f.chars("0123456789abcdef", 32), f.r.choice(people)["email"], f.timestamp()) for _ in range(40)]
    s.append(ins("sessions", ["token", "user_email", "expires_at"], rows))
    add(F, "sessions", "user_email", ["pii.email"], [r[1] for r in rows], note="WITHOUT ROWID table")
    add(F, "sessions", "token", [], negative_control=True, note="random hex, not a secret shape")
    s.append("""CREATE TABLE app_credentials (
  id INTEGER PRIMARY KEY, service TEXT NOT NULL, aws_access_key_id TEXT NOT NULL,
  aws_secret_access_key TEXT NOT NULL, owner_email TEXT NOT NULL
) STRICT;
""")
    rows = []
    for i, svc in enumerate(("mobile-sync", "export", "backup")):
        a, k = f.aws_key_pair()
        rows.append((i + 1, svc, a, k, f.r.choice(people)["email"]))
    s.append(ins("app_credentials", ["id", "service", "aws_access_key_id", "aws_secret_access_key", "owner_email"],
                 rows))
    add(F, "app_credentials", "aws_access_key_id", ["secret.aws_key"], [r[2] for r in rows], note="STRICT table")
    add(F, "app_credentials", "aws_secret_access_key", ["secret.aws_key"], [r[3] for r in rows],
        note="STRICT table")
    add(F, "app_credentials", "owner_email", ["pii.email"], [r[4] for r in rows], note="STRICT table")
    add(F, "app_credentials", "service", [], negative_control=True)
    s.append("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, card_number TEXT NOT NULL, "
             "amount_cents INTEGER NOT NULL);\n")
    rows = [(i + 1, f.r.randint(1, len(people)), p["card"], f.r.randint(500, 90000))
            for i, p in enumerate(people[:50])]
    s.append(ins("orders", ["id", "user_id", "card_number", "amount_cents"], rows))
    add(F, "orders", "card_number", ["pii.card_number"], [r[2] for r in rows])
    add(F, "orders", "amount_cents", [], negative_control=True)
    # The writer sidecar's own table: it inserts a row every few seconds (dev/sqlite/build.py hold).
    s.append("CREATE TABLE writer_heartbeat (id INTEGER PRIMARY KEY, beat INTEGER NOT NULL);\n")
    s.append("INSERT INTO writer_heartbeat (beat) VALUES (0);\n")
    add(F, "writer_heartbeat", "beat", [], negative_control=True, note="written by the writer sidecar")
    s.append("ANALYZE;\n")
    out["seed/out/sqlite-app.sql"] = "".join(s)

    # ---------------------------------------------------------------- intl.db (UTF-16le, rollback)
    F = "intl.db"
    people = [f.person() for _ in range(40)]
    s = [HEADER.format(seed=SEED)]
    s.append("CREATE TABLE contacts (id INTEGER PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL, "
             "phone TEXT, city TEXT NOT NULL);\n")
    rows = [(i + 1, f"{p['first']} {p['last']}", p["email"], p["phone"], p["city"]) for i, p in enumerate(people)]
    s.append(ins("contacts", ["id", "full_name", "email", "phone", "city"], rows))
    add(F, "contacts", "full_name", ["pii.person_name"], [r[1] for r in rows], note="UTF-16le file")
    add(F, "contacts", "email", ["pii.email"], [r[2] for r in rows], note="UTF-16le file")
    add(F, "contacts", "phone", ["pii.phone"], [r[3] for r in rows], note="UTF-16le file")
    add(F, "contacts", "city", [], negative_control=True, note="city names alone")
    s.append("ANALYZE;\n")
    out["seed/out/sqlite-intl.sql"] = "".join(s)

    manifest = {
        "version": 1,
        "generator": "dev/seed/generate.py",
        "seed": SEED,
        "note": "FAKE data only. Read by dev/sqlite/build.py; the SQL is run after the pragmas of its file.",
        "requires_markers": [SQLITE_REQUIRES.strip(), SQLITE_REQUIRES_END.strip()],
        "files": [
            {"file": file, "target": target, "sql": f"sqlite-{file[:-3]}.sql", "journal_mode": jm,
             "encoding": enc, "rollback_mode": rm}
            for file, target, jm, enc, rm in SQLITE_FILES
        ],
    }
    out["seed/out/sqlite.json"] = json.dumps(manifest, indent=1, sort_keys=True) + "\n"
    return out


# --------------------------------------------------------------------------------------------------
# Firebird: database crm (opt-in profile `firebird`, ADR-0060 decision 9)
# --------------------------------------------------------------------------------------------------
# The file of the declared database `crm` (dev/firebird/seed.sh creates it before running the seed).
FIREBIRD_DATABASE_FILE = "/var/lib/firebird/data/crm.fdb"
# The directory of external-file tables (`ExternalFileAccess = Restrict`, dev/firebird/firebird.conf).
FIREBIRD_EXTERNAL_DIR = "/var/lib/firebird/data/external"


def fb_lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def fb_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def fb_inserts(table: str, cols: list[str], rows: list[tuple]) -> str:
    """One INSERT per row: Firebird 4.0 and 5.0 have no multi-row VALUES."""
    head = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ("
    return "".join(head + ", ".join(fb_lit(v) for v in row) + ");\n" for row in rows)


def gen_firebird(f: Fake, t: Truth) -> str:
    """isql script (dialect 3, connection character set UTF8) run by dev/firebird/seed.sh as SYSDBA
    over an embedded connection, after it created the database. The fixtures of ADR-0060 decision 9
    (quoted mixed-case names, a name with a trailing space, a value-bearing name, BLOB SUB_TYPE TEXT,
    NONE and WIN1252 columns, a computed column calling a PSQL function, a view, an external-file
    table, a GTT, an ON CONNECT trigger, a user table named like a system relation, a CAS-shaped ticket
    table) sit next to the PII. The reader role (minimal variant, decision 4) and the mapping of the
    refused account are created here; the accounts themselves, with their passwords, by the service's
    entrypoint (dev/firebird/entrypoint.sh) or the integration test script (dev/firebird/it.sh)."""
    E, DB = "firebird", "crm"
    people = [f.person() for _ in range(60)]
    s = [HEADER.format(seed=SEED), "SET SQL DIALECT 3;\nSET AUTODDL ON;\n"]
    granted: list[str] = []

    # Plain upper-case names (unquoted identifiers); 9 text columns: 3 column batches.
    s.append("CREATE TABLE CUSTOMERS (ID INTEGER NOT NULL PRIMARY KEY, FIRST_NAME VARCHAR(60), "
             "LAST_NAME VARCHAR(60), EMAIL VARCHAR(160), PHONE VARCHAR(32), BIRTH_DATE DATE, "
             "STREET VARCHAR(200), POSTAL_CODE VARCHAR(16), CITY VARCHAR(80), NIR VARCHAR(32), "
             "IBAN VARCHAR(42), EMAIL_OPT_IN BOOLEAN, CREATED_AT TIMESTAMP);\n")
    rows = [(i + 1, p["first"], p["last"], p["email"], p["phone"], p["birth_date"], p["street"],
             p["postal_code"], p["city"], p["nir"], p["iban"], f.r.random() < 0.5,
             f.timestamp()[:19].replace("T", " ")) for i, p in enumerate(people)]
    s.append(fb_inserts("CUSTOMERS", ["ID", "FIRST_NAME", "LAST_NAME", "EMAIL", "PHONE", "BIRTH_DATE",
                                      "STREET", "POSTAL_CODE", "CITY", "NIR", "IBAN", "EMAIL_OPT_IN",
                                      "CREATED_AT"], rows))
    granted.append("CUSTOMERS")
    c = (None, "CUSTOMERS")
    t.add(E, DB, *c, "FIRST_NAME", ["pii.person_name"], [r[1] for r in rows])
    t.add(E, DB, *c, "LAST_NAME", ["pii.person_name"], [r[2] for r in rows])
    t.add(E, DB, *c, "EMAIL", ["pii.email"], [r[3] for r in rows])
    t.add(E, DB, *c, "PHONE", ["pii.phone"], [r[4] for r in rows])
    t.add(E, DB, *c, "BIRTH_DATE", ["pii.birth_date"], [r[5] for r in rows],
          note="DATE, converted on the server to YYYY-MM-DD")
    t.add(E, DB, *c, "STREET", ["pii.postal_address"], [r[6] for r in rows])
    t.add(E, DB, *c, "NIR", ["pii.nir"], [r[9] for r in rows])
    t.add(E, DB, *c, "IBAN", ["pii.iban"], [r[10] for r in rows])
    t.add(E, DB, *c, "EMAIL_OPT_IN", [], negative_control=True, note="BOOLEAN: never sampled")
    t.add(E, DB, *c, "CREATED_AT", [], negative_control=True, note="timestamp, not a birth date")

    # A quoted mixed-case table and column, and a BLOB SUB_TYPE TEXT column.
    notes, note_emails, note_phones = [], [], []
    for i in range(30):
        p = f.r.choice(people)
        ph, em = f.fr_phone(), f.email(p["first"], p["last"])
        note_phones.append(ph)
        note_emails.append(em)
        notes.append((i + 1, f"Customer called from {ph} and asked to use {em} for invoices."))
    s.append(f"CREATE TABLE {fb_ident('Customer Notes')} (ID INTEGER NOT NULL, "
             f"{fb_ident('Note Text')} BLOB SUB_TYPE TEXT CHARACTER SET UTF8);\n")
    s.append(fb_inserts(fb_ident("Customer Notes"), ["ID", fb_ident("Note Text")], notes))
    granted.append(fb_ident("Customer Notes"))
    t.add(E, DB, None, "Customer Notes", "Note Text", ["pii.email", "pii.phone"], note_emails + note_phones,
          note="quoted mixed-case names; BLOB SUB_TYPE TEXT, its first 4000 characters cast on the server")

    # Trailing spaces in quoted names: not significant in a Firebird name (stored padded).
    rows = [(i + 1, p["email"]) for i, p in enumerate(people[:20])]
    s.append(f"CREATE TABLE {fb_ident('Legacy Contacts ')} ({fb_ident('Contact Email ')} VARCHAR(160));\n")
    s.append(fb_inserts(fb_ident("Legacy Contacts "), [fb_ident("Contact Email ")], [(r[1],) for r in rows]))
    granted.append(fb_ident("Legacy Contacts "))
    t.add(E, DB, None, "Legacy Contacts", "Contact Email", ["pii.email"], [r[1] for r in rows],
          note="declared with a trailing space in the table and column names (not significant: dropped, "
               "no ADR-0056 marker)")

    # WIN1252 and NONE columns.
    rows = [(i + 1, f"{p['first']} {p['last']}", p["email"]) for i, p in enumerate(people[20:50])]
    s.append("CREATE TABLE LEGACY_1252 (ID INTEGER NOT NULL, FULL_NAME VARCHAR(120) CHARACTER SET WIN1252, "
             "RAW_EMAIL VARCHAR(160) CHARACTER SET NONE);\n")
    s.append(fb_inserts("LEGACY_1252", ["ID", "FULL_NAME", "RAW_EMAIL"], rows))
    granted.append("LEGACY_1252")
    t.add(E, DB, None, "LEGACY_1252", "FULL_NAME", ["pii.person_name"], [r[1] for r in rows],
          note="CHARACTER SET WIN1252, transliterated to UTF8 on the server")
    t.add(E, DB, None, "LEGACY_1252", "RAW_EMAIL", ["pii.email"], [r[2] for r in rows],
          note="CHARACTER SET NONE, read as OCTETS and kept as valid UTF-8 text")

    # A computed column calling a PSQL function (user code on read), and the ON CONNECT trigger.
    s.append("""SET TERM ^ ;
CREATE FUNCTION FN_IBAN_PREFIX (IBAN VARCHAR(42)) RETURNS VARCHAR(8) AS
BEGIN
  RETURN SUBSTRING(IBAN FROM 1 FOR 4) || '****';
END^
CREATE TRIGGER TRG_DEV_ON_CONNECT ACTIVE ON CONNECT POSITION 0 AS
DECLARE V INTEGER;
BEGIN
  V = RDB$SET_CONTEXT('USER_SESSION', 'DEV_ON_CONNECT', 'seen');
END^
SET TERM ; ^
""")
    s.append("CREATE TABLE PAYMENT_CARDS (ID INTEGER NOT NULL, CARD_BRAND VARCHAR(16), CARD_NUMBER VARCHAR(24), "
             "CARD_HOLDER VARCHAR(120), IBAN VARCHAR(42), TRACKING_REF VARCHAR(16), "
             "IBAN_PREFIX COMPUTED BY (FN_IBAN_PREFIX(IBAN)));\n")
    rows = [(i + 1, p["card_brand"], p["card"], f"{p['first']} {p['last']}".upper(), p["iban"], f.not_luhn(16))
            for i, p in enumerate(people[:40])]
    s.append(fb_inserts("PAYMENT_CARDS", ["ID", "CARD_BRAND", "CARD_NUMBER", "CARD_HOLDER", "IBAN",
                                          "TRACKING_REF"], rows))
    granted.append("PAYMENT_CARDS")
    c = (None, "PAYMENT_CARDS")
    t.add(E, DB, *c, "CARD_NUMBER", ["pii.card_number"], [r[2] for r in rows])
    t.add(E, DB, *c, "CARD_HOLDER", ["pii.person_name"], [r[3] for r in rows])
    t.add(E, DB, *c, "IBAN", ["pii.iban"], [r[4] for r in rows])
    t.add(E, DB, *c, "CARD_BRAND", [], negative_control=True, note="brand name, not a card number")
    t.add(E, DB, *c, "TRACKING_REF", [], negative_control=True, note="16-digit numbers that FAIL the Luhn check")
    t.add(E, DB, *c, "IBAN_PREFIX", [], note=(
        "computed column calling the PSQL function FN_IBAN_PREFIX (user code on read): never sampled, "
        "coverage.computed_columns_not_sampled"))

    # A view: never sampled (its base table is).
    s.append("CREATE VIEW V_CUSTOMER_EMAILS (EMAIL) AS SELECT EMAIL FROM CUSTOMERS;\n")
    t.add(E, DB, None, "V_CUSTOMER_EMAILS", "EMAIL", [], note="view: never sampled, coverage.views_not_sampled")

    # An external-file table: the server reads a file outside the database: never read (I5).
    ext = [(f.r.choice(people)["email"].ljust(40), "\n") for _ in range(5)]
    s.append(f"CREATE TABLE EXT_EXPORT EXTERNAL FILE '{FIREBIRD_EXTERNAL_DIR}/ext_export.dat' "
             "(EMAIL CHAR(40), EOL CHAR(1));\n")
    s.append(fb_inserts("EXT_EXPORT", ["EMAIL", "EOL"], ext))
    granted.append("EXT_EXPORT")
    t.add(E, DB, None, "EXT_EXPORT", "EMAIL", [], [r[0].strip() for r in ext], never_sampled=True,
          note="external-file table: never read (skipped_remote, coverage.external_file_tables)")

    # A global temporary table: its rows belong to other attachments.
    s.append("CREATE GLOBAL TEMPORARY TABLE SESSION_SCRATCH (EMAIL VARCHAR(160)) ON COMMIT PRESERVE ROWS;\n")
    granted.append("SESSION_SCRATCH")
    t.add(E, DB, None, "SESSION_SCRATCH", "EMAIL", [], note="global temporary table: never sampled")

    # A user table named like a system relation: a user table all the same (system flag 0).
    rows = [(i + 1, p["email"]) for i, p in enumerate(people[50:60])]
    s.append(f"CREATE TABLE {fb_ident('RDB$CUSTOMER_ARCHIVE')} (ID INTEGER NOT NULL, EMAIL VARCHAR(160));\n")
    s.append(fb_inserts(fb_ident("RDB$CUSTOMER_ARCHIVE"), ["ID", "EMAIL"], rows))
    granted.append(fb_ident("RDB$CUSTOMER_ARCHIVE"))
    t.add(E, DB, None, "RDB$CUSTOMER_ARCHIVE", "EMAIL", ["pii.email"], [r[1] for r in rows],
          note="user table (system flag 0) named with the RDB$ prefix: sampled as a user table")

    # A value-bearing table name: an e-mail address in a quoted name.
    p = people[3]
    tname = f"EXPORT_{p['email']}"
    s.append(f"CREATE TABLE {fb_ident(tname)} (ID INTEGER NOT NULL, PHONE VARCHAR(32));\n")
    s.append(fb_inserts(fb_ident(tname), ["ID", "PHONE"], [(1, p["phone"])]))
    granted.append(fb_ident(tname))
    t.add(E, DB, None, tname, "PHONE", ["pii.phone"], [p["phone"]], name_values=[p["email"]],
          name_value_classifiers=["pii.email"], normalized="*", note="table name embeds an e-mail address")

    # CAS JPA ticket registry shape (ADR-0041 decisions 5 and 6): counted per type, never sampled.
    s.append("CREATE TABLE CAS_TICKETS (ID VARCHAR(768) NOT NULL, TYPE VARCHAR(255) NOT NULL, "
             "BODY BLOB SUB_TYPE TEXT, PARENT_ID VARCHAR(768), PRINCIPAL_ID VARCHAR(768), "
             "CREATION_TIME TIMESTAMP NOT NULL, EXPIRATION_TIME TIMESTAMP);\n")
    tickets = []
    for i in range(6):
        kind = ("TGT", "org.apereo.cas.ticket.TicketGrantingTicketImpl") if i % 2 == 0 else \
            ("ST", "org.apereo.cas.ticket.ServiceTicketImpl")
        tid = f"{kind[0]}-{i + 1}-dev-only-{f.chars(B64_CHARSET, 24)}"
        tickets.append((tid, kind[1], "{}", None, f.person()["email"], f"2026-09-{i + 1:02d} 10:00:00", None))
    s.append(fb_inserts("CAS_TICKETS", ["ID", "TYPE", "BODY", "PARENT_ID", "PRINCIPAL_ID", "CREATION_TIME",
                                        "EXPIRATION_TIME"], tickets))
    granted.append("CAS_TICKETS")
    t.add(E, DB, None, "CAS_TICKETS", "ID", [], [r[0] for r in tickets], never_sampled=True,
          note="CAS ticket registry (ADR-0041): its type counts only, never sampled; Firebird grants SELECT "
               "per table, so check() reports privilege.ticket_credentials_readable")
    t.add(E, DB, None, "CAS_TICKETS", "PRINCIPAL_ID", [], [r[4] for r in tickets], never_sampled=True,
          note="CAS ticket registry: never sampled")

    # Ticket ids in an ordinary table: the tripwire drops the column before classification.
    refs = [(i + 1, f"TGT-{i + 10}-dev-only-{f.chars(B64_CHARSET, 24)}", f.r.choice(people)["email"])
            for i in range(10)]
    s.append("CREATE TABLE LOGIN_REFS (ID INTEGER NOT NULL, SESSION_REF VARCHAR(80), USER_EMAIL VARCHAR(160));\n")
    s.append(fb_inserts("LOGIN_REFS", ["ID", "SESSION_REF", "USER_EMAIL"], refs))
    granted.append("LOGIN_REFS")
    t.add(E, DB, None, "LOGIN_REFS", "SESSION_REF", [], [r[1] for r in refs], never_sampled=True,
          note="CAS ticket ids: the ticket-id tripwire drops the column before classification "
               "(coverage.cas_guard_tripped)")
    t.add(E, DB, None, "LOGIN_REFS", "USER_EMAIL", ["pii.email"], [r[2] for r in refs])

    # Secrets.
    rows = []
    for i, svc in enumerate(("erp-export", "warehouse-sync", "backup")):
        a, k = f.aws_key_pair()
        rows.append((i + 1, svc, a, k))
    s.append("CREATE TABLE APP_CREDENTIALS (ID INTEGER NOT NULL, SERVICE VARCHAR(32), "
             "AWS_ACCESS_KEY_ID VARCHAR(32), AWS_SECRET_ACCESS_KEY VARCHAR(64));\n")
    s.append(fb_inserts("APP_CREDENTIALS", ["ID", "SERVICE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], rows))
    granted.append("APP_CREDENTIALS")
    c = (None, "APP_CREDENTIALS")
    t.add(E, DB, *c, "AWS_ACCESS_KEY_ID", ["secret.aws_key"], [r[2] for r in rows])
    t.add(E, DB, *c, "AWS_SECRET_ACCESS_KEY", ["secret.aws_key"], [r[3] for r in rows])
    t.add(E, DB, *c, "SERVICE", [], negative_control=True)

    # Numeric types converted on the server: look-alikes only.
    rows = [(i + 1, f"INV-2026-{i + 1:06d}", f"{f.r.randint(500, 250000)}.{f.r.randint(0, 99):02d}",
             f.r.randint(1, 10 ** 30), f"{f.r.randint(1, 999)}.5", f.r.randint(1, 9)) for i in range(40)]
    s.append("CREATE TABLE INVOICES (ID INTEGER NOT NULL, INVOICE_NUMBER VARCHAR(20), AMOUNT NUMERIC(18,2), "
             "REF_ID INT128, SCORE DOUBLE PRECISION, RATE DECFLOAT(34));\n")
    s.append(fb_inserts("INVOICES", ["ID", "INVOICE_NUMBER", "AMOUNT", "REF_ID", "SCORE", "RATE"], rows))
    granted.append("INVOICES")
    for col in ("INVOICE_NUMBER", "AMOUNT", "REF_ID", "SCORE", "RATE"):
        t.add(E, DB, None, "INVOICES", col, [], negative_control=True,
              note="NUMERIC, INT128, DOUBLE PRECISION and DECFLOAT converted on the server")

    # A table the reader role is not granted: never read (coverage.relations_without_select).
    staff = [f.person() for _ in range(10)]
    s.append("CREATE TABLE HR_SALARIES (EMPLOYEE_EMAIL VARCHAR(160), SALARY_EUR INTEGER);\n")
    s.append(fb_inserts("HR_SALARIES", ["EMPLOYEE_EMAIL", "SALARY_EUR"],
                        [(p["email"], f.r.randint(28000, 95000)) for p in staff]))
    t.add(E, DB, None, "HR_SALARIES", "EMPLOYEE_EMAIL", [], note=(
        "no SELECT for the reader role: never read, skipped_not_readable, coverage.relations_without_select"))

    # The minimal variant (decision 4): a reader role holding the table grants, granted DEFAULT; the
    # refused account mapped to SYSDBA (the refusal tests).
    s.append("COMMIT;\nCREATE ROLE DATABASTION_READER;\n")
    for name in granted:
        s.append(f"GRANT SELECT ON TABLE {name} TO ROLE DATABASTION_READER;\n")
    s.append("GRANT DEFAULT DATABASTION_READER TO USER DATABASTION_AGENT;\n")
    s.append("CREATE MAPPING DEV_MAP_SYSDBA USING PLUGIN SRP FROM USER AGENT_SYSDBA_MAPPED TO USER SYSDBA;\n")
    s.append("COMMIT;\n")
    return "".join(s)

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
    files["seed/out/sqlserver.sql"] = gen_sqlserver(Fake(seed + 51), t)
    files["seed/out/redis.txt"] = gen_redis(Fake(seed + 52), t)
    files.update(gen_sqlite(Fake(seed + 53), t))
    files["seed/out/firebird.sql"] = gen_firebird(Fake(seed + 54), t)
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
            "sqlserver: opt-in service `sqlserver` (ADR-0051); container is the schema. Locations "
            "with a note and no classifier are fixtures Discovery must skip (masked, encrypted, "
            "computed, row-level security, synonym).",
            "redis / valkey: opt-in profile `redis` (ADR-0052 decision 7); both services load the same "
            "keyspace (dev/seed/out/redis.txt). database is db<index>, container the Redis type, "
            "object the expected key pattern, field `value`, a hash or stream field, `*` for fields "
            "keyed by data, `#key` / `#field` for values found in key or field names.",
            "sqlite: opt-in profile `sqlite` (ADR-0059 decision 10); one dev target per file "
            "(targets.sqlite.files, dev/seed/out/sqlite.json), written by dev/sqlite/build.py. database "
            "is `main`, no container, `file` the database file. `requires: fts5`: created only by a "
            "writer with FTS5 (the agent's bundled library has none). Locations with a note and no "
            "classifier are fixtures Discovery must not report (view, VIRTUAL generated column, BLOB, "
            "value above 64 KiB, FTS5 virtual table).",
            "firebird: opt-in profile `firebird` (ADR-0060 decision 9); database is the name declared in "
            "agent.yaml (`crm`, file targets.firebird.file), no container (no schema). Object and field are "
            "the catalog names, trailing spaces dropped. Locations with a note and no classifier are "
            "fixtures Discovery must not sample (BOOLEAN, computed column, view, external-file table, "
            "global temporary table, table without SELECT).",
        ],
        "targets": {
            "postgresql": {"service": "postgres", "databases": ["shop"]},
            "mysql": {"service": "mysql", "databases": ["hr"]},
            "mariadb": {"service": "mariadb", "databases": ["support"]},
            "mongodb": {"service": "mongo", "databases": ["app"]},
            "openldap": {"service": "openldap", "databases": ["dc=example,dc=org"]},
            "cas": {"service": "cas", "databases": ["service_registry", "audit_trail"]},
            "sqlserver": {"service": "sqlserver", "databases": ["retail"]},
            "valkey": {"service": "valkey", "databases": ["db0", "db1"],
                       "key_patterns_scoped_user": list(REDIS_SCOPED_PATTERNS)},
            "redis": {"service": "redis", "databases": ["db0", "db1"],
                      "key_patterns_scoped_user": list(REDIS_SCOPED_PATTERNS)},
            "sqlite": {"service": "sqlite", "databases": ["main"],
                       "files": {file: target for file, target, *_ in SQLITE_FILES}},
            "firebird": {"service": "firebird", "databases": ["crm"], "file": FIREBIRD_DATABASE_FILE},
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
