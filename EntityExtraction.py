import pandas as pd
import re
import ipaddress
from urllib.parse import urlparse
from datetime import datetime

df = pd.read_csv('Input_alert_data/SentinelHighSeverityIncidentsDataperweek.csv')
entities = (df['Entities'])
# print(entities)
# lets work on extraction of entities from the entities column and create a new column with the extracted entities
def extract_entity_columns(value):
    """
    Extract entities from one cell and return them as a dictionary.
    Each dictionary key becomes a new DataFrame column.
    """

    result = {
        "ipv4": [],
        "ipv6": [],
        "hostname": [],
        "url": [],
        "email": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
        "sha512": [],
        "cve": [],
        "username": []
    }

    text = str(value).strip()
    if not text:
        return result

    # URL
    url_match = re.search(
        r"\bhttps?://[^\s<>'\"]+",
        text,
        flags=re.IGNORECASE
    )

    if url_match:
        result["url"].append(url_match.group(0).rstrip(".,;)]}"))

    # Email
    email_match = re.search(
        r"\b[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b",
        text
    )

    if email_match:
        result["email"].append(email_match.group(0).lower())

    # CVE
    cve_match = re.search(
        r"\bCVE-\d{4}-\d{4,}\b",
        text,
        flags=re.IGNORECASE
    )

    if cve_match:
        result["cve"].append(cve_match.group(0).upper())

    # Hashes
    sha512_match = re.search(
        r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{128}(?![A-Fa-f0-9])",
        text
    )

    sha256_match = re.search(
        r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])",
        text
    )

    sha1_match = re.search(
        r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])",
        text
    )

    md5_match = re.search(
        r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])",
        text
    )

    if sha512_match:
        result["sha512"].append(sha512_match.group(0).lower())

    if sha256_match:
        result["sha256"].append(sha256_match.group(0).lower())

    if sha1_match:
        result["sha1"].append(sha1_match.group(0).lower())

    if md5_match:
        result["md5"].append(md5_match.group(0).lower())

    # IPv4 candidates, validated with ipaddress
    ipv4_candidates = re.findall(
        r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
        text
    )

    for candidate in ipv4_candidates:
        try:
            ip = ipaddress.ip_address(candidate)

            if ip.version == 4:
                result["ipv4"].append(str(ip))
                break

        except ValueError:
            continue

    # IPv6 candidates, validated with ipaddress
    ipv6_candidates = re.findall(
        r"(?<![A-Fa-f0-9:])[A-Fa-f0-9:]{2,39}(?![A-Fa-f0-9:])",
        text
    )

    for candidate in ipv6_candidates:
        # Avoid treating ordinary words or timestamps as IPv6
        if ":" not in candidate:
            continue

        try:
            ip = ipaddress.ip_address(candidate)

            if ip.version == 6:
                result["ipv6"].append(str(ip))
                break

        except ValueError:
            continue

    # Hostname/domain
    hostname_match = re.findall(
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.[a-z]+",
        text,
        flags=re.IGNORECASE
    )

    if hostname_match:
        unique_hostname = list(set(hostname_match))  # Remove duplicates
        result["hostname"].append(unique_hostname)

    return result



entity_columns = pd.json_normalize(
    df["Entities"].apply(extract_entity_columns)
)

df = pd.concat(
    [
        df.reset_index(drop=True),
        entity_columns.reset_index(drop=True)
    ],
    axis=1
)

df.to_csv('Output_alert_data/SentinelHighSeverityIncidentsDataperweek_with_entities.csv', index=False)