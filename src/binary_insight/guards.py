"""Deterministic loop guards independent of model confidence."""

import hashlib
import re


def normalize_request(description: str) -> str:
    return " ".join(re.findall(r"\w+", description.casefold()))


def fresh_tests(tests, previously_tested):
    seen = {tuple(arguments) for arguments in previously_tested}
    fresh = []
    skipped = 0
    for test in tests:
        key = tuple(test.arguments)
        if key in seen:
            skipped += 1
        else:
            seen.add(key)
            fresh.append(test)
    return fresh, skipped


def split_observations(observations: str) -> list[str]:
    return [part for part in re.split(r"\s*TEST \d+\s*={2,}", observations) if part.strip()]


def observation_fingerprint(observation: str) -> str:
    # Ignore test explanations and argument echoes; compare observed behavior.
    match = re.search(r"(?:RETURN CODE:|RESULT:|ERROR:)", observation)
    actual = observation[match.start() :] if match else observation
    actual = actual.replace("\r\n", "\n").strip()
    return hashlib.sha256(actual.encode()).hexdigest()
