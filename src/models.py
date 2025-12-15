"""
Data models for the Loop application.

This module defines lightweight data classes representing a new user signup and a survey response.
Each class provides helper methods for generating DynamoDB items and computing partition keys.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import hashlib


def now_iso() -> str:
    """Return the current UTC time as an ISO 8601 formatted string."""
    return datetime.now(timezone.utc).isoformat()


def sha256_hex(s: str) -> str:
    """Return the hexadecimal representation of a SHA‑256 hash of the given string."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@dataclass
class UserSignup:
    """
    Represents a user who has signed up to try the Loop application.

    Attributes:
        email: User's email address (case‑insensitive).
        source: String describing where the user came from (e.g. 'website', 'referral', etc.).
        createdAt: ISO timestamp when the user was created.
        status: String representing the user's status (e.g. 'VALID', 'PENDING').
        surveyTokenHash: SHA‑256 hex digest of the raw survey token.
    """

    email: str
    source: str
    createdAt: str
    status: str
    surveyTokenHash: str

    @property
    def pk(self) -> str:
        """Compute the partition key for the user record."""
        return f"USER#{self.email.lower()}"

    def to_item(self) -> Dict[str, Any]:
        """Convert the user into a DynamoDB item (dictionary)."""
        item: Dict[str, Any] = {
            "pk": self.pk,
            "email": self.email.lower(),
            "source": self.source,
            "createdAt": self.createdAt,
            "status": self.status,
            "surveyTokenHash": self.surveyTokenHash,
        }
        # Add a GSI partition key for token lookup
        item["gsi1pk"] = f"TOKEN#{self.surveyTokenHash}"
        return item


@dataclass
class SurveyResponse:
    """
    Represents a completed survey response.

    Attributes:
        tokenHash: SHA‑256 hex digest of the raw survey token.
        email: Email of the respondent.
        submittedAt: ISO timestamp when the survey was submitted.
        answers: Dictionary containing answers keyed by question name.
    """

    tokenHash: str
    email: str
    submittedAt: str
    answers: Dict[str, Any]

    @property
    def pk(self) -> str:
        """Compute the partition key for the survey response record."""
        return f"SURVEY#{self.tokenHash}"

    def to_item(self) -> Dict[str, Any]:
        """Convert the survey response into a DynamoDB item (dictionary)."""
        return {
            "pk": self.pk,
            "tokenHash": self.tokenHash,
            "email": self.email.lower(),
            "submittedAt": self.submittedAt,
            "answers": self.answers,
        }