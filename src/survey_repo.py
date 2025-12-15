"""
DynamoDB repository for survey responses.

This module exposes a simple repository that inserts completed survey responses
into the configured DynamoDB table.  Survey responses use the token hash as
their partition key and store the entire answer set in a single item.
"""

from __future__ import annotations

import boto3
from typing import Dict, Any


class SurveyRepo:
    """Repository for storing survey responses in DynamoDB."""

    def __init__(self, table_name: str) -> None:
        self.table_name = table_name
        self.table = boto3.resource("dynamodb").Table(table_name)

    def put_survey(self, item: Dict[str, Any]) -> None:
        """Put a survey response into the table."""
        self.table.put_item(Item=item)