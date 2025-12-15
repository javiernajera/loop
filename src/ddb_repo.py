"""
DynamoDB repository for user signups.

This module wraps common DynamoDB operations related to user signup records.  It defines methods
for inserting a new user only if they do not already exist, fetching users by email, and
fetching users by the hash of their survey token via a global secondary index.
"""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError
from typing import Optional, Dict, Any, List
from boto3.dynamodb.conditions import Key


class UserRepo:
    """Repository for working with users stored in DynamoDB."""

    def __init__(self, table_name: str) -> None:
        self.table_name = table_name
        self.table = boto3.resource("dynamodb").Table(table_name)

    def put_user_if_new(self, item: Dict[str, Any]) -> bool:
        """
        Insert a user record if it does not already exist.

        Args:
            item: A dictionary representing the DynamoDB item for the user.
        Returns:
            True if the item was inserted, False if it already existed.
        Raises:
            ClientError: For DynamoDB errors other than conditional check failures.
        """
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk)",
            )
            return True
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                # The item already exists; do not overwrite
                return False
            raise

    def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Retrieve a user by email (partition key)."""
        pk = f"USER#{email.lower()}"
        resp = self.table.get_item(Key={"pk": pk})
        return resp.get("Item")

    def get_by_token_hash(self, token_hash: str, index_name: str = "GSI1") -> Optional[Dict[str, Any]]:
        """
        Retrieve a user by the SHA‑256 hash of their survey token via a GSI.

        Args:
            token_hash: The hex digest of the survey token.
            index_name: Name of the global secondary index to query.
        Returns:
            The user item if found, otherwise None.
        """
        partition_key_value = f"TOKEN#{token_hash}"
        resp = self.table.query(
            IndexName=index_name,
            KeyConditionExpression=Key("gsi1pk").eq(partition_key_value),
            Limit=1,
        )
        items: List[Dict[str, Any]] = resp.get("Items", [])
        return items[0] if items else None