"""Merge template department and email verification heads.

Revision ID: 0021_merge_template_department_and_email_verification
Revises: 0020_template_department, 0020_user_email_verification
Create Date: 2026-03-17
"""
from __future__ import annotations


revision = "0021_merge_template_department_and_email_verification"
down_revision = ("0020_template_department", "0020_user_email_verification")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
