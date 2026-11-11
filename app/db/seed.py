"""Idempotent seed script for multi-tenant enterprise RAG database.

Seeds 3 tenants (CityCare, SecureLife, TechNova) with:
- Approximately 5 users per tenant
- 3-4 groups per tenant
- User-to-group memberships
- Sample indexed document & chunk with tenant ACL

Usage:
    python -m app.db.seed
"""

import asyncio
import hashlib
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings
from app.db.models import (
    Chunk,
    Document,
    DocumentACL,
    DocumentStatus,
    Group,
    PrincipalType,
    Tenant,
    User,
    UserGroup,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("seed")
settings = get_settings()

# Administrative seed engine uses the privileged migration/DB owner connection
seed_engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
)
SeedSessionLocal = async_sessionmaker(
    bind=seed_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

SEED_DATA = [
    {
        "name": "CityCare",
        "plan": "enterprise",
        "rate_limit": 120,
        "groups": [
            "Hospital Administrators",
            "Clinical Operations",
            "Medical Records",
            "Emergency Response",
        ],
        "users": [
            {
                "email": "admin@citycare.org",
                "role": "admin",
                "groups": ["Hospital Administrators"],
            },
            {
                "email": "dr.patel@citycare.org",
                "role": "clinician",
                "groups": ["Clinical Operations"],
            },
            {
                "email": "nurse.sharma@citycare.org",
                "role": "nurse",
                "groups": ["Clinical Operations", "Emergency Response"],
            },
            {
                "email": "records.clerk@citycare.org",
                "role": "staff",
                "groups": ["Medical Records"],
            },
            {
                "email": "audit.officer@citycare.org",
                "role": "auditor",
                "groups": ["Hospital Administrators"],
            },
        ],
        "sample_doc": {
            "title": "CityCare Clinical Practice Guidelines",
            "content": (
                "CityCare emergency triage protocol: patients presenting with acute symptoms "
                "must be triaged within 10 minutes according to the ESI framework."
            ),
        },
    },
    {
        "name": "SecureLife",
        "plan": "enterprise",
        "rate_limit": 100,
        "groups": [
            "Underwriting",
            "Claims Adjusters",
            "Fraud Investigation",
            "Policy Support",
        ],
        "users": [
            {
                "email": "admin@securelife.com",
                "role": "admin",
                "groups": ["Underwriting"],
            },
            {
                "email": "underwriter.lead@securelife.com",
                "role": "underwriter",
                "groups": ["Underwriting"],
            },
            {
                "email": "claims.adjuster@securelife.com",
                "role": "claims_agent",
                "groups": ["Claims Adjusters"],
            },
            {
                "email": "fraud.analyst@securelife.com",
                "role": "investigator",
                "groups": ["Fraud Investigation"],
            },
            {
                "email": "compliance@securelife.com",
                "role": "auditor",
                "groups": ["Underwriting", "Claims Adjusters"],
            },
        ],
        "sample_doc": {
            "title": "SecureLife Health Claim Guidelines",
            "content": (
                "SecureLife reimbursement policy: standard claims below $5,000 are processed "
                "within 48 hours upon electronic submission of itemized receipts."
            ),
        },
    },
    {
        "name": "TechNova",
        "plan": "standard",
        "rate_limit": 60,
        "groups": [
            "Platform Engineering",
            "Data Science",
            "Security & Privacy",
        ],
        "users": [
            {
                "email": "admin@technova.io",
                "role": "admin",
                "groups": ["Platform Engineering"],
            },
            {
                "email": "ml.lead@technova.io",
                "role": "engineer",
                "groups": ["Data Science"],
            },
            {
                "email": "backend.dev@technova.io",
                "role": "engineer",
                "groups": ["Platform Engineering"],
            },
            {
                "email": "sec.analyst@technova.io",
                "role": "security",
                "groups": ["Security & Privacy"],
            },
            {
                "email": "qa.engineer@technova.io",
                "role": "qa",
                "groups": ["Platform Engineering"],
            },
        ],
        "sample_doc": {
            "title": "TechNova API Security Architecture",
            "content": (
                "TechNova zero-trust infrastructure: all internal microservice calls must "
                "carry validated tenant context in JWT claims and mutual TLS tokens."
            ),
        },
    },
]


async def seed_tenant(session: AsyncSession, data: dict) -> Tenant:
    # 1. Upsert Tenant
    stmt = select(Tenant).where(Tenant.name == data["name"])
    res = await session.execute(stmt)
    tenant = res.scalar_one_or_none()

    if not tenant:
        tenant = Tenant(
            name=data["name"],
            plan=data["plan"],
            rate_limit=data["rate_limit"],
        )
        session.add(tenant)
        await session.flush()
        logger.info("Created tenant '%s' (%s)", tenant.name, tenant.id)
    else:
        logger.info("Tenant '%s' already exists (%s)", tenant.name, tenant.id)

    # 2. Upsert Groups
    group_map: dict[str, Group] = {}
    for g_name in data["groups"]:
        stmt = select(Group).where(Group.tenant_id == tenant.id, Group.name == g_name)
        res = await session.execute(stmt)
        group = res.scalar_one_or_none()
        if not group:
            group = Group(tenant_id=tenant.id, name=g_name)
            session.add(group)
            await session.flush()
            logger.info("  Created group '%s'", g_name)
        group_map[g_name] = group

    # 3. Upsert Users & Group Memberships
    for u_data in data["users"]:
        stmt = select(User).where(
            User.tenant_id == tenant.id, User.email == u_data["email"]
        )
        res = await session.execute(stmt)
        user = res.scalar_one_or_none()
        if not user:
            user = User(
                tenant_id=tenant.id,
                email=u_data["email"],
                role=u_data["role"],
            )
            session.add(user)
            await session.flush()
            logger.info("  Created user '%s' (%s)", user.email, user.role)

        # Memberships
        for g_name in u_data["groups"]:
            group = group_map.get(g_name)
            if group:
                stmt = select(UserGroup).where(
                    UserGroup.tenant_id == tenant.id,
                    UserGroup.user_id == user.id,
                    UserGroup.group_id == group.id,
                )
                res = await session.execute(stmt)
                membership = res.scalar_one_or_none()
                if not membership:
                    membership = UserGroup(
                        tenant_id=tenant.id,
                        user_id=user.id,
                        group_id=group.id,
                    )
                    session.add(membership)
                    logger.info("    Added '%s' to group '%s'", user.email, g_name)

    # 4. Upsert Sample Document, Chunk, and ACL
    doc_info = data["sample_doc"]
    stmt = select(Document).where(
        Document.tenant_id == tenant.id, Document.title == doc_info["title"]
    )
    res = await session.execute(stmt)
    doc = res.scalar_one_or_none()

    source_hash = hashlib.sha256(doc_info["content"].encode("utf-8")).hexdigest()

    if not doc:
        doc = Document(
            tenant_id=tenant.id,
            title=doc_info["title"],
            source_hash=source_hash,
            version=1,
            status=DocumentStatus.indexed,
        )
        session.add(doc)
        await session.flush()
        logger.info("  Created document '%s'", doc.title)

        # Add chunk
        # 384-dimensional synthetic dummy vector
        dummy_vector = [0.01 * (i % 50) for i in range(384)]
        chunk = Chunk(
            tenant_id=tenant.id,
            document_id=doc.id,
            version=1,
            chunk_index=0,
            content=doc_info["content"],
            embedding=dummy_vector,
            page=1,
            chunk_metadata={"section": "Overview", "seeded": True},
        )
        session.add(chunk)

        # Add tenant-wide ACL entry
        acl = DocumentACL(
            tenant_id=tenant.id,
            document_id=doc.id,
            principal_type=PrincipalType.tenant,
            principal_id=None,
        )
        session.add(acl)
        logger.info("    Created chunk and tenant-wide ACL for '%s'", doc.title)

    return tenant


async def seed_all() -> None:
    logger.info("Starting database seed...")
    async with SeedSessionLocal() as session:
        async with session.begin():
            for tenant_data in SEED_DATA:
                await seed_tenant(session, tenant_data)
    logger.info("Database seed completed successfully.")


async def main() -> None:
    try:
        await seed_all()
    finally:
        await seed_engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
