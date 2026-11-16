"""Integration tests for the area ``test_metering_pipeline.py`` covers; the unit tests live in ``unit/test_metering_pipeline.py``."""

from __future__ import annotations

import base64

import asyncpg
import mcp.types as mt
from fastmcp.tools.base import ToolResult
from image_builders import png
from test_metering_pipeline import (
    _NEVER_MS,
    _SETTINGS,
    _backend,
    _lines,
    _usage_record,
)

from af_mcp_broker.config import Settings
from af_mcp_broker.usage import build_usage_store
from af_mcp_broker.usage.summary import build_usage_summary


async def test_duplicate_audit_ids_through_the_pipeline_count_once_in_postgres(
    postgres_dsn: str,
    audit_buffer,
) -> None:
    """End to end against a real postgres: the same record redelivered in one
    batch and again in a later batch still produces a single usage row."""
    store = build_usage_store(
        Settings(
            usage_store_backend="postgres",
            usage_postgres_dsn=postgres_dsn,
            usage_batch_max=2,
            usage_batch_interval_ms=_NEVER_MS,
        )
    )
    await store.start()
    conn = await asyncpg.connect(postgres_dsn)
    try:
        await conn.execute("TRUNCATE af_mcp_usage_events CASCADE")
    finally:
        await conn.close()
    p = _backend(
        Settings(usage_batch_max=2, usage_batch_interval_ms=_NEVER_MS),
        usage_store=store,
    )
    await p.start()

    record = _usage_record()
    await p.submit(record, None)
    await p.submit(record, None)  # fills the batch: duplicate within a batch
    await p.submit(record, None)  # next batch: duplicate across batches
    await p.aclose()

    (agg,) = await store.query("sub-abc", days=30)
    assert agg.calls == 1
    await store.aclose()


async def test_image_result_is_measured_end_to_end_into_postgres_and_the_audit_line(
    postgres_dsn: str,
    audit_buffer,
) -> None:
    """The production gap: a call returning a 640x480 PNG as ImageContent was
    recorded as 29 bytes / 14 tokens. The worker must measure the image, the
    audit line must carry the breakdown, and the same breakdown must reach the
    usage store and be served back by the usage summary."""
    store = build_usage_store(
        Settings(usage_store_backend="postgres", usage_postgres_dsn=postgres_dsn)
    )
    await store.start()
    conn = await asyncpg.connect(postgres_dsn)
    try:
        await conn.execute("TRUNCATE af_mcp_usage_events CASCADE")
    finally:
        await conn.close()
    p = _backend(_SETTINGS, usage_store=store)
    await p.start()

    png_b64 = base64.b64encode(png(640, 480)).decode("ascii")
    result = ToolResult(
        content=[
            mt.TextContent(type="text", text="plot done"),
            mt.ImageContent(type="image", data=png_b64, mimeType="image/png"),
        ]
    )
    await p.submit(_usage_record(), result)
    await p.aclose()

    (line,) = _lines(audit_buffer)
    assert line["result_content"]["image"] == {
        "blocks": 1,
        "bytes": len(png_b64),
        "tokens_est": 23 * 18,
    }
    assert line["result_bytes"] == len(b"plot done") + len(png_b64)
    assert line["result_bytes"] == sum(
        c["bytes"] for c in line["result_content"].values()
    )

    summary = await build_usage_summary(store, "sub-abc", 30)
    await store.aclose()
    assert summary.totals.result_bytes == line["result_bytes"]
    by_type = {c.content_type: c for c in summary.by_content_type}
    assert by_type["image"].tokens_est == 414
    assert by_type["image"].bytes == len(png_b64)
    assert by_type["text"].blocks == 1
