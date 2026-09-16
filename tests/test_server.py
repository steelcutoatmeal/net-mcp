"""Smoke tests for server assembly: every tool registers with a usable contract."""

from net_mcp.server import mcp

EXPECTED_PREFIXES = (
    "dns_",
    "rpki_",
    "bgp_",
    "ris_",
    "mrt_",
    "irr_",
    "peeringdb_",
    "subnet_",
    "ip_",
    "prefix_",
    "supernet_",
    "bogon_",
    "local_",
)


async def test_all_tools_register():
    tools = await mcp.list_tools()
    names = [t.name for t in tools]
    assert len(set(names)) == len(names), "duplicate tool names registered"
    assert len(names) >= 39
    for name in names:
        assert name.startswith(EXPECTED_PREFIXES), f"unexpected tool prefix: {name}"


def _has_description(schema: dict) -> bool:
    """True if the schema node, or any anyOf/allOf/oneOf member, carries a description.

    Pydantic on Python 3.10 nests the description of an ``X | None`` parameter
    inside an inner ``anyOf`` entry instead of at the top level.
    """
    if schema.get("description"):
        return True
    for key in ("anyOf", "allOf", "oneOf"):
        if any(
            _has_description(sub)
            for sub in schema.get(key, [])
            if isinstance(sub, dict)
        ):
            return True
    return False


async def test_every_tool_has_llm_facing_contract():
    """The LLM only sees the description and schemas, so none may be empty."""
    for tool in await mcp.list_tools():
        assert tool.description and len(tool.description.strip()) > 20, tool.name
        assert tool.parameters.get("type") == "object", tool.name
        # Every tool returns a Pydantic model, which FastMCP exposes as an output schema.
        assert tool.output_schema, f"{tool.name} has no output schema"
        for pname, pschema in tool.parameters.get("properties", {}).items():
            assert _has_description(pschema), (
                f"{tool.name}.{pname} missing Field(description=...)"
            )


async def test_every_tool_is_tagged():
    for tool in await mcp.list_tools():
        assert tool.tags, f"{tool.name} has no tags"


async def test_tool_errors_reach_the_client():
    """Invalid input must surface as a readable ToolError, not a masked exception."""
    from fastmcp.exceptions import ToolError

    try:
        await mcp.call_tool(
            "dns_lookup", {"name": "example.com", "record_type": "BOGUS"}
        )
    except ToolError as exc:
        assert "Unsupported record type" in str(exc)
    else:
        raise AssertionError("expected ToolError")
