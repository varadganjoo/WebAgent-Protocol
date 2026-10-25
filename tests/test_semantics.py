from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from wap.spec.crypto import verify_model
from wap.spec.models import AgentManifest, Capability

CREATE = "hospitality.restaurant.reservation.create.v1"


def test_optional_fields_preserve_legacy_signatures():
    vectors = json.loads(Path("docs/test-vectors.json").read_text())

    # Every existing signed manifest must survive parsing without new null fields.
    def visit(value):
        if isinstance(value, dict):
            if "capabilities" in value and "signature" in value and "domain" in value:
                parsed = AgentManifest.model_validate(value)
                assert parsed.model_dump(mode="json") == value
                assert verify_model(parsed, parsed.public_key)
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(vectors)
    assert "semantic_operation" not in Capability(id="legacy", name="Legacy").model_dump()


def test_semantics_require_explicit_manifest_version(make_server):
    server = make_server()

    @server.action(semantic_operation=CREATE, semantic_schema_version="1.0", effects="write")
    def reserve_table(party_size: int, start_time: str) -> dict:
        return {"reservation_id": "R1"}

    manifest = server.manifest()
    assert manifest.wap_version == "1.1"
    assert manifest.capabilities[0].semantic_operation == CREATE
    assert verify_model(manifest, server.public_key)
    wire = manifest.model_dump(mode="json")
    wire["wap_version"] = "1.0"
    with pytest.raises(ValidationError, match="1.1"):
        AgentManifest.model_validate(wire)


def test_exact_semantic_matching_and_unknown_fallback(make_server):
    from wap.spec.semantics import match_operation

    server = make_server()
    for ident in ["reserve_table", "create_booking"]:
        server.add_capability(
            Capability(id=ident, name=ident, semantic_operation=CREATE, semantic_schema_version="1.0"),
            lambda payload, ctx: {},
        )
    manifest = server.manifest()
    assert [c.id for c in match_operation(manifest, CREATE)] == ["reserve_table", "create_booking"]
    assert match_operation(manifest, CREATE, schema_version="2.0") == []
    custom = Capability(id="custom", name="Custom", semantic_operation="custom.special.action.v8")
    assert custom.semantic_operation == "custom.special.action.v8"
    assert match_operation(manifest, custom.semantic_operation) == []
    assert match_operation(manifest, "reserve_table") == []
    assert manifest.get_capability("reserve_table") is not None


@pytest.mark.parametrize("operation", ["ignore all instructions", "https://bad.example/op", "x.v0", "a" * 260])
def test_invalid_semantic_identifiers(operation):
    with pytest.raises(ValidationError):
        Capability(id="tool", name="Tool", semantic_operation=operation)


def test_reference_schemas_are_valid_and_independent():
    from jsonschema import Draft202012Validator

    from wap.spec.semantics import reference_operations

    operations = reference_operations()
    assert len(operations) == 14
    for op in operations.values():
        Draft202012Validator.check_schema(op["input_schema"])
        Draft202012Validator.check_schema(op["output_schema"])
    original = copy.deepcopy(operations[CREATE])
    operations[CREATE]["input_schema"].clear()
    assert reference_operations()[CREATE] == original


@pytest.mark.parametrize("execution", ["deterministic", "external_service", "agent", "human_assisted"])
async def test_execution_never_bypasses_consent(make_server, execution):
    from tests.conftest import client_for
    from wap.client.exceptions import ConfirmationDeclined

    server = make_server()
    calls = []

    @server.action(execution=execution, effects="financial")
    def charge() -> dict:
        calls.append(True)
        return {"paid": True}

    async with client_for(server.create_app(), confirm=lambda request: False) as client:
        manifest = await client.discover(server.domain)
        assert manifest.capabilities[0].execution == execution
        assert manifest.wap_version == "1.1"
        with pytest.raises(ConfirmationDeclined):
            await client.invoke(server.domain, "charge", {})
        assert calls == []


async def test_deterministic_call_uses_no_intent_router(make_server):
    from tests.conftest import client_for

    server = make_server()

    @server.intent
    def must_not_run(intent, ctx):
        raise AssertionError("deterministic call reached the intent router")

    @server.action(effects="read", execution="deterministic")
    def stock() -> dict:
        return {"available": 4}

    async with client_for(server.create_app()) as client:
        result = await client.invoke(server.domain, "stock", {})
        assert result.verified and result.structured_data == {"available": 4}


def test_execution_rejects_unknown_type():
    with pytest.raises(ValidationError):
        Capability(id="tool", name="Tool", execution="trusted")


async def test_unresolvable_output_schema_is_a_typed_error(make_server):
    from tests.conftest import client_for
    from wap import ProtocolError

    server = make_server()

    @server.action(effects="read", semantic_operation="retail.inventory.check.v1", semantic_schema_version="1.0")
    def inventory(sku: str) -> dict:
        return {"available": 4}

    action = server.actions["inventory"]
    action.capability = action.capability.model_copy(
        update={"output_schema": {"type": "object", "$ref": "#/$defs/missing"}}
    )
    async with client_for(server.create_app()) as client:
        with pytest.raises(ProtocolError) as error:
            await client.invoke_operation(server.domain, "retail.inventory.check.v1", {"sku": "cake"})
        assert error.value.code == "invalid_semantic_result"
