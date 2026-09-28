from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from wap.spec.models import (
    ERROR_STATUS,
    AgentManifest,
    AgentMessage,
    Capability,
    Challenge,
    ErrorCode,
    ErrorResponse,
    RateLimitPolicy,
    Role,
    authority_host,
    is_local_authority,
    normalize_authority,
)

PUB = "ab" * 32


def manifest(**overrides) -> AgentManifest:
    data = dict(
        domain="bakery.example",
        name="Bakery",
        public_key=PUB,
        interaction_url="https://bakery.example/wap/v1/interact",
        capabilities=[Capability(id="get_menu", name="Get Menu")],
    )
    data.update(overrides)
    return AgentManifest(**data)


class TestAuthority:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Bakery.Example", "bakery.example"),
            ("bakery.example.", "bakery.example"),
            ("localhost:8000", "localhost:8000"),
            ("api.shop.co.uk:8443", "api.shop.co.uk:8443"),
            ("127.0.0.1:9000", "127.0.0.1:9000"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ],
    )
    def test_valid(self, raw: str, expected: str) -> None:
        assert normalize_authority(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "https://bakery.example",
            "bakery.example/path",
            "user@bakery.example",
            "bakery",
            "-bad.example",
            "bad-.example",
            "bakery.example:0",
            "bakery.example:70000",
            "bakery.example:http",
            "under_score.example",
            "999.1.1.1",
            "a" * 64 + ".example",
        ],
    )
    def test_invalid(self, raw: str) -> None:
        with pytest.raises(ValueError):
            normalize_authority(raw)

    def test_helpers(self) -> None:
        assert authority_host("localhost:8000") == "localhost"
        assert authority_host("bakery.example") == "bakery.example"
        assert is_local_authority("localhost:8000")
        assert is_local_authority("127.0.0.1")
        assert is_local_authority("api.localhost")
        assert not is_local_authority("bakery.example")


class TestCapability:
    def test_defaults(self) -> None:
        cap = Capability(id="check_stock", name="Check stock")
        assert cap.input_schema == {"type": "object", "properties": {}}
        assert cap.requires_auth is False
        assert cap.output_schema is None

    @pytest.mark.parametrize("bad_id", ["CheckStock", "1stock", "", "has space", "x" * 65])
    def test_rejects_bad_ids(self, bad_id: str) -> None:
        with pytest.raises(ValidationError):
            Capability(id=bad_id, name="x")

    def test_input_schema_must_be_object(self) -> None:
        with pytest.raises(ValidationError, match="JSON object"):
            Capability(id="x", name="x", input_schema={"type": "string"})

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            Capability(id="x", name="x", surprise=True)


class TestManifest:
    def test_valid_manifest_round_trips(self) -> None:
        m = manifest()
        again = AgentManifest.model_validate_json(m.model_dump_json())
        assert again == m
        assert again.wap_version == "1.0"
        assert again.get_capability("get_menu") is not None
        assert again.get_capability("nope") is None

    def test_public_key_is_normalised_and_checked(self) -> None:
        assert manifest(public_key="AB" * 32).public_key == PUB
        with pytest.raises(ValidationError):
            manifest(public_key="ab" * 31)
        with pytest.raises(ValidationError):
            manifest(public_key="zz" * 32)

    def test_signature_format(self) -> None:
        with pytest.raises(ValidationError):
            manifest(signature="abcd")
        assert manifest(signature="00" * 64).signature == "00" * 64

    def test_rejects_wrong_version(self) -> None:
        with pytest.raises(ValidationError):
            AgentManifest.model_validate({**manifest().model_dump(), "wap_version": "2.0"})

    def test_rejects_relative_interaction_url(self) -> None:
        with pytest.raises(ValidationError):
            manifest(interaction_url="/wap/v1/interact")
        with pytest.raises(ValidationError):
            manifest(interaction_url="ftp://bakery.example/x")

    def test_duplicate_capabilities(self) -> None:
        with pytest.raises(ValidationError, match="duplicate"):
            manifest(capabilities=[Capability(id="a", name="A"), Capability(id="a", name="A2")])

    def test_pow_requires_difficulty_and_challenge_url(self) -> None:
        with pytest.raises(ValidationError, match="pow_difficulty"):
            manifest(pow_required=True, challenge_url="https://bakery.example/wap/v1/challenge")
        with pytest.raises(ValidationError, match="challenge_url"):
            manifest(pow_required=True, pow_difficulty=4)
        m = manifest(pow_required=True, pow_difficulty=4, challenge_url="https://bakery.example/wap/v1/challenge")
        assert m.pow_required

    def test_expiry(self) -> None:
        m = manifest(issued_at=1000.0, expires_at=2000.0)
        assert m.is_expired(now=2500.0)
        assert not m.is_expired(now=1500.0)
        assert not manifest(expires_at=None).is_expired()

    def test_default_rate_limit_policy(self) -> None:
        assert manifest().rate_limit_policy == RateLimitPolicy().model_dump()


class TestAgentMessage:
    def test_defaults(self) -> None:
        msg = AgentMessage(session_id="s1", role="user_agent", content="hi")
        assert msg.role is Role.USER_AGENT
        assert len(msg.message_id) == 32
        assert msg.signature == ""
        assert msg.timestamp > 0

    def test_role_enum(self) -> None:
        with pytest.raises(ValidationError):
            AgentMessage(session_id="s1", role="admin", content="hi")

    def test_pow_fields_come_in_pairs(self) -> None:
        with pytest.raises(ValidationError, match="together"):
            AgentMessage(session_id="s", role="user_agent", pow_seed="ab" * 20)
        msg = AgentMessage(session_id="s", role="user_agent", pow_seed="ab" * 20, pow_nonce="1f")
        assert msg.pow_nonce == "1f"

    def test_structured_data_must_be_object(self) -> None:
        with pytest.raises(ValidationError):
            AgentMessage(session_id="s", role="user_agent", structured_data=[1, 2])

    def test_json_wire_format(self) -> None:
        msg = AgentMessage(session_id="s", role="business_agent", content="ok", structured_data={"a": 1})
        wire = json.loads(msg.model_dump_json())
        assert wire["role"] == "business_agent"
        assert wire["wap_version"] == "1.0"
        assert AgentMessage.model_validate(wire) == msg

    def test_limits(self) -> None:
        with pytest.raises(ValidationError):
            AgentMessage(session_id="", role="user_agent")
        with pytest.raises(ValidationError):
            AgentMessage(session_id="s", role="user_agent", content="x" * 70000)


class TestChallengeAndErrors:
    def test_challenge(self) -> None:
        c = Challenge(seed="ab" * 20, difficulty=4, expires_at=10.0)
        assert c.algorithm == "sha256-leading-zero-hex"
        with pytest.raises(ValidationError):
            Challenge(seed="xyz" * 10, difficulty=4, expires_at=1.0)
        with pytest.raises(ValidationError):
            Challenge(seed="ab" * 20, difficulty=0, expires_at=1.0)

    def test_every_error_code_has_a_status(self) -> None:
        assert set(ERROR_STATUS) == set(ErrorCode)
        assert ERROR_STATUS[ErrorCode.POW_REQUIRED] == 428
        assert ERROR_STATUS[ErrorCode.RATE_LIMITED] == 429

    def test_error_response(self) -> None:
        err = ErrorResponse.build(ErrorCode.RATE_LIMITED, "slow down", retry_after=2.0)
        assert err.model_dump(mode="json", exclude_none=True) == {
            "error": {"code": "rate_limited", "message": "slow down", "retry_after": 2.0}
        }
