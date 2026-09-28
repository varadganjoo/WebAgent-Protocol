"""``wap`` command-line interface.

Commands:

* ``wap ask <domain> "<query>"``        single-shot query with live streaming output
* ``wap inspect <domain>``              pretty-print a verified manifest and capability schemas
* ``wap verify <domain>``               report every verification check performed on a manifest
* ``wap keygen``                        generate an Ed25519 key pair for manifest signing
* ``wap serve module:app``              run a WAP-enabled ASGI application with uvicorn
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .. import __version__
from ..client import WAPClient, WAPError
from ..client.dnskey import txt_record_for
from ..client.exceptions import ProtocolError, SchemaValidationError
from ..spec.crypto import fingerprint, generate_keypair
from ..spec.models import AgentManifest, StreamEventType

app = typer.Typer(
    name="wap",
    help="WebAgent Protocol: discover and talk to business AI agents across the open web.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"wap {__version__} (WAP/1.0)")
        raise typer.Exit()


def _utf8_output() -> None:
    """Write UTF-8 even where the locale says otherwise (e.g. Windows with output redirected to a file)."""
    for stream in (sys.stdout, sys.stderr):
        if (getattr(stream, "encoding", None) or "").lower().replace("-", "") != "utf8":
            try:
                stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
            except (AttributeError, ValueError):
                pass  # not a TextIOWrapper (e.g. a test runner's capture); leave it alone


@app.callback()
def _root(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    """WebAgent Protocol CLI."""
    _utf8_output()


def _client(insecure: bool, pin: list[str] | None, token: str | None, domain: str | None, timeout: float) -> WAPClient:
    pinned: dict[str, str] = {}
    for item in pin or []:
        host, sep, key = item.partition("=")
        if not sep:
            raise typer.BadParameter(f"--pin expects domain=<hex public key>, got {item!r}")
        pinned[host] = key
    tokens = {domain: token} if token and domain else None
    return WAPClient(
        agent_key=os.environ.get("WAP_AGENT_KEY") or None,
        allow_insecure=insecure,
        pinned_keys=pinned,
        auth_tokens=tokens,
        timeout=timeout,
    )


def _fail(exc: Exception) -> None:
    title = type(exc).__name__
    body = Text(str(exc))
    if isinstance(exc, ProtocolError) and exc.details:
        body.append("\n\n")
        body.append(json.dumps(exc.details, indent=2, default=str))
    if isinstance(exc, SchemaValidationError):
        body.append("\n\n" + "\n".join(f"• {e}" for e in exc.errors))
    err_console.print(Panel(body, title=f"[bold red]{title}", border_style="red"))
    raise typer.Exit(code=1)


def _parse_data(data: str | None) -> dict[str, Any] | None:
    if data is None:
        return None
    if data.startswith("@"):
        data = Path(data[1:]).read_text(encoding="utf-8")
    try:
        value = json.loads(data)
    except ValueError as exc:
        raise typer.BadParameter(f"--data must be JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise typer.BadParameter("--data must be a JSON object")
    return value


def _ts(value: float | None) -> str:
    if value is None:
        return "—"
    return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _manifest_table(manifest: AgentManifest) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column()
    table.add_row("Name", manifest.name)
    table.add_row("Domain", manifest.domain)
    table.add_row("Description", manifest.description or "—")
    table.add_row("WAP version", manifest.wap_version)
    table.add_row("Public key", manifest.public_key)
    table.add_row("Fingerprint", fingerprint(manifest.public_key))
    table.add_row("Interaction URL", manifest.interaction_url)
    table.add_row(
        "Proof-of-work",
        f"required (difficulty {manifest.pow_difficulty})" if manifest.pow_required else "not required",
    )
    table.add_row("Rate limit", json.dumps(manifest.rate_limit_policy))
    table.add_row("Issued / expires", f"{_ts(manifest.issued_at)}  →  {_ts(manifest.expires_at)}")
    return table


@app.command()
def ask(
    domain: Annotated[str, typer.Argument(help="Domain or URL, e.g. bakery.example or localhost:8000.")],
    query: Annotated[str, typer.Argument(help="Free-text request for the business agent.")] = "",
    capability: Annotated[
        str | None, typer.Option("--capability", "-c", help="Invoke a specific capability id.")
    ] = None,
    data: Annotated[
        str | None, typer.Option("--data", "-d", help="JSON payload (or @file.json) for the capability.")
    ] = None,
    session: Annotated[str | None, typer.Option("--session", "-s", help="Continue an existing session id.")] = None,
    token: Annotated[
        str | None, typer.Option("--token", envvar="WAP_TOKEN", help="Bearer token for auth-gated capabilities.")
    ] = None,
    no_stream: Annotated[bool, typer.Option("--no-stream", help="Request a single JSON reply instead of SSE.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print the verified result as JSON only.")] = False,
    insecure: Annotated[bool, typer.Option("--insecure", help="Allow plain HTTP for non-loopback hosts.")] = False,
    pin: Annotated[
        list[str] | None, typer.Option("--pin", help="Pin a key: domain=<hex public key>. Repeatable.")
    ] = None,
    timeout: Annotated[float, typer.Option("--timeout", help="Request timeout in seconds.")] = 30.0,
) -> None:
    """Send a single query to a domain's business agent and show the signed reply."""
    payload = _parse_data(data)
    if not query and not capability:
        raise typer.BadParameter("provide a QUERY or --capability")

    async def run() -> None:
        async with _client(insecure, pin, token, domain, timeout) as client:
            manifest = await client.discover(domain)
            if not as_json:
                console.print(
                    f"[dim]→ {manifest.name} ({manifest.domain}) · key {fingerprint(manifest.public_key)}"
                    + (f" · solving PoW d={manifest.pow_difficulty}" if manifest.pow_required else "")
                    + "[/dim]"
                )
            final = None
            request = None
            data_events: list[dict[str, Any]] = []
            async for event in client.query(
                domain, query, capability, payload, session_id=session, stream=not no_stream
            ):
                if event.type is StreamEventType.TOKEN and not as_json:
                    console.print(event.text or "", end="", soft_wrap=True, highlight=False, markup=False)
                elif event.type is StreamEventType.DATA and event.data:
                    data_events.append(event.data)
                elif event.type is StreamEventType.MESSAGE:
                    final, request = event.message, event.request
            if final is None:
                raise ProtocolError("invalid_response", "reply stream ended without a final message")
            if as_json:
                console.print_json(
                    json.dumps(
                        {
                            "domain": manifest.domain,
                            "session_id": final.session_id,
                            "capability_id": final.capability_id,
                            "text": final.content,
                            "structured_data": final.structured_data,
                            "verified": True,
                            "pow_solved": bool(request and request.pow_nonce),
                            "message_id": final.message_id,
                            "signature": final.signature,
                        }
                    )
                )
                return
            console.print()
            if final.structured_data:
                console.print(
                    Panel(JSON.from_data(final.structured_data), title="structured_data", border_style="cyan")
                )
            console.print(
                f"[green]✔ reply signature verified[/green] [dim]session={final.session_id} "
                f"message={final.message_id}[/dim]"
            )

    try:
        asyncio.run(run())
    except (WAPError, ValueError) as exc:
        _fail(exc)


@app.command()
def inspect(
    domain: Annotated[str, typer.Argument(help="Domain or URL to inspect.")],
    raw: Annotated[bool, typer.Option("--raw", help="Print the raw manifest JSON.")] = False,
    insecure: Annotated[bool, typer.Option("--insecure", help="Allow plain HTTP for non-loopback hosts.")] = False,
    timeout: Annotated[float, typer.Option("--timeout", help="Request timeout in seconds.")] = 30.0,
) -> None:
    """Pretty-print a site's verified wap.json manifest and capability schemas."""

    async def run() -> None:
        async with _client(insecure, None, None, None, timeout) as client:
            manifest = await client.discover(domain)
        if raw:
            console.print_json(manifest.model_dump_json())
            return
        console.print(Panel(_manifest_table(manifest), title="[bold]WAP manifest ✔ verified", border_style="green"))
        caps = Table(title="Capabilities", show_lines=True, expand=True)
        caps.add_column("id", style="bold magenta", no_wrap=True)
        caps.add_column("description")
        caps.add_column("input", overflow="fold")
        caps.add_column("auth", justify="center")
        for cap in manifest.capabilities:
            props = cap.input_schema.get("properties", {})
            required = set(cap.input_schema.get("required", []))
            params = (
                "\n".join(
                    f"{'*' if name in required else ' '}{name}: {spec.get('type', spec.get('$ref', 'any'))}"
                    for name, spec in props.items()
                )
                or "—"
            )
            caps.add_row(cap.id, cap.description or cap.name, params, "🔒" if cap.requires_auth else "")
        console.print(caps)
        for cap in manifest.capabilities:
            console.print(Panel(JSON.from_data(cap.input_schema), title=f"{cap.id} · input_schema", border_style="dim"))

    try:
        asyncio.run(run())
    except (WAPError, ValueError) as exc:
        _fail(exc)


@app.command()
def verify(
    domain: Annotated[str, typer.Argument(help="Domain or URL to verify.")],
    expect_key: Annotated[
        str | None, typer.Option("--expect-key", help="Fail unless the manifest uses this public key.")
    ] = None,
    insecure: Annotated[bool, typer.Option("--insecure", help="Allow plain HTTP for non-loopback hosts.")] = False,
    timeout: Annotated[float, typer.Option("--timeout", help="Request timeout in seconds.")] = 30.0,
) -> None:
    """Fetch a manifest and report each authenticity check."""

    async def run() -> None:
        pins = [f"{domain.split('://')[-1].split('/')[0]}={expect_key}"] if expect_key else None
        async with _client(insecure, pins, None, None, timeout) as client:
            resolved = await client.resolver.resolve_detailed(domain, force_refresh=True)
        manifest = resolved.manifest
        checks = Table(title=f"Verification of {manifest.domain}", show_header=True)
        checks.add_column("check")
        checks.add_column("result")
        checks.add_row("Schema (WAP/1.0 AgentManifest)", "[green]pass")
        checks.add_row("Domain binding", f"[green]pass[/green] ({manifest.domain})")
        checks.add_row("Embedded Ed25519 signature", "[green]pass")
        checks.add_row(
            "X-WAP-Signature header",
            "[green]pass" if resolved.header_signature_verified else "[yellow]absent",
        )
        checks.add_row("Endpoint origin binding", "[green]pass")
        checks.add_row("Expiry", f"[green]valid until {_ts(manifest.expires_at)}")
        checks.add_row("Pinned key", "[green]match" if expect_key else "[dim]not pinned")
        checks.add_row("Key fingerprint", resolved.fingerprint)
        console.print(checks)

    try:
        asyncio.run(run())
    except (WAPError, ValueError) as exc:
        _fail(exc)


@app.command()
def keygen(
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the private key to this file (mode 0600).")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the key pair as JSON.")] = False,
) -> None:
    """Generate an Ed25519 key pair for signing a business manifest."""
    pair = generate_keypair()
    if out is not None:
        if out.exists():
            err_console.print(f"[red]{out} already exists; refusing to overwrite a key file.")
            raise typer.Exit(code=1)
        out.write_text(pair.private_key + "\n", encoding="utf-8")
        out.chmod(stat.S_IRUSR | stat.S_IWUSR)
    if as_json:
        document = {
            "public_key": pair.public_key,
            "fingerprint": pair.fingerprint,
            "dns_txt_record": txt_record_for(pair.public_key),
        }
        if out is None:
            document["private_key"] = pair.private_key
        else:
            document["private_key_file"] = str(out)
        console.print_json(json.dumps(document))
        return
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan")
    table.add_column()
    if out is None:
        table.add_row("Private key", pair.private_key)
    else:
        table.add_row("Private key", f"written to {out}")
    table.add_row("Public key", pair.public_key)
    table.add_row("Fingerprint", pair.fingerprint)
    table.add_row("DNS TXT (optional)", f'_wap.<your-domain>  TXT  "{txt_record_for(pair.public_key)}"')
    console.print(Panel(table, title="Ed25519 key pair", border_style="green"))
    console.print("[dim]Keep the private key secret. Provide it via WAP_PRIVATE_KEY or WAPServer(private_key=...).")


@app.command()
def serve(
    target: Annotated[str, typer.Argument(help="ASGI application import path, e.g. examples.bakery_server:app")],
    host: Annotated[str, typer.Option("--host", help="Interface to bind.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Port to bind.")] = 8000,
    reload: Annotated[bool, typer.Option("--reload", help="Reload on code changes (development).")] = False,
    app_dir: Annotated[Path, typer.Option("--app-dir", help="Directory added to sys.path before import.")] = Path("."),
) -> None:
    """Run a WAP-enabled ASGI application with uvicorn."""
    try:
        import uvicorn
    except ImportError as exc:
        err_console.print('[red]uvicorn is not installed. Run: pip install "webagent-protocol[server]"')
        raise typer.Exit(code=1) from exc
    sys.path.insert(0, str(app_dir.resolve()))
    uvicorn.run(target, host=host, port=port, reload=reload, app_dir=str(app_dir.resolve()))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
