"""Command line entry points."""

from __future__ import annotations

import argparse
from pathlib import Path

from keylemon.broker import AttestationBroker
from keylemon.keylime_client import KeylimeClient
from keylemon.policy import AttestationPolicy
from keylemon.server import serve
from keylemon.signing import ClaimSigner
from keylemon.tee.mock import MockTEEVerifier


def load_or_create_signer(path: Path) -> ClaimSigner:
    if path.exists():
        return ClaimSigner.from_private_pem(path.read_bytes())
    signer = ClaimSigner.generate()
    path.write_bytes(signer.private_pem())
    return signer


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Keylemon attestation broker PoC")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--signing-key", default=Path("keylemon-signing-key.pem"), type=Path)
    parser.add_argument("--keylime-url")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    signer = load_or_create_signer(args.signing_key)
    policy = AttestationPolicy.from_yaml(args.policy.read_text(encoding="utf-8"))
    keylime_client = KeylimeClient(args.keylime_url, signer) if args.keylime_url else None
    broker = AttestationBroker(
        signer=signer,
        policy=policy,
        keylime_client=keylime_client,
        tee_verifiers={"mock": MockTEEVerifier(signer)},
    )
    serve(broker, args.host, args.port)


if __name__ == "__main__":
    main()
