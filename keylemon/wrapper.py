"""Application-transparent TCP wrapper skeleton.

This module provides the enforcement boundary for the PoC.  It is intentionally
small: production deployments should add robust lifecycle management, metrics,
revocation streaming, and service-mesh integration.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509

from keylemon.certificates import certificate_matches_attestation_result
from keylemon.models import AttestationResult


@dataclass(slots=True)
class TCPWrapperConfig:
    listen_host: str
    listen_port: int
    upstream_host: str
    upstream_port: int
    certfile: Path
    keyfile: Path
    cafile: Path
    server_side: bool = False


class TCPWrapper:
    def __init__(self, config: TCPWrapperConfig) -> None:
        self.config = config

    async def run(self) -> None:
        ssl_ctx = self._ssl_context()
        server = await asyncio.start_server(
            self._handle_client,
            self.config.listen_host,
            self.config.listen_port,
            ssl=ssl_ctx if self.config.server_side else None,
        )
        async with server:
            await server.serve_forever()

    def _ssl_context(self) -> ssl.SSLContext:
        purpose = ssl.Purpose.CLIENT_AUTH if self.config.server_side else ssl.Purpose.SERVER_AUTH
        ctx = ssl.create_default_context(purpose, cafile=str(self.config.cafile))
        ctx.load_cert_chain(str(self.config.certfile), str(self.config.keyfile))
        if self.config.server_side:
            ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ssl_ctx = None if self.config.server_side else self._ssl_context()
        upstream_reader, upstream_writer = await asyncio.open_connection(
            self.config.upstream_host,
            self.config.upstream_port,
            ssl=ssl_ctx,
            server_hostname=self.config.upstream_host if ssl_ctx else None,
        )
        await asyncio.gather(
            self._pipe(reader, upstream_writer),
            self._pipe(upstream_reader, writer),
        )

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


def validate_peer_attestation_certificate(cert_pem: str | bytes, expected_result: AttestationResult) -> bool:
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode("utf-8")
    cert = x509.load_pem_x509_certificate(cert_pem)
    return certificate_matches_attestation_result(cert, expected_result)
