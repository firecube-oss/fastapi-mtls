from enum import Enum, StrEnum
from pathlib import Path
from typing import List, Union

import trustme
from cryptography.hazmat.primitives.serialization import (
    NoEncryption,
    load_pem_private_key,
    pkcs12,
)
from cryptography.x509 import load_pem_x509_certificates
from loguru import logger


class CertificateType(Enum):
    ROOT = "ROOT"
    INTERMEDIATE = "INTERMEDIATE"
    LEAF = "LEAF"


class PrimitivePaths(StrEnum):
    FULLCHAIN = "fullchain.pem"
    CERTIFICATE = "certificate.crt"
    PRIVATE_KEY = "private.key"
    PFX = "client.pfx"
    CERTIFICATE_AUTHORITIES = "Certificate Authorities"
    LEAFS = "Certificates"


class CryptoCoordinator:
    def __init__(
        self,
        certificate_name: str,
        certificate_type: CertificateType,
        certificate_signer: Union[trustme.CA, trustme.LeafCert] = None,
    ) -> None:
        self._certificate_name = certificate_name
        self._certificate_type = certificate_type
        self._certificate_signer = certificate_signer
        if self.exists:
            self._certificate_for_signing = self.load()
            logger.info(f"Found Existing CA {certificate_name} -- Loading")
        else:
            self._certificate_for_signing = self.create_and_dump()
            logger.info(f"Did not find Existing CA {certificate_name} -- Creating")

    @property
    def storage_path(self) -> Path:
        if self._certificate_type == CertificateType.LEAF:
            self._storage_path = Path(
                f"{PrimitivePaths.LEAFS}/{self._certificate_name}"
            )
        else:
            self._storage_path = Path(
                f"{PrimitivePaths.CERTIFICATE_AUTHORITIES}/{self._certificate_name}"
            )
        return self._storage_path

    @property
    def exists(self) -> bool:
        return self.storage_path.exists()

    @property
    def certificate_signer(self) -> str:
        return self._certificate_for_signing

    def create_and_dump(self):
        certificate = None
        if self._certificate_type == CertificateType.ROOT:
            self.storage_path.mkdir(parents=True, exist_ok=True)
            certificate = trustme.CA(
                organization_name=self._certificate_name,
                organization_unit_name=self._certificate_name,
            )
            certificate.cert_pem.write_to_path(
                self._storage_path / PrimitivePaths.CERTIFICATE
            )
            certificate.private_key_pem.write_to_path(
                self._storage_path / PrimitivePaths.PRIVATE_KEY
            )

        if self._certificate_type == CertificateType.INTERMEDIATE:
            self.storage_path.mkdir(parents=True, exist_ok=True)
            certificate = trustme.CA(
                organization_name=self._certificate_name,
                parent_cert=self._certificate_signer,
                organization_unit_name=self._certificate_name,
            )
            certificate.cert_pem.write_to_path(
                self._storage_path / PrimitivePaths.CERTIFICATE
            )
            certificate.private_key_pem.write_to_path(
                self._storage_path / PrimitivePaths.PRIVATE_KEY
            )

        if (
            self._certificate_type == CertificateType.LEAF
            and self._certificate_name.startswith("Server")
        ):
            self.storage_path.mkdir(parents=True, exist_ok=True)
            certificate = self._certificate_signer.issue_cert(
                "127.0.0.1",
                "localhost",
                "mtls.127.0.1.sslip.io",
                common_name=self._certificate_name,
                organization_name=self._certificate_name,
                organization_unit_name=self._certificate_name,
            )
            certificate.cert_chain_pems[0].write_to_path(
                self._storage_path / PrimitivePaths.CERTIFICATE
            )
            certificate.private_key_pem.write_to_path(
                self._storage_path / PrimitivePaths.PRIVATE_KEY
            )

        if (
            self._certificate_type == CertificateType.LEAF
            and self._certificate_name.startswith("Client")
        ):
            self.storage_path.mkdir(parents=True, exist_ok=True)
            certificate = self._certificate_signer.issue_cert(
                common_name=self._certificate_name,
                organization_name=self._certificate_name,
            )
            certificate.cert_chain_pems[0].write_to_path(
                self._storage_path / PrimitivePaths.CERTIFICATE
            )
            certificate.private_key_pem.write_to_path(
                self._storage_path / PrimitivePaths.PRIVATE_KEY
            )

        return certificate

    def load(self):
        if (
            self._certificate_type == CertificateType.INTERMEDIATE
            or self._certificate_type == CertificateType.ROOT
        ):
            cert_path = self._storage_path / PrimitivePaths.CERTIFICATE
            key_path = self._storage_path / PrimitivePaths.PRIVATE_KEY
            certificate = trustme.CA.from_pem(
                cert_bytes=cert_path.read_bytes(),
                private_key_bytes=key_path.read_bytes(),
            )
            return certificate

        else:
            return None


class CryptoDumper:

    @classmethod
    def dump_full_chain(
        self,
        leaf: CryptoCoordinator = None,
        intermediates: List[CryptoCoordinator] = None,
        root: CryptoCoordinator = None,
    ):
        fullchain_path = None
        if leaf:
            fullchain_path = leaf.storage_path / PrimitivePaths.FULLCHAIN
            cert_path = leaf.storage_path / PrimitivePaths.CERTIFICATE
            fullchain_path.write_bytes(cert_path.read_bytes())
        else:
            fullchain_path = intermediates[0].storage_path / PrimitivePaths.FULLCHAIN
            fullchain_path.write_bytes(b"")

        for intermediate in intermediates:
            cert_path = intermediate.storage_path / PrimitivePaths.CERTIFICATE
            fullchain_path.open("ab").write(cert_path.read_bytes())
        cert_path = root.storage_path / PrimitivePaths.CERTIFICATE
        fullchain_path.open("ab").write(cert_path.read_bytes())

    @classmethod
    def dump_pfx(self, leaf: CryptoCoordinator):
        fullchain_path = leaf.storage_path / PrimitivePaths.FULLCHAIN
        private_key_path = leaf.storage_path / PrimitivePaths.PRIVATE_KEY
        pfx_path = leaf.storage_path / PrimitivePaths.PFX
        certificates = load_pem_x509_certificates(fullchain_path.read_bytes())
        pfx = pkcs12.serialize_key_and_certificates(
            b"mTLS Client Cert",
            key=load_pem_private_key(private_key_path.read_bytes(), password=None),
            cert=certificates[0],  # leaf
            cas=certificates[1:],  # root and intermediates
            encryption_algorithm=NoEncryption(),
        )
        pfx_path.write_bytes(pfx)
