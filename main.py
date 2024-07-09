import argparse
from ssl import CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED

from fastapi import FastAPI
from loguru import logger

from trustme_issuers import (
    CertificateType,
    CryptoCoordinator,
    CryptoDumper,
    PrimitivePaths,
)

root_ca = CryptoCoordinator(
    certificate_name="Emulated Root", certificate_type=CertificateType.ROOT
)

public_ca = CryptoCoordinator(
    certificate_name="Emulated Public CA",
    certificate_type=CertificateType.INTERMEDIATE,
    certificate_signer=root_ca.certificate_signer,
)
private_ca = CryptoCoordinator(
    certificate_name="Emulated Private CA",
    certificate_type=CertificateType.INTERMEDIATE,
    certificate_signer=root_ca.certificate_signer,
)

client_certificate = CryptoCoordinator(
    certificate_name="Client",
    certificate_type=CertificateType.LEAF,
    certificate_signer=private_ca.certificate_signer,
)

server_certificate = CryptoCoordinator(
    certificate_name="Server",
    certificate_type=CertificateType.LEAF,
    certificate_signer=public_ca.certificate_signer,
)

# create fullchain.pems we are cheating a little in the client fullchain and including the server intermediate
CryptoDumper.dump_full_chain(
    leaf=client_certificate, intermediates=[private_ca, public_ca], root=root_ca
)
CryptoDumper.dump_full_chain(
    leaf=server_certificate, intermediates=[public_ca], root=root_ca
)
CryptoDumper.dump_full_chain(intermediates=[private_ca], root=root_ca)

CryptoDumper.dump_pfx(leaf=client_certificate)

app = FastAPI()


@app.get("/")
def hello():
    return {"message": "Hello World"}


def hacker_ca(openssl_hints: bool):
    # Optional: Create a Hacker CA PFX (to validate that Client Certs are verified)
    hacker_root = CryptoCoordinator(
        "Hacker Root", certificate_type=CertificateType.ROOT
    )
    hacker_ca = CryptoCoordinator(
        certificate_name="Hacker CA",
        certificate_type=CertificateType.INTERMEDIATE,
        certificate_signer=hacker_root.certificate_signer,
    )
    hacker_certificate = CryptoCoordinator(
        certificate_name="Client from Hacker",
        certificate_type=CertificateType.LEAF,
        certificate_signer=hacker_ca.certificate_signer,
    )
    CryptoDumper.dump_full_chain(
        leaf=hacker_certificate, intermediates=[hacker_ca], root=hacker_root
    )
    CryptoDumper.dump_pfx(leaf=hacker_certificate)
    if openssl_hints:
        logger.info(
            f"""\n Test Bad Client Cert issued by Hacker CA: 
            \n openssl s_client -connect 127.0.0.1:5000 -cert '{hacker_certificate.storage_path/PrimitivePaths.CERTIFICATE}' -key '{hacker_certificate.storage_path/PrimitivePaths.PRIVATE_KEY}'"""
        )

    logger.info(
        f"""\n To install Hacker Client Certificate in system certificates (for browser testing): 
            \n Get-ChildItem -Path '{hacker_certificate.storage_path/PrimitivePaths.PFX}' | Import-PfxCertificate -CertStoreLocation Cert:\CurrentUser\My"""
    )


def hints(openssl_hints: bool):
    logger.warning(
        f"""\n You will need to install root certificate and Client Certificate Bundle. Run: 
        \n ⌨️  Get-ChildItem -Path '{root_ca.storage_path/PrimitivePaths.CERTIFICATE}' | Import-Certificate -CertStoreLocation cert:\CurrentUser\Root 
        \n ⌨️  Get-ChildItem -Path '{client_certificate.storage_path/PrimitivePaths.PFX}' | Import-PfxCertificate -CertStoreLocation Cert:\CurrentUser\My 
        \n 🍎 security import '{root_ca.storage_path/PrimitivePaths.CERTIFICATE}' -k ~/Library/Keychains/login.keychain
        \n 🐧 Coming Soon?
        """
    )
    if openssl_hints:
        logger.info(
            f"""\n Test Valid Client Cert with OpenSSL
            \n openssl s_client -connect 127.0.0.1:5000 -cert '{client_certificate.storage_path/PrimitivePaths.CERTIFICATE}' -key '{client_certificate.storage_path/PrimitivePaths.PRIVATE_KEY}'"""
        )


def run_with_uvicorn():
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=5000,
        log_level="trace",
        ssl_keyfile=str(server_certificate.storage_path / PrimitivePaths.PRIVATE_KEY),
        ssl_certfile=str(server_certificate.storage_path / PrimitivePaths.FULLCHAIN),
        ssl_cert_reqs=CERT_REQUIRED,
        ssl_ca_certs=str(private_ca.storage_path / PrimitivePaths.FULLCHAIN),
    )


def run_with_hypercorn():
    import asyncio

    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    config = Config()
    config.bind = ["127.0.0.1:5000"]
    config.certfile = str(server_certificate.storage_path / PrimitivePaths.FULLCHAIN)
    config.keyfile = str(server_certificate.storage_path / PrimitivePaths.PRIVATE_KEY)
    config.verify_mode = CERT_REQUIRED
    config.ca_certs = str(private_ca.storage_path / PrimitivePaths.FULLCHAIN)
    config.loglevel = "DEBUG"
    loop = asyncio.get_event_loop()
    asyncio.run(serve(app, config))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run a FastAPI Server with mTLS Support"
    )
    parser.add_argument(
        "--hypercorn",
        action="store_true",
        help="If set as a flag it will use Hypercorn ASGI Server",
    )
    parser.add_argument(
        "--hacker-ca",
        action="store_true",
        help='If set as a flag it will create a "Hacker CA" to validate client certs',
    )
    parser.add_argument(
        "--openssl-hints",
        action="store_true",
        help="Output OpenSSL s_client commands",
    )
    args = parser.parse_args()
    if args.hacker_ca:
        logger.info("Creating A Hacker CA")
        hacker_ca(openssl_hints=args.openssl_hints)
    hints(openssl_hints=args.openssl_hints)
    if args.hypercorn:
        run_with_hypercorn()
    else:
        run_with_uvicorn()
