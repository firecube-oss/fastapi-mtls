import argparse
from ssl import CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED

from fastapi import FastAPI
from loguru import logger

from trustme_issuers import (CertificateType, CryptoCoordinator, CryptoDumper,
                             PrimitivePaths)

root_ca = CryptoCoordinator(
    certificate_name="Emulated Root", certificate_type=CertificateType.ROOT
)
hacker_root = CryptoCoordinator("Hacker Root", certificate_type=CertificateType.ROOT)
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
hacker_ca = CryptoCoordinator(
    certificate_name="Hacker CA",
    certificate_type=CertificateType.INTERMEDIATE,
    certificate_signer=hacker_root.certificate_signer,
)
client_certificate = CryptoCoordinator(
    certificate_name="Client",
    certificate_type=CertificateType.LEAF,
    certificate_signer=private_ca.certificate_signer,
)
hacker_certificate = CryptoCoordinator(
    certificate_name="Client from Hacker",
    certificate_type=CertificateType.LEAF,
    certificate_signer=hacker_ca.certificate_signer,
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


def openssl_debug_output():
    logger.warning(
        f"Test Valid Client Cert: openssl s_client -connect 127.0.0.1:5000 -cert '{client_certificate.storage_path/PrimitivePaths.CERTIFICATE}' -key '{client_certificate.storage_path/PrimitivePaths.PRIVATE_KEY}'"
    )
    logger.warning(
        f"Test Bad Client Cert: openssl s_client -connect 127.0.0.1:5000 -cert '{hacker_certificate.storage_path/PrimitivePaths.CERTIFICATE}' -key '{hacker_certificate.storage_path/PrimitivePaths.PRIVATE_KEY}'"
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
    parser.add_argument("--hypercorn", action="store_true")
    args = parser.parse_args()
    openssl_debug_output()
    if args.hypercorn:
        run_with_hypercorn()
    else:
        run_with_uvicorn()
