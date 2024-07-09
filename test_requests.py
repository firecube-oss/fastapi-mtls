import requests

response = requests.get(
    "https://127.0.0.1:5000",
    verify="Certificates/Server/fullchain.pem",
    cert=("Certificates/Client/certificate.crt", "Certificates/Client/private.key"),
)
print(response)

try:
    response = requests.get(
        "https://127.0.0.1:5000",
        verify="Certificates/Server/fullchain.pem",
        cert=(
            "Certificates/Client from Hacker/certificate.crt",
            "Certificates/Client from Hacker/private.key",
        ),
    )
except requests.exceptions.ConnectionError as e:
    print(f" this has failed as expected. {e}")
