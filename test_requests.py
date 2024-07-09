import requests

response = requests.get(
    "https://127.0.0.1:5000",
    verify="Certificates/Server/fullchain.pem",
    cert=("Certificates/Client/certificate.crt", "Certificates/Client/private.key"),
)
print(response)
