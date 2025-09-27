import requests
import json
import base64
import hmac
import hashlib
import datetime
from urllib.parse import quote, urlencode
from decouple import config # Para ler .env localmente

# --- CONFIGURAÇÕES ---
# Lendo credenciais do .env (para testes locais)
# No GitHub Actions, usaremos secrets diretamente
AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID')
AWS_SECRET_KEY = config('AWS_SECRET_KEY')
AWS_PARTNER_TAG = config('AWS_PARTNER_TAG') # Ex: 'seudominio-20' ou 'lojanome-20'
HOST = 'webservices.amazon.com.br' # Para o Brasil
REGION = 'sa-east-1' # Para o Brasil
PATH = '/paapi5/searchitems' # Caminho da API para pesquisa de itens

# IDs dos produtos que queremos buscar (exemplo, você pode alterar)
# Você pode pesquisar por termos também, mas para começar, IDs são mais diretos
PRODUCT_ASINS = [
    "B0C8V2Y3N1", # Exemplo de ASIN de fone de ouvido
    "B0BFG21L33", # Exemplo de ASIN de um livro
    "B0B9V8499B"  # Exemplo de ASIN de um teclado
]

# --- FUNÇÃO DE AUTENTICAÇÃO SIGV4 ---
# Esta função é essencial para assinar as requisições da PA API
def sign_paapi_request(
    access_key,
    secret_key,
    host,
    region,
    path,
    payload
):
    method = 'POST'
    canonical_uri = path
    content_type = 'application/json; charset=utf-8'

    # 1. Create a Canonical Request
    hashed_payload = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    current_time = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    date_stamp = datetime.datetime.utcnow().strftime('%Y%m%d')

    canonical_headers = (
        f"content-type:{content_type}\\n"
        f"host:{host}\\n"
        f"x-amz-date:{current_time}\\n"
    )
    signed_headers = "content-type;host;x-amz-date"

    canonical_request = (
        f"{method}\\n"
        f"{canonical_uri}\\n"
        "\\n" # Canonical Query String (empty for POST with payload)
        f"{canonical_headers}\\n"
        f"{signed_headers}\\n"
        f"{hashed_payload}"
    )

    # 2. Create the String to Sign
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f"{date_stamp}/{region}/ProductAdvertisingAPI/aws4_request"
    hashed_canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    string_to_sign = (
        f"{algorithm}\\n"
        f"{current_time}\\n"
        f"{credential_scope}\\n"
        f"{hashed_canonical_request}"
    )

    # 3. Calculate the Signature
    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    k_date = sign(('AWS4' + secret_key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, 'ProductAdvertisingAPI')
    k_signing = sign(k_service, 'aws4_request')

    signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    # 4. Add signing information to the request
    authorization_header = (
        f"{algorithm} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        'Host': host,
        'Content-Type': content_type,
        'X-Amz-Date': current_time,
        'X-Amz-Target': 'com.amazon.paapi5.v1.ProductAdvertisingAPI.SearchItems', # Para SearchItems
        'Authorization': authorization_header
    }
    return headers

# --- FUNÇÃO PRINCIPAL PARA BUSCAR PRODUTOS ---
def get_amazon_products(asins):
    payload = {
        "ItemIds": asins,
        "Resources": [
            "Images.Primary.Medium",
            "ItemInfo.Title",
            "Offers.Listings.Price
