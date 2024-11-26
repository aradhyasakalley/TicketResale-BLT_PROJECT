import os
import hashlib
import json
import qrcode
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# CORS middleware setup to allow requests from React (localhost:3000)
origins = ["http://localhost:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure the tickets_data directory and qr_code folder exist
os.makedirs("tickets_data", exist_ok=True)
os.makedirs("qr_code", exist_ok=True)

class BuyTicketRequest(BaseModel):
    name: str
    unique_id: str
    event_id: str

class ResellTicketRequest(BaseModel):
    ticket_id: str
    new_owner_name: str
    new_owner_unique_id: str

class ValidateTicketRequest(BaseModel):
    ticket_id: str

class TransferTicketRequest(BaseModel):
    ticket_id: str
    new_owner_name: str

# Generate RSA key pair
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_key, public_pem

# Generate a unique ticket
def generate_ticket(ticket_details, owner_public_key):
    ticket_id = hashlib.sha256(ticket_details.encode()).hexdigest()
    ticket_hash = hashlib.sha256(ticket_details.encode()).hexdigest()
    ticket = {
        'ticket_id': ticket_id,
        'owner_public_key': owner_public_key,
        'details': ticket_details,
        'ticket_hash': ticket_hash
    }
    return ticket

# Sign the ticket
def sign_ticket(private_key: RSAPrivateKey, ticket_hash: str):
    signature = private_key.sign(
        ticket_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify ticket ownership
def verify_ownership(public_key_pem: str, ticket_hash: str, signature: bytes, original_public_key_pem: str):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        public_key.verify(
            signature,
            ticket_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return public_key_pem == original_public_key_pem
    except Exception:
        return False

# Generate QR code for the ticket
def generate_qr_code(ticket_id):
    qr = qrcode.make(ticket_id)
    qr.save(f"qr_code/{ticket_id}_qr.png")

# Endpoint to Buy a Ticket
@app.post("/buy-ticket")
async def buy_ticket(request: BuyTicketRequest):
    private_key, public_key_pem = generate_keys()
    ticket_details = f"{request.name}:{request.unique_id}:{request.event_id}"
    ticket = generate_ticket(ticket_details, public_key_pem)
    signature = sign_ticket(private_key, ticket['ticket_hash'])

    # Save ticket information with transaction history
    ticket_file = f"tickets_data/{ticket['ticket_id']}.json"
    with open(ticket_file, "w") as f:
        json.dump({
            "ticket": ticket,
            "signature": signature.hex(),
            "public_key_pem": public_key_pem,
            "owner_name": request.name,
            "owner_unique_id": request.unique_id,
            "transactions": [{
                "owner_name": request.name,
                "owner_unique_id": request.unique_id,
                "action": "bought"
            }]
        }, f)

    generate_qr_code(ticket['ticket_id'])

    return {
        "message": "Ticket purchased successfully",
        "ticket_id": ticket['ticket_id'],
        "qr_code_path": f"qr_code/{ticket['ticket_id']}_qr.png"
    }

# Endpoint to Resell a Ticket
@app.post("/resell-ticket")
async def resell_ticket(request: ResellTicketRequest):
    ticket_file = f"tickets_data/{request.ticket_id}.json"
    try:
        with open(ticket_file, "r") as f:
            data = json.load(f)
            ticket = data['ticket']
            original_ticket_hash = ticket['ticket_hash']
            original_owner_name = data['owner_name']
            original_owner_unique_id = data['owner_unique_id']

        # Update ticket details and hash with new owner
        new_ticket_details = f"{request.new_owner_name}:{request.new_owner_unique_id}:{ticket['details'].split(':', 2)[2]}"
        new_ticket_hash = hashlib.sha256(new_ticket_details.encode()).hexdigest()

        # Generate new keys for the new owner
        new_private_key, new_public_key_pem = generate_keys()
        new_signature = sign_ticket(new_private_key, new_ticket_hash)

        # Invalidate previous ticket and add resale transaction history
        data.update({
            "ticket": {
                "ticket_id": request.ticket_id,
                "owner_public_key": new_public_key_pem,
                "details": new_ticket_details,
                "ticket_hash": new_ticket_hash,
                "original_ticket_hash": original_ticket_hash
            },
            "signature": new_signature.hex(),
            "public_key_pem": new_public_key_pem,
            "owner_name": request.new_owner_name,
            "owner_unique_id": request.new_owner_unique_id
        })
        data["transactions"].append({
            "owner_name": request.new_owner_name,
            "owner_unique_id": request.new_owner_unique_id,
            "action": "resold",
            "reseller_name": original_owner_name,
            "reseller_unique_id": original_owner_unique_id
        })

        # Mark the previous ticket as resold (invalidate it)
        prev_ticket_file = f"tickets_data/{ticket['ticket_id']}_invalid.json"
        with open(prev_ticket_file, "w") as f:
            json.dump({
                "ticket": ticket,
                "signature": data['signature'],
                "public_key_pem": data['public_key_pem'],
                "owner_name": original_owner_name,
                "owner_unique_id": original_owner_unique_id,
                "transactions": [{
                    "owner_name": original_owner_name,
                    "owner_unique_id": original_owner_unique_id,
                    "action": "resold"
                }]
            }, f)

        with open(ticket_file, "w") as f:
            json.dump(data, f)

        generate_qr_code(request.ticket_id + "_resold")

        return {
            "message": "Ticket resold successfully",
            "new_ticket_hash": new_ticket_hash,
            "qr_code_path": f"qr_code/{request.ticket_id}_resold_qr.png"
        }

    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Ticket not found")

# Endpoint to Validate a Ticket
@app.post("/validate-ticket")
async def validate_ticket(request: ValidateTicketRequest):
    ticket_file = f"tickets_data/{request.ticket_id}.json"
    try:
        with open(ticket_file, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Ticket not found")

    ticket = data['ticket']
    signature = bytes.fromhex(data['signature'])
    public_key_pem = data['public_key_pem']

    is_valid = verify_ownership(public_key_pem, ticket['ticket_hash'], signature, ticket['owner_public_key'])
    if is_valid:
        return {"message": "Ticket is valid"}
    else:
        return {"message": "Ticket is invalid"}

# Endpoint to Transfer a Ticket
@app.post("/transfer-ticket")
async def transfer_ticket(request: TransferTicketRequest):
    ticket_file = f"tickets_data/{request.ticket_id}.json"
    try:
        with open(ticket_file, "r") as f:
            data = json.load(f)
            ticket = data['ticket']
            original_owner_name = data['owner_name']
            original_owner_unique_id = data['owner_unique_id']

        # Update ticket details with new owner
        new_ticket_details = f"{request.new_owner_name}:{original_owner_unique_id}:{ticket['details'].split(':', 2)[2]}"
        new_ticket_hash = hashlib.sha256(new_ticket_details.encode()).hexdigest()

        # Generate new keys for the new owner
        new_private_key, new_public_key_pem = generate_keys()
        new_signature = sign_ticket(new_private_key, new_ticket_hash)

        # Update ticket data and add transfer transaction
        data.update({
            "ticket": {
                "ticket_id": request.ticket_id,
                "owner_public_key": new_public_key_pem,
                "details": new_ticket_details,
                "ticket_hash": new_ticket_hash
            },
            "signature": new_signature.hex(),
            "public_key_pem": new_public_key_pem,
            "owner_name": request.new_owner_name,
            "owner_unique_id": original_owner_unique_id
        })

        data["transactions"].append({
            "owner_name": request.new_owner_name,
            "owner_unique_id": original_owner_unique_id,
            "action": "transferred"
        })

        with open(ticket_file, "w") as f:
            json.dump(data, f)

        generate_qr_code(request.ticket_id + "_transferred")

        return {
            "message": "Ticket transferred successfully",
            "qr_code_path": f"qr_code/{request.ticket_id}_transferred_qr.png"
        }

    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Ticket not found")

# Endpoint to Get Transaction History of a Ticket
@app.get("/transaction-history/{ticket_id}")
async def transaction_history(ticket_id: str):
    ticket_file = f"tickets_data/{ticket_id}.json"
    try:
        with open(ticket_file, "r") as f:
            data = json.load(f)
        return {"transactions": data['transactions']}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Ticket not found")

