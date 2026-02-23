from flask import Flask, jsonify, request

app = Flask(__name__)

# Intentional vulnerability: no tenant ownership check.
DATA = {
    "acct_a": {"invoice_1": {"amount": 100}},
    "acct_b": {"invoice_2": {"amount": 200}},
}


def current_account() -> str:
    return request.headers.get("X-Account", "acct_a")


@app.get("/invoice/<invoice_id>")
def get_invoice(invoice_id: str):
    # Vulnerable: attacker can request another account's invoice by ID.
    for account, invoices in DATA.items():
        if invoice_id in invoices:
            return jsonify({"owner": account, "invoice": invoices[invoice_id]})
    return jsonify({"error": "not found"}), 404
