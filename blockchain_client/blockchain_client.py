from flask import Flask, render_template, jsonify, request
from argparse import ArgumentParser
from time import time
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA


class Transaction:
    def __init__(self, sender_public_key, sender_private_key, recipient_address, value):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def to_dict(self):
        return OrderedDict({
            "sender_public_key": self.sender_public_key,
            "recipient_address": self.recipient_address,
            "value": self.value,
        })

    def sign_transaction(self):
        private_key = RSA.import_key(
            binascii.unhexlify(self.sender_private_key))
        signature = pkcs1_15.new(private_key)
        hsh = SHA.new(str(self.to_dict()).encode('utf8'))
        print("hsh", hsh)
        return binascii.hexlify(signature.sign(hsh)).decode("ascii")


app = Flask(__name__)


@app.route('/')
def index():
    return render_template("./index.html")


@app.route('/make_transaction')
def make_transaction():
    return render_template("./make_transaction.html")


@app.route('/generate/transaction', methods=["POST"])
def generate_transaction():
    sender_public_key = request.form["sender_public_key"]
    sender_private_key = request.form["sender_private_key"]
    recipient_address = request.form["recipient_public_key"]
    value = request.form["value"]
    transaction = Transaction(
        sender_public_key, sender_private_key, recipient_address, value)

    res = {
        "transaction": transaction.to_dict(),
        "sign": transaction.sign_transaction()
    }
    return jsonify(res), 200


@app.route('/view_transactions')
def view_transactions():
    return render_template("./view_transactions.html")


@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    publick_key = private_key.publickey()
    res = {
        "private_key": binascii.hexlify(private_key.export_key(format("DER"))).decode("ascii"),
        "publick_key": binascii.hexlify(publick_key.export_key(format("DER"))).decode("ascii"),
    }
    return jsonify(res), 200


if (__name__ == '__main__'):
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default=8081,
                        type=int, help="port to listen")
    args = parser.parse_args()
    port = args.port

    app.run(host="localhost", port=port, debug=True)
