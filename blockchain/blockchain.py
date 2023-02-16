from flask import Flask, render_template, jsonify, request
from argparse import ArgumentParser
from time import time
from flask_cors import CORS
from collections import OrderedDict
import binascii
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse

Mining_Sender = "The Miner"
Mining_Reward = 1
Mining_Difficulty = 2


class Blockchain:
    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace("-", "")
        self.create_block(0, '00')

    def create_block(self, nonce, prev_hash):
        block = {
            "block_number": len(self.chain) + 1,
            "timestamp": time(),
            "transactions": self.transactions,
            "nonce": nonce,
            "prev_hash": prev_hash
        }

        self.transactions = []
        self.chain.append(block)
        return block

    def verify_signature(self, sender_key, signature, transaction):
        public_key = RSA.import_key(binascii.unhexlify(sender_key))
        verifier = pkcs1_15.new(public_key)
        hsh = SHA.new(str(transaction).encode('utf8'))
        try:
            verifier.verify(hsh, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False

    def submit_transactions(self, values,):
        csk = values["confirmation_sender_key"]
        crk = values["confirmation_recipient_key"]
        cv = values["confirmation_value"]
        sign = values["transaction_signature"]

        transactions = OrderedDict({
            "sender_public_key": csk,
            "recipient_address": crk,
            "value": cv,
        })
        if csk == Mining_Sender:
            self.transactions.append(transactions)
            return len(self.chain) + 1
        else:
            signature_transaction = self.verify_signature(
                sender_key=csk, signature=sign, transaction=transactions)
            if signature_transaction:
                self.transactions.append(transactions)
                return len(self.chain) + 1
            else:
                return False

    @staticmethod
    def hash(block):
        block_string = json.dump(block, sort_keys=True).encode("utf8")
        h = hashlib.new("sha256")
        h.update(block_string)
        return h.hexdigest()

    @staticmethod
    def valid_proof(transactions, last_hash, nonce, difficulty=Mining_Difficulty):
        guess = (str(transactions) + str(last_hash) +
                 str(nonce)).encode(("utf8"))
        h = hashlib.new("sha256")
        h.update(guess)
        guess_hash = h.hexdigest()
        return guess_hash[:difficulty] == "0" * difficulty

    def resolve_confilict(self,):
        neighbours = self.nodes
        new_chain = None
        max_lenght = len(self.chain)
        for node in neighbours:
            res = requests.get("http://" + node + "/chain")
            if (res.status_code == 200):
                chain = res.json()["chain"]
            if (len(chain) > max_lenght and self.valid_chain(chain)):
                max_lenght = len(chain)
                new_chain = chain
        if (new_chain):
            self.chain = new_chain
            return True
        return False

    def proof_of_work(self):
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['prev_hash'] != self.hash(last_block):
                return False
            transactions = block["transactions"][:-1]
            transactions_elements = [
                "confirmation_sender_key",
                "confirmation_recipient_key",
                "confirmation_value",
            ]
            transactions = [OrderedDict(
                (k, transaction[k]) for k in transactions_elements) for transactions in transactions]
            if not self.valid_proof(transactions,  block['prev_hash'], block['nonce']):
                return False
            last_block = block
            current_index += 1

        return True

    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        if (parsed_url.netloc):
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError("invalid Url")


blockchain = Blockchain()

app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return render_template("./index.html")


@app.route('/configure')
def configure():
    return render_template("./configure.html")


@app.route('/transactions/new', methods=["POST"])
def new_transactions():
    values = request.form
    required = [
        "confirmation_sender_key",
        "confirmation_recipient_key",
        "confirmation_value",
        "transaction_signature",
    ]
    if not all(key in values for key in required):
        return 'Missing Values', 400

    transaction_results = blockchain.submit_transactions(values)
    if transaction_results == False:
        res = {"message": "Invalid transaction"}
        return jsonify(res), 406
    else:
        res = {"message": "transaction will added to Block"}
        return jsonify(res), 201


@app.route('/transactions/get', methods=["Get"])
def get_transactions():
    transaction = blockchain.transactions
    res = {"transaction": transaction}
    return jsonify(res), 200


@app.route('/mine', methods=["Get"])
def get_mine():
    nonce = blockchain.proof_of_work()

    blockchain.submit_transactions({
        "confirmation_sender_key": Mining_Sender,
        "confirmation_recipient_key": blockchain.node_id,
        "confirmation_value": Mining_Reward,
        "transaction_signature": '',
    })
    last_block = blockchain.chain[-1]
    hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, hash)
    res = {"block": block}
    return jsonify(res), 200


@app.route('/chain', methods=["Get"])
def get_chain():
    res = {"chain": blockchain.chain}
    return jsonify(res), 200


@app.route('/nodes/get', methods=["Get"])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/nodes/register', methods=["POST"])
def register_node():
    values = request.form
    print("values", values)
    nodes = values.get("nodes").replace(' ', '').split(",")
    if nodes is None:
        return "Error: Please Supply a valid list", 400
    for node in nodes:
        blockchain.register_node(node)
    res = {
        "Message": "Nodes have been added",
        "total_nodes": [node for node in blockchain.nodes]
    }
    return jsonify(res), 200


if (__name__ == '__main__'):
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default=5001,
                        type=int, help="port to listen")
    args = parser.parse_args()
    port = args.port

    app.run(host="localhost", port=port, debug=True)
