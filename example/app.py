from flask import Flask, request, Response
from hook import verify_hook_signature
from datetime import timedelta

app = Flask(__name__)

psk = bytes.fromhex('<insert_your_pre_shared_key_here')

@app.route("/webhook", methods=['POST'])
def webhook():
    sigHeader = request.headers['X-ZTC-Signature']
    body = request.data

    print("HEADER: ", sigHeader)
    print("BODY: ", body)

    if verify_hook_signature(psk, sigHeader, body, timedelta(weeks=65535)):
        return Response(status=200)
    
    return Response(status=403)