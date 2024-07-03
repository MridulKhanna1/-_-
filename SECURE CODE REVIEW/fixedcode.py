import os
from flask import Flask, request

app = Flask(__name__)

# curl -X GET "http://localhost:5000/tainted7/touch%20HELLO"
@app.route("/tainted7/<path:something>")
def test_sources_7(something):
    # Sanitize or validate the input if necessary
    # In this example, just using request.remote_addr directly can be unsafe
    remote_address = request.remote_addr

    # Instead of os.system, consider using safer alternatives like subprocess
    # However, in this case, we will simply print the remote address
    print(f"Remote address: {remote_address}")

    return "foo"

if __name__ == "__main__":
    app.run(debug=False)
