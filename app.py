from flask import Flask, render_template, request
import time

app = Flask(__name__)


# Replace this with your existing scan function
def run_scan():
    # Simulate scanning
    time.sleep(2)
    return "Scan complete! Found 5 active connections."


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        result = run_scan()
    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
