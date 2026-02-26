from flask import Flask, render_template, request
import random

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None

    if request.method == "POST":
        # Simulate packet features
        packet = [random.random() for _ in range(10)]

        # Simulate model prediction
        result = random.choice([0, 1])

        if result == 0:
            prediction = "Normal Traffic"
        else:
            prediction = "Attack Detected"

    return render_template("index.html", prediction=prediction)

if __name__ == "__main__":
    app.run(debug=True)
