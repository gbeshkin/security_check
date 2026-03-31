from flask import Flask, render_template, request, redirect
import subprocess
import json
import os
from pathlib import Path

app = Flask(__name__)
REPORT_PATH = "reports/security-report.json"


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        repo_path = request.form.get("path")

        if not repo_path:
            return "Path required", 400

        subprocess.run(["python", "scanner.py", repo_path])

        return redirect("/report")

    return render_template("index.html")


@app.route("/report")
def report():
    if not os.path.exists(REPORT_PATH):
        return "No report found"

    with open(REPORT_PATH, "r") as f:
        data = json.load(f)

    return render_template("report.html", data=data)


if __name__ == "__main__":
    app.run(debug=True)