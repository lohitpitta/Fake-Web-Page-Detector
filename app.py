from flask import Flask, render_template, request
from urllib.parse import urlparse
import re

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    status = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        # URL format validation
        url_pattern = re.compile(
            r'^(https?:\/\/)'
            r'(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'
            r'(\/.*)?$'
        )

        if not url_pattern.match(url):
            result = "❌ Invalid URL Format"
            status = "danger"

            return render_template(
                "index.html",
                result=result,
                status=status
            )

        score = 0

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # HTTP instead of HTTPS
        if url.startswith("http://"):
            score += 2

        # Suspicious words
        suspicious_words = [
            "login",
            "secure",
            "verify",
            "signin",
            "update",
            "account",
            "banking",
            "confirm",
            "wallet"
        ]

        for word in suspicious_words:
            if word in url.lower():
                score += 1

        # @ symbol
        if "@" in url:
            score += 2

        # Too many hyphens
        if url.count("-") >= 3:
            score += 1

        # Long URL
        if len(url) > 100:
            score += 1

        # IP address detection
        ip_pattern = r"\d+\.\d+\.\d+\.\d+"

        if re.search(ip_pattern, url):
            score += 3

        # Multiple subdomains
        if domain.count(".") >= 3:
            score += 1

        # Final Decision
        if score >= 5:
            result = "🚨 High Risk URL Detected"
            status = "danger"

        elif score >= 2:
            result = "⚠️ Suspicious URL"
            status = "warning"

        else:
            result = "✅ Safe URL"
            status = "safe"

    return render_template(
        "index.html",
        result=result,
        status=status
    )

if __name__ == "__main__":
    app.run(debug=True)
