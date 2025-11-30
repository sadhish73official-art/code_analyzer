# backend.py

import re
import hashlib
from collections import Counter
import difflib
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Allow your ngrok & Lovable domains (safe)
CORS(app, origins="*")


# ============================================================
# 1. Overview
# ============================================================
def generate_overview(code):
    lines = code.strip().splitlines()
    return "\n".join(lines[:4]) if lines else "No code provided."


# ============================================================
# 2. Language detection
# ============================================================
def detect_language(code):
    patterns = {
        "Python": ["def ", "import "],
        "JavaScript": ["function ", "console.log"],
        "Java": ["public static void main", "class "],
        "C++": ["#include"],
        "TypeScript": ["export const", "import type"]
    }
    for lang, sigs in patterns.items():
        if any(sig in code for sig in sigs):
            return lang
    return "Unknown"


# ============================================================
# 3. Framework detection
# ============================================================
def detect_framework(code):
    frameworks = {
        "Flask": "from flask",
        "Django": "django.",
        "React": "useState(",
        "Express": "express()",
        "Spring": "@SpringBootApplication",
        "Vue": "new Vue(",
        "Laravel": "Illuminate",
    }
    for name, sig in frameworks.items():
        if sig in code:
            return name
    return "Unknown"


# ============================================================
# 4. Detect open passwords
# ============================================================
def find_passwords(code):
    return re.findall(
        r"(password|passwd|pwd)\s*=\s*['\"]([^'\"]+)['\"]",
        code,
        flags=re.I
    )


# ============================================================
# 5. Detect API keys
# ============================================================
def find_api_keys(code):
    patterns = [
        r"API_KEY\s*=\s*['\"].+?['\"]",
        r"SECRET_KEY\s*=\s*['\"].+?['\"]",
        r"ACCESS_TOKEN\s*=\s*['\"].+?['\"]",
        r"BEARER\s+[A-Za-z0-9._\-]+",
        r"-----BEGIN PRIVATE KEY-----"
    ]

    keys = []
    for pattern in patterns:
        keys.extend(re.findall(pattern, code))

    return keys


# ============================================================
# 6. Optimization suggestions
# ============================================================
def optimization_suggestions(code):
    suggestions = []

    if "print(" in code:
        suggestions.append("Avoid print() statements in production.")

    if len(code.splitlines()) > 200:
        suggestions.append("Large file detected — consider splitting into modules.")

    return suggestions if suggestions else ["Looks OK."]


# ============================================================
# 7. Naming conventions
# ============================================================
def check_naming_conventions(code, language):
    problems = []

    # Python — snake_case preferred
    if language == "Python":
        camel = re.findall(r"\b([a-z]+[A-Z][a-zA-Z0-9_]*)\b", code)
        if camel:
            problems.append(f"CamelCase variable names found: {', '.join(set(camel))}")

    # JS/TS — camelCase preferred
    if language in ("JavaScript", "TypeScript"):
        snake = re.findall(r"\b([a-z]+_[a-z0-9_]+)\b", code)
        if snake:
            problems.append(f"Snake_case found in JS/TS: {', '.join(set(snake))}")

    # Class names should be PascalCase
    classes = re.findall(r"class\s+([A-Za-z_][A-Za-z0-9_]*)", code)
    bad = [c for c in classes if not re.match(r"^[A-Z][A-Za-z0-9]+$", c)]
    if bad:
        problems.append(f"Classes not in PascalCase: {', '.join(bad)}")

    return "Pass" if not problems else "Fail: " + "; ".join(problems)


# ============================================================
# 8. Indentation check
# ============================================================
def check_indentation(code):
    lines = [l for l in code.splitlines() if l.strip()]
    if not lines:
        return "No indentation detected"

    spaces = sum(1 for l in lines if l.startswith(" "))
    tabs = sum(1 for l in lines if l.startswith("\t"))

    report = []

    if spaces and tabs:
        report.append(f"Mixed indentation ({spaces} spaces, {tabs} tabs)")
    elif spaces:
        report.append("Indentation uses spaces")
    else:
        report.append("Indentation uses tabs")

    indents = [len(re.match(r"^(\s*)", l).group(1)) for l in lines]
    if any(i % 2 != 0 for i in indents if i > 0):
        report.append("Indentation not multiple of 2 spaces")

    return " ; ".join(report)


# ============================================================
# 9. Lint checks
# ============================================================
def lint_issues(code, language):
    issues = []
    for i, line in enumerate(code.splitlines(), start=1):
        if len(line) > 120:
            issues.append(f"Line {i}: Too long ({len(line)} chars)")

        if line.rstrip() != line:
            issues.append(f"Line {i}: Trailing whitespace detected")

        if "\t" in line and line.startswith(" "):
            issues.append(f"Line {i}: Mixed tabs and spaces")

    if language == "Python":
        if not re.search(r"^\s*(\"\"\"|''').+?(\"\"\"|''')", code, flags=re.S):
            issues.append("Missing module-level docstring")

    return issues


# ============================================================
# 10. Duplicate code detection
# ============================================================
def detect_duplicates(code):
    blocks = re.split(r"\n\s*\n", code)
    hashes = Counter()
    mapping = {}

    for block in blocks:
        clean = block.strip()
        if not clean:
            continue

        h = hashlib.sha256(clean.encode()).hexdigest()
        hashes[h] += 1
        mapping.setdefault(h, []).append(clean[:200])

    exact = [
        {"count": c, "example": mapping[h][0]}
        for h, c in hashes.items() if c > 1
    ]

    similar = []
    for i in range(len(blocks)):
        for j in range(i + 1, len(blocks)):
            if not blocks[i].strip() or not blocks[j].strip():
                continue

            ratio = difflib.SequenceMatcher(
                None, blocks[i], blocks[j]
            ).ratio()

            if ratio > 0.80:
                similar.append({
                    "similarity": ratio,
                    "block1": blocks[i][:150],
                    "block2": blocks[j][:150]
                })

    return {"exact_duplicates": exact, "similar_blocks": similar}


# ============================================================
# MAIN /analyze ENDPOINT
# ============================================================
@app.route("/analyze", methods=["POST"])
def analyze():
    code = None

    # Case 1: File upload
    if "file" in request.files:
        try:
            code = request.files["file"].read().decode("utf-8", errors="ignore")
        except Exception:
            return jsonify({"error": "Could not read uploaded file"}), 400

    # Case 2: JSON body
    elif request.is_json:
        code = request.json.get("code")

    if not code:
        return jsonify({"error": "No code provided"}), 400

    language = detect_language(code)

    result = {
        "overview": generate_overview(code),
        "language": language,
        "framework": detect_framework(code),
        "open_passwords": find_passwords(code),
        "open_keys": find_api_keys(code),
        "optimization": optimization_suggestions(code),
        "naming_conventions": check_naming_conventions(code, language),
        "indentation": check_indentation(code),
        "lint_issues": lint_issues(code, language),
        "duplicate_code": detect_duplicates(code),
        "status": "success",
    }

    return jsonify(result), 200


# ============================================================
# RUN SERVER
# ============================================================
if __name__ == "__main__":
    app.run(port=5000, debug=True)
