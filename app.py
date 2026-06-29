"""Network Recon Toolkit — Flask application."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, url_for

from scanner import run_scan

app = Flask(__name__)
DB_PATH = Path(__file__).parent / "scan_history.db"


def init_db():
    """Create the scan history table if it does not exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            target_type TEXT,
            scanned_at TEXT NOT NULL,
            results_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_scan(target, target_type, results):
    """Persist scan results to SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO scans (target, target_type, scanned_at, results_json) VALUES (?, ?, ?, ?)",
        (
            target,
            target_type,
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            json.dumps(results),
        ),
    )
    conn.commit()
    scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return scan_id


def get_scan_history(limit=20):
    """Retrieve recent scans from the database."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, target, target_type, scanned_at FROM scans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [
        {
            "id": row[0],
            "target": row[1],
            "target_type": row[2],
            "scanned_at": row[3],
        }
        for row in rows
    ]


def get_scan_by_id(scan_id):
    """Retrieve a single scan by ID."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT target, target_type, scanned_at, results_json FROM scans WHERE id = ?",
        (scan_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    results = json.loads(row[3])
    results["scan_id"] = scan_id
    results["scanned_at"] = row[2]
    return results


@app.route("/")
def index():
    """Home page with scan form."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """Process a scan request from the web form."""
    target = request.form.get("target", "").strip()
    if not target:
        return render_template("index.html", error="Please enter a target.")

    results = run_scan(target)

    if results.get("success"):
        scan_id = save_scan(
            results["target"],
            results["target_type"],
            results,
        )
        results["scan_id"] = scan_id
        results["scanned_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    return render_template("results.html", results=results)


@app.route("/history")
def history():
    """Display scan history."""
    scans = get_scan_history()
    return render_template("history.html", scans=scans)


@app.route("/history/<int:scan_id>")
def history_detail(scan_id):
    """View a past scan result."""
    results = get_scan_by_id(scan_id)
    if not results:
        return render_template("history.html", error="Scan not found."), 404
    return render_template("results.html", results=results)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """JSON API endpoint for scanning."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"success": False, "error": "Target is required."}), 400

    results = run_scan(target)

    if results.get("success"):
        scan_id = save_scan(
            results["target"],
            results["target_type"],
            results,
        )
        results["scan_id"] = scan_id
        results["scanned_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    status_code = 200 if results.get("success") else 400
    return jsonify(results), status_code


init_db()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
