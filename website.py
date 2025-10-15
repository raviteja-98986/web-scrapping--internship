from flask import Flask, render_template, request
import os, json, pandas as pd
from urllib.parse import unquote

app = Flask(__name__)

# Category folders
CATEGORIES = {
    "Softwares": "Software_Tools/website_tables",
    "Groups": "Threat_Actor_Groups/website_tables",
    "Techniques": "Enterprise_Techniques/website_tables"
}


@app.route("/")
@app.route("/dashboard")
def dashboard():
    """Show main categories"""
    return render_template("dashboard.html", categories=CATEGORIES)


@app.route("/category/<string:category_name>")
def show_category(category_name):
    """Show summary list for each category"""
    category_name = unquote(category_name)
    folder = CATEGORIES.get(category_name)
    items = []

    if not folder or not os.path.exists(folder):
        return render_template("category.html", category_name=category_name, items=[])

    for file in os.listdir(folder):
        if file.endswith(".json"):
            filepath = os.path.join(folder, file)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Normalize and extract summary
                if isinstance(data, dict):
                    data = [data]
                elif not isinstance(data, list):
                    continue

                df = pd.DataFrame(data)
                df = df.head(3)  # summary (first 3 rows)
                summary_html = df.to_html(classes="table table-sm table-bordered", index=False, escape=False)
                items.append({"filename": file, "summary": summary_html})
            except Exception as e:
                print(f"Error loading {filepath}: {e}")

    return render_template("category.html", category_name=category_name, items=items)


@app.route("/detail/<string:category_name>/<string:filename>")
def detail_view(category_name, filename):
    """Show full details of one JSON file"""
    category_name = unquote(category_name)
    folder = CATEGORIES.get(category_name)
    filepath = os.path.join(folder, filename)
    full_table = None

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            data = [data]
        df = pd.DataFrame(data)
        full_table = df.to_html(classes="table table-bordered table-striped", index=False, escape=False)
    except Exception as e:
        full_table = f"<p>Error reading {filename}: {e}</p>"

    return render_template("details.html", category_name=category_name, filename=filename, table=full_table)


if __name__ == "__main__":
    app.run(debug=True)
