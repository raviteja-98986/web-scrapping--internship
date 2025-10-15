import os
import json
import time
import pandas as pd
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime

# -------------------------------
# Global State
# -------------------------------
visited_links = set()
lock = threading.Lock()
count = 0


# -------------------------------
# Helper: Create unique folder names
# -------------------------------
def create_unique_folder(base_name):
    """Create timestamped folder for each scrape job."""
    ##timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs(os.path.join(folder_name, "website_tables"), exist_ok=True)
    return folder_name


# -------------------------------
# Core Scraping Function
# -------------------------------
def scrap_table(
    url,
    base_url="https://attack.mitre.org",
    folder="MITRE_Data",
    depth=0,
    max_depth=1,
    session=None,
    executor=None,
    keywords=None
):
    """Scrape all tables from a page and follow links recursively."""
    global count, visited_links

    if session is None:
        session = requests.Session()

    # Skip already visited URLs or excessive depth
    if url in visited_links or depth > max_depth:
        return []
    visited_links.add(url)

    full_url = urljoin(base_url, url)
    folder_name = os.path.join(folder, "website_tables")
    os.makedirs(folder_name, exist_ok=True)

    print(f"🔍 Scraping (depth {depth}): {full_url}")

    try:
        response = session.get(full_url, timeout=20)
        response.raise_for_status()
    except Exception as e:
        print(f"❌ Failed to fetch {full_url}: {e}")
        return []

    soup = BeautifulSoup(response.text, "html.parser")

    # -------------------------------
    # Collect next-level links
    # -------------------------------
    id_links = []
    if keywords:
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if any(keyword in href for keyword in keywords):
                abs_link = urljoin(base_url, href)
                if abs_link not in visited_links:
                    id_links.append(abs_link)

    # -------------------------------
    # Extract and Save Tables
    # -------------------------------
    tables = soup.find_all("table")
    if not tables:
        print(f"⚠️ No tables found at: {full_url}")

    for table in tables:
        headings = [th.get_text(strip=True) for th in table.find_all("th")]
        all_data = []

        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if not cells:
                continue
            row_data = [td.get_text(strip=True) for td in cells]
            all_data.append(row_data)

        if not all_data:
            continue

        # Normalize column lengths
        if headings:
            num_headers = len(headings)
            fixed_data = [
                (row + [""] * (num_headers - len(row)))[:num_headers]
                for row in all_data
            ]
            df = pd.DataFrame(fixed_data, columns=headings)
        else:
            df = pd.DataFrame(all_data)

        # Save JSON file
        with lock:
            count += 1
            file_path = os.path.join(folder_name, f"table_{count}.json")

        df.to_json(file_path, orient="records", indent=4, force_ascii=False)
        print(f"✅ Saved: {file_path}")

    # -------------------------------
    # Recurse into linked pages
    # -------------------------------
    new_futures = []
    next_depth = depth + 1
    if next_depth <= max_depth and id_links:
        for link in id_links:
            new_futures.append(
                executor.submit(
                    scrap_table,
                    link,
                    base_url,
                    folder,
                    next_depth,
                    max_depth,
                    session,
                    executor,
                    keywords,
                )
            )

    return new_futures


# -------------------------------
# Runner Function
# -------------------------------
def run_all_scrapes(max_depth=1):
    """Run scrapers for all three MITRE ATT&CK categories."""
    global count
    count = 0
    visited_links.clear()

    start = time.time()

    # Target base pages
    base_targets = {
        "Enterprise_Techniques": "https://attack.mitre.org/versions/v15/techniques/enterprise/",
        "Threat_Actor_Groups": "https://attack.mitre.org/versions/v15/groups/",
        "Software_Tools": "https://attack.mitre.org/versions/v15/software/",
    }

    # Keywords to identify valid subpage links
    keywords = ["/techniques/", "/groups/", "/software/"]

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for name, url in base_targets.items():
                folder = create_unique_folder(name)
                futures.append(
                    executor.submit(
                        scrap_table,
                        url,
                        folder=folder,
                        max_depth=max_depth,
                        session=session,
                        executor=executor,
                        keywords=keywords,
                    )
                )

            # Handle recursive futures dynamically
            while futures:
                new_futures = []
                for f in as_completed(futures):
                    try:
                        extra = f.result()
                        if extra:
                            new_futures.extend(extra)
                    except Exception as e:
                        print(f"⚠️ Thread error: {e}")
                futures = new_futures

    print(f"\n🏁 Finished scraping {count} tables in {time.time() - start:.2f} seconds.")


# -------------------------------
# Main Entry
# -------------------------------
if __name__ == "__main__":
    # Increase depth to 2 if you want deeper linked pages (may take longer)
    run_all_scrapes(max_depth=1)
