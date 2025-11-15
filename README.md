Result links Finder

A robust Python script that automates the tedious process of finding your academic results on the Osmania University examination portal. It scans hundreds of links, intelligently submits forms with your roll number, and pinpoints the exact pages where your results are located.

---

## 🔧 Features
- **Automated Form Submission**: Intelligently detects input forms on result pages and automatically submits your roll number.
- **Heuristic Field Detection**: Uses a smart scoring system to guess the correct "hall ticket" or "roll number" field on various forms.
- **Powerful Filtering**: Narrow down the search using custom stream filters (`--stream-filter`) and keywords (`--keywords`) to find specific results (e.g., "BE,CBCS", "marks,grade").
- **Concurrent Processing**: Checks dozens of links simultaneously for maximum speed.
- **Resilient Networking**: Built to handle network errors, slow servers, and problematic TLS/SSL configurations without crashing.
- **Real-time Progress**: Displays a `tqdm` progress bar showing the status, speed, and estimated time remaining.
- **Saves Results**: All matching links are saved to `matches.txt` for easy access.

---

## 🚀 Setup & Usage

1.  **Clone the repository:**
   ```bash
    git clone https://github.com/your-username/resultscraper.git
    cd resultscraper
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the Web Application (Recommended):**
    The easiest way to use the finder is through the web interface.

    ```bash
    # For Windows
    set FLASK_APP=app.py 
    python -m flask run

    # For macOS/Linux
    export FLASK_APP=app.py
    python -m flask run
    ```
    Now, open your web browser and go to `http://127.0.0.1:5000`.


## CLI Usage (Advanced)
3.  **Run the script:**
    The script is run from the project's root directory. You must provide the main results URL and your roll number.

    **Basic Example:**
    ```bash
    python finder.py "https://www.osmania.ac.in/examination-results.php" 161022733073
    ```

    **Recommended Example (with filters):**
    ```bash
    python finder.py "https://www.osmania.ac.in/examination-results.php" 161022733073 --insecure --stream-filter "BE,CBCS" --keywords "marks,grade,total" --workers 20
    ```

---

## ⚙️ Command-Line Arguments

| Argument          | Description                                                                                             |
| ----------------- | ------------------------------------------------------------------------------------------------------- |
| `index_url`       | The main URL of the university's examination results page.                                              |
| `roll`            | Your roll number / hall ticket number.                                                                  |
| `--insecure`      | (Optional) Skips SSL/TLS certificate verification. Useful for sites with expired or self-signed certs.  |
| `--stream-filter` | (Optional) Comma-separated keywords for your stream (e.g., "BE,CBCS"). A page must contain one of these. |
| `--keywords`      | (Optional) Comma-separated keywords that must appear on a valid result page (e.g., "marks,grade,total"). |
| `--workers`       | (Optional) Number of concurrent threads to use for checking links. Defaults to `10`.                    |
| `--max-follow`    | (Optional) The maximum number of links to check. Defaults to `2000`.                                    |

This project is just for practising python and web scraping