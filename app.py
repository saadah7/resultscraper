import sys
from flask import Flask, render_template, request
from finder import find_results  # Import our refactored function

app = Flask(__name__)

# --- Configuration ---
# These are the default settings for the web UI, based on the original script's
# recommended usage.
INDEX_URL = "https://www.osmania.ac.in/examination-results.php"
DEFAULT_KEYWORDS = ["marks", "grade", "total"]
DEFAULT_STREAM_FILTERS = ["BE", "CBCS"]
DEFAULT_WORKERS = 20
DEFAULT_MAX_FOLLOW = 300  # A reasonable limit for a web request
INSECURE = True  # Set to True as per recommended command

@app.route('/', methods=['GET'])
def index():
    """Renders the main page with the input form."""
    return render_template('index.html', roll_number="")

@app.route('/search', methods=['POST'])
def search():
    """Handles the form submission and displays results."""
    roll_number = request.form.get('roll_number', '').strip()

    if not roll_number:
        return render_template('index.html', error="Please enter a roll number.", roll_number="")

    # This will print to the console where you run "flask run"
    print(f"Starting search for roll number: {roll_number}", file=sys.stderr)

    # Call the core logic from finder.py
    found_links = find_results(
        index_url=INDEX_URL,
        roll=roll_number,
        keywords=DEFAULT_KEYWORDS,
        stream_filters=DEFAULT_STREAM_FILTERS,
        insecure=INSECURE,
        max_follow=DEFAULT_MAX_FOLLOW,
        workers=DEFAULT_WORKERS,
    )

    print(f"Search finished. Found {len(found_links)} links.", file=sys.stderr)

    # Render the same page, but now with the results
    return render_template('index.html', results=found_links, roll_number=roll_number)