import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, request, jsonify
from finder import find_results  # Import our refactored function

app = Flask(__name__)

# --- App State & Configuration ---

# A thread pool to run our long-running scraping tasks in the background.
executor = ThreadPoolExecutor(max_workers=2)
# A simple in-memory dictionary to store the status and results of tasks.
TASKS = {}

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
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    """
    Starts a new search task in the background and returns a task ID.
    """
    roll_number = request.form.get('roll_number', '').strip()
    if not roll_number:
        return render_template('index.html', error="Please enter a roll number.")

    task_id = str(uuid.uuid4())
    TASKS[task_id] = {"status": "pending", "results": []}

    # Submit the long-running function to our background executor
    executor.submit(background_task, task_id, roll_number)

    # Immediately render the page, passing the task_id to the template
    return render_template('index.html', task_id=task_id, roll_number=roll_number)

def background_task(task_id: str, roll_number: str):
    """The actual workhorse function that runs in the background."""
    print(f"Starting background search for roll: {roll_number} (Task ID: {task_id})", file=sys.stderr)
    try:
        found_links = find_results(
            index_url=INDEX_URL,
            roll=roll_number,
            keywords=DEFAULT_KEYWORDS,
            stream_filters=DEFAULT_STREAM_FILTERS,
            insecure=INSECURE,
            max_follow=DEFAULT_MAX_FOLLOW,
            workers=DEFAULT_WORKERS,
        )
        TASKS[task_id] = {"status": "complete", "results": found_links}
        print(f"Task {task_id} finished. Found {len(found_links)} links.", file=sys.stderr)
    except Exception as e:
        print(f"Task {task_id} failed: {e}", file=sys.stderr)
        TASKS[task_id] = {"status": "error", "results": []}

@app.route('/status/<task_id>', methods=['GET'])
def status(task_id: str):
    """
    A new endpoint for the frontend to poll for the status of a task.
    """
    task = TASKS.get(task_id)
    if not task:
        return jsonify({"status": "error", "message": "Task not found"}), 404

    return jsonify(task)