# Osmania Result Finder

A Python-based tool that automatically finds and extracts Osmania University result links where your roll number appears.  
It filters only **B.E (CBCS)** results, handling variations like `BE`, `B.E.`, and `B E`.

---

## 🔧 Features
- Fetches all result links from the official Osmania University results page  
- Handles different naming formats for streams (BE, B.E., etc.)  
- Searches both **HTML** and **PDF** pages for your roll number  
- Optional filters for stream/semester keywords  
- Saves matching result links to a text file (`matches.txt`)

---

## 🚀 Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/<your-username>/<repo-name>.git
   cd <repo-name>
2. Install dependencies:
pip install -r requirements.txt
3. Run
python finder.py "https://www.osmania.ac.in/results.html" YOUR_ROLL_NUMBER --stream-filter "BE,CBCS"
