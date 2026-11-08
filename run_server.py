"""
AIGIS Wargame Engine — Launcher Script
Chạy máy chủ Wargame và mở trình duyệt tự động
"""
import os
from pathlib import Path
import webbrowser
import threading
import time

ROOT_DIR = Path(__file__).resolve().parent
os.chdir(ROOT_DIR)

import uvicorn
from backend.server import app

def open_browser():
    time.sleep(1.5)
    print("\n[AIGIS] Opening Wargame Dashboard at http://localhost:8000 ...")
    webbrowser.open("http://localhost:8000")

if __name__ == "__main__":
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
