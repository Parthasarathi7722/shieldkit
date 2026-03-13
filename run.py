"""
ShieldKit startup script.
Run from anywhere inside the project:  python run.py
"""
import sys
import os
from pathlib import Path

# Add parent directory to sys.path so `shieldkit` resolves as a package
_project_root = Path(__file__).resolve().parent
_parent = _project_root.parent
sys.path.insert(0, str(_parent))
os.chdir(_parent)

import uvicorn
from dotenv import load_dotenv

load_dotenv(_project_root / ".env")

host = os.environ.get("SERVER_HOST", "0.0.0.0")
port = int(os.environ.get("SERVER_PORT", "8000"))

if __name__ == "__main__":
    print(f"Starting ShieldKit on http://{host}:{port}")
    print(f"Mode: {os.environ.get('SHIELDKIT_MODE', 'mock')}")
    uvicorn.run("shieldkit.server:app", host=host, port=port, reload=False)
