import os
import sys
import tempfile
from pathlib import Path

# Configure before the app is imported: throwaway data dir, auth on, no network for health.
os.environ.setdefault("MSPGATHER_DATA_DIR", tempfile.mkdtemp(prefix="mspgather-test-"))
os.environ.setdefault("MSPGATHER_AUTH", "on")
os.environ.setdefault("MSPGATHER_COOKIE_SECURE", "false")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
