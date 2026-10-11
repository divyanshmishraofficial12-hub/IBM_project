"""Root wrapper syncing backend/train_model.py"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "backend"))
from train_model import train_url_model, train_email_model

if __name__ == "__main__":
    train_url_model()
    train_email_model()
