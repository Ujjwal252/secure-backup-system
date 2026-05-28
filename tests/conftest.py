import sys
import os

# Add the parent folder (secure_backup/) to Python's path
# so test files can import encryption, decryption, etc.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))