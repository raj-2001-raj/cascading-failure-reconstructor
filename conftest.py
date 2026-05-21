import sys
import os

# Ensure project root is on the path so pytest can import local modules
# regardless of where it is invoked from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
