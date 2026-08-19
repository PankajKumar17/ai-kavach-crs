import os
import sys

# Add project root to PYTHONPATH so we can import dashboard
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.app import app
