#!/usr/bin/env python3
"""
Sentinel Antivirus - Enhanced GUI Launcher
"""

import sys
import os

def main():
    """Launch Sentinel Antivirus with enhanced GUI"""
    print("🛡️ Sentinel - Advanced Threat Protection System")
    print("=" * 50)
    print("Starting enhanced GUI...")
    print()
    
    try:
        # Import and run main application
        from main import main as run_app
        run_app()
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        print("Make sure all required modules are available.")
        sys.exit(1)
        
    except Exception as e:
        print(f"✗ Application error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
