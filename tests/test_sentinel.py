#!/usr/bin/env python3
"""
Simple Test for Sentinel Antivirus
"""

import tkinter as tk
import os
import tempfile
import time

def create_test_file():
    """Create a test file for scanning"""
    test_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    test_file = "test_eicar.txt"
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(test_content)
    return test_file

def test_sentinel():
    """Test the Sentinel Antivirus"""
    print("🛡️ Testing Sentinel Antivirus")
    print("=" * 40)
    
    try:
        from main import SentinelAntivirus
        from gui import SentinelGUI
        
        # Create root window
        root = tk.Tk()
        root.withdraw()  # Hide for testing
        
        # Create antivirus application
        antivirus_app = SentinelAntivirus()
        
        # Create GUI
        gui = SentinelGUI(root, antivirus_app)
        antivirus_app.set_gui(gui)
        
        print("✓ Application created successfully")
        print("✓ GUI integrated")
        
        # Test file scanning
        test_file = create_test_file()
        print(f"✓ Created test file: {test_file}")
        
        # Test scan
        antivirus_app.scan_file(test_file)
        print("✓ File scan completed")
        
        # Wait for result processing
        time.sleep(1)
        
        # Check results
        items = gui.results_tree.get_children()
        if len(items) > 0:
            print(f"✓ {len(items)} results found in GUI")
            for item in items:
                values = gui.results_tree.item(item, 'values')
                print(f"  - {values[0]}: {values[1]} ({values[2]})")
        else:
            print("✗ No results found in GUI")
        
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
        root.destroy()
        
        print("✓ Test completed successfully")
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_sentinel()
    if success:
        print("\n✅ Sentinel Antivirus is working!")
        print("Run 'python main.py' to start the application.")
    else:
        print("\n❌ Test failed. Check the errors above.")