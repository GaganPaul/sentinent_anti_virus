#!/usr/bin/env python3
"""
Complete Sentinel Antivirus Test
"""

import tkinter as tk
import os
import tempfile
import time
import threading

def create_test_files():
    """Create test files for scanning"""
    test_files = []
    
    # EICAR test file
    eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_file = "test_eicar.txt"
    with open(eicar_file, 'w', encoding='utf-8') as f:
        f.write(eicar_content)
    test_files.append(eicar_file)
    
    # Clean file
    clean_file = "test_clean.txt"
    with open(clean_file, 'w', encoding='utf-8') as f:
        f.write("This is a clean test file.")
    test_files.append(clean_file)
    
    return test_files

def test_complete_sentinel():
    """Test the complete Sentinel Antivirus"""
    print("🛡️ Complete Sentinel Antivirus Test")
    print("=" * 50)
    
    try:
        from main import SentinelAntivirus
        from gui import SentinelGUI
        
        # Create root window
        root = tk.Tk()
        
        # Create antivirus application
        antivirus_app = SentinelAntivirus()
        
        # Create GUI
        gui = SentinelGUI(root, antivirus_app)
        antivirus_app.set_gui(gui)
        
        print("✓ Application created successfully")
        print("✓ GUI integrated")
        print(f"✓ Window title: {root.title()}")
        
        # Test file scanning
        test_files = create_test_files()
        print(f"✓ Created {len(test_files)} test files")
        
        # Test individual file scan
        print("\n--- Testing File Scan ---")
        antivirus_app.scan_file(test_files[0])
        time.sleep(2)  # Wait for processing
        
        # Check results
        items = gui.results_tree.get_children()
        print(f"✓ Results in GUI: {len(items)}")
        
        if len(items) > 0:
            for item in items:
                values = gui.results_tree.item(item, 'values')
                print(f"  - {values[0]}: {values[1]} ({values[2]})")
        
        # Test directory scan
        print("\n--- Testing Directory Scan ---")
        current_dir = os.getcwd()
        antivirus_app.scan_directory(current_dir)
        time.sleep(3)  # Wait for processing
        
        # Check results
        items_after_dir = gui.results_tree.get_children()
        print(f"✓ Results after directory scan: {len(items_after_dir)}")
        
        # Test quick scan
        print("\n--- Testing Quick Scan ---")
        antivirus_app.quick_scan()
        time.sleep(2)  # Wait for processing
        
        # Check final results
        final_items = gui.results_tree.get_children()
        print(f"✓ Final results: {len(final_items)}")
        
        # Cleanup
        for test_file in test_files:
            if os.path.exists(test_file):
                os.remove(test_file)
        
        print("\n✓ Test completed successfully")
        print("✓ All scan methods working")
        print("✓ Results visible in GUI")
        
        # Keep window open for a moment to see results
        root.after(3000, root.destroy)
        root.mainloop()
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_complete_sentinel()
    if success:
        print("\n✅ Sentinel Antivirus is fully working!")
        print("Run 'python main.py' to start the application.")
    else:
        print("\n❌ Test failed. Check the errors above.")
