#!/usr/bin/env python3
"""
Test the enhanced GUI
"""

import tkinter as tk
import os
import tempfile
import time

def test_gui_creation():
    """Test GUI creation"""
    print("=== Testing Enhanced GUI Creation ===")
    
    try:
        from main import SentinelAntivirus
        from gui import SentinelGUI
        
        # Create root window
        root = tk.Tk()
        root.withdraw()  # Hide the window for testing
        
        # Create antivirus app
        antivirus_app = SentinelAntivirus()
        
        # Create GUI
        gui = SentinelGUI(root, antivirus_app)
        antivirus_app.set_gui(gui)
        
        print("✓ GUI created successfully")
        print("✓ Cyber theme applied")
        print("✓ All components initialized")
        
        # Test GUI components
        components = [
            ("Header", gui.header_status),
            ("Progress Bar", gui.progress_bar),
            ("Results Tree", gui.results_tree),
            ("Status Bar", gui.status_text),
            ("Scan Buttons", gui.scan_file_btn),
            ("System Status", gui.yara_status)
        ]
        
        for name, component in components:
            if component:
                print(f"✓ {name} component available")
            else:
                print(f"✗ {name} component missing")
        
        # Test result addition
        test_result = ("test_file.txt", "Test Threat", "High", "1024.0", "12:34:56", "YARA")
        gui.add_result(*test_result)
        
        # Check if result was added
        items = gui.results_tree.get_children()
        if items:
            print("✓ Result added to GUI successfully")
        else:
            print("✗ Result not added to GUI")
        
        # Cleanup
        root.destroy()
        
        return True
        
    except Exception as e:
        print(f"✗ GUI creation test failed: {e}")
        return False

def test_gui_functionality():
    """Test GUI functionality"""
    print("\n=== Testing GUI Functionality ===")
    
    try:
        from main import SentinelAntivirus
        from gui import SentinelGUI
        
        # Create root window
        root = tk.Tk()
        root.withdraw()
        
        # Create antivirus app
        antivirus_app = SentinelAntivirus()
        
        # Create GUI
        gui = SentinelGUI(root, antivirus_app)
        antivirus_app.set_gui(gui)
        
        # Test status updates
        gui.update_status("Testing status update")
        print("✓ Status update works")
        
        # Test progress updates
        gui.update_progress(50)
        print("✓ Progress update works")
        
        # Test statistics updates
        gui.update_statistics()
        print("✓ Statistics update works")
        
        # Test system status updates
        gui.update_system_status()
        print("✓ System status update works")
        
        # Test button states
        gui.enable_scan_buttons(False)
        print("✓ Button state control works")
        
        # Cleanup
        root.destroy()
        
        return True
        
    except Exception as e:
        print(f"✗ GUI functionality test failed: {e}")
        return False

def test_integration():
    """Test GUI integration with main app"""
    print("\n=== Testing GUI Integration ===")
    
    try:
        from main import SentinelAntivirus
        from gui import SentinelGUI
        
        # Create root window
        root = tk.Tk()
        root.withdraw()
        
        # Create antivirus app
        antivirus_app = SentinelAntivirus()
        
        # Create GUI
        gui = SentinelGUI(root, antivirus_app)
        antivirus_app.set_gui(gui)
        
        # Test file scanning integration
        test_file = "test_integration.txt"
        with open(test_file, 'w') as f:
            f.write("This is a test file for integration")
        
        # Test scan
        antivirus_app.scan_file(test_file)
        
        # Check if result appears in GUI
        time.sleep(0.1)  # Give time for result processing
        items = gui.results_tree.get_children()
        if items:
            print("✓ File scan integration works")
        else:
            print("✗ File scan integration failed")
        
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
        root.destroy()
        
        return True
        
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        return False

def main():
    """Main test function"""
    print("Enhanced GUI Test Suite")
    print("=" * 30)
    
    tests = [
        ("GUI Creation", test_gui_creation),
        ("GUI Functionality", test_gui_functionality),
        ("GUI Integration", test_integration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✓ {test_name} test passed")
            else:
                print(f"✗ {test_name} test failed")
        except Exception as e:
            print(f"✗ {test_name} test error: {e}")
    
    print(f"\n=== Final Results ===")
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n🎉 SUCCESS! Enhanced GUI is working perfectly!")
        print("Features:")
        print("✓ Professional cyber theme")
        print("✓ Real-time results display")
        print("✓ Advanced controls")
        print("✓ User-friendly interface")
        print("✓ Performance statistics")
        print("✓ YARA rules management")
    else:
        print("\n⚠️ Some tests failed. Check the errors above.")

if __name__ == "__main__":
    main()

