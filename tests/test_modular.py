#!/usr/bin/env python3
"""
Test script for the modular Sentinel Antivirus structure
"""

import os
import tempfile
import sys

def test_imports():
    """Test that all modules can be imported"""
    print("=== Testing Module Imports ===")
    
    try:
        from detectors import YARADetector, MLDetector, SignatureDetector
        print("✓ Detectors module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import detectors: {e}")
        return False
    
    try:
        from file_monitor import FileMonitor, BatchFileProcessor, FileSystemScanner
        print("✓ File monitor module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import file_monitor: {e}")
        return False
    
    try:
        from gui import SentinelGUI, PerformanceStatsWindow, YARARulesWindow
        print("✓ GUI module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import gui: {e}")
        return False
    
    try:
        from main import SentinelAntivirus
        print("✓ Main application module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import main: {e}")
        return False
    
    return True

def test_detectors():
    """Test detector functionality"""
    print("\n=== Testing Detectors ===")
    
    try:
        from detectors import YARADetector, MLDetector, SignatureDetector
        
        # Test YARA detector
        yara_detector = YARADetector("rules")
        print(f"✓ YARA detector initialized: {yara_detector.rules is not None}")
        
        # Test ML detector
        ml_detector = MLDetector()
        print(f"✓ ML detector initialized: {ml_detector.model is not None}")
        
        # Test Signature detector
        sig_detector = SignatureDetector()
        print("✓ Signature detector initialized")
        
        return True
        
    except Exception as e:
        print(f"✗ Detector test failed: {e}")
        return False

def test_file_scanning():
    """Test file scanning functionality"""
    print("\n=== Testing File Scanning ===")
    
    try:
        from main import SentinelAntivirus
        
        # Create test file
        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        test_file.write("This is a test file")
        test_file.close()
        
        # Create antivirus instance
        antivirus = SentinelAntivirus()
        
        # Test detection
        threat_level, threat_name, method = antivirus.detect_malware(test_file.name)
        print(f"✓ File scanning test: Level {threat_level}, {threat_name}, Method: {method}")
        
        # Cleanup
        os.unlink(test_file.name)
        
        return True
        
    except Exception as e:
        print(f"✗ File scanning test failed: {e}")
        return False

def test_eicar_detection():
    """Test EICAR detection"""
    print("\n=== Testing EICAR Detection ===")
    
    try:
        from main import SentinelAntivirus
        
        # Create EICAR test file
        eicar_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        eicar_file.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        eicar_file.close()
        
        # Create antivirus instance
        antivirus = SentinelAntivirus()
        
        # Test detection
        threat_level, threat_name, method = antivirus.detect_malware(eicar_file.name)
        print(f"EICAR test result: Level {threat_level}, {threat_name}, Method: {method}")
        
        if threat_level > 0:
            print("✓ EICAR detected successfully")
        else:
            print("✗ EICAR not detected")
        
        # Cleanup
        os.unlink(eicar_file.name)
        
        return threat_level > 0
        
    except Exception as e:
        print(f"✗ EICAR test failed: {e}")
        return False

def test_gui_creation():
    """Test GUI creation (without showing)"""
    print("\n=== Testing GUI Creation ===")
    
    try:
        import tkinter as tk
        from gui import SentinelGUI
        from main import SentinelAntivirus
        
        # Create root window (hidden)
        root = tk.Tk()
        root.withdraw()  # Hide the window
        
        # Create antivirus instance
        antivirus = SentinelAntivirus()
        
        # Create GUI
        gui = SentinelGUI(root, antivirus)
        print("✓ GUI created successfully")
        
        # Cleanup
        root.destroy()
        
        return True
        
    except Exception as e:
        print(f"✗ GUI test failed: {e}")
        return False

def main():
    """Main test function"""
    print("Sentinel Antivirus - Modular Structure Test")
    print("=" * 50)
    
    tests = [
        ("Module Imports", test_imports),
        ("Detectors", test_detectors),
        ("File Scanning", test_file_scanning),
        ("EICAR Detection", test_eicar_detection),
        ("GUI Creation", test_gui_creation)
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
    
    print(f"\n=== Test Results ===")
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("✓ All tests passed! Modular structure is working correctly.")
    else:
        print("✗ Some tests failed. Check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)


