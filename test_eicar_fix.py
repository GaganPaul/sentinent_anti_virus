#!/usr/bin/env python3
"""
Test EICAR detection specifically
"""

import os
import tempfile

def test_eicar_detection():
    """Test EICAR detection with improved error handling"""
    print("=== Testing EICAR Detection ===")
    
    try:
        from detectors import SignatureDetector, YARADetector
        
        # Test Signature Detector
        print("\n1. Testing Signature Detector:")
        sig_detector = SignatureDetector()
        
        # Create EICAR test file
        eicar_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        eicar_file.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        eicar_file.close()
        
        # Wait a moment for file to be fully written
        import time
        time.sleep(0.1)
        
        print(f"Created EICAR file: {eicar_file.name}")
        print(f"File exists: {os.path.exists(eicar_file.name)}")
        print(f"File readable: {os.access(eicar_file.name, os.R_OK)}")
        
        # Test signature detection
        threat_level, threat_name, method = sig_detector.scan_file(eicar_file.name)
        print(f"Signature result: Level {threat_level}, {threat_name}, Method: {method}")
        
        if threat_level > 0:
            print("✓ Signature detector detected EICAR!")
        else:
            print("✗ Signature detector failed to detect EICAR")
        
        # Test YARA Detector
        print("\n2. Testing YARA Detector:")
        yara_detector = YARADetector("rules")
        
        threat_level, threat_name, method = yara_detector.scan_file(eicar_file.name)
        print(f"YARA result: Level {threat_level}, {threat_name}, Method: {method}")
        
        if threat_level > 0:
            print("✓ YARA detector detected EICAR!")
        else:
            print("✗ YARA detector failed to detect EICAR")
        
        # Cleanup
        os.unlink(eicar_file.name)
        
        return threat_level > 0
        
    except Exception as e:
        print(f"✗ EICAR test failed: {e}")
        return False

def test_file_access():
    """Test file access improvements"""
    print("\n=== Testing File Access ===")
    
    try:
        from detectors import SignatureDetector
        
        detector = SignatureDetector()
        
        # Test with non-existent file
        result = detector.scan_file("nonexistent_file.txt")
        print(f"Non-existent file result: {result}")
        
        # Test with readable file
        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        test_file.write("This is a test file")
        test_file.close()
        
        result = detector.scan_file(test_file.name)
        print(f"Readable file result: {result}")
        
        # Cleanup
        os.unlink(test_file.name)
        
        print("✓ File access test passed")
        return True
        
    except Exception as e:
        print(f"✗ File access test failed: {e}")
        return False

def main():
    """Main test function"""
    print("EICAR Detection Test")
    print("=" * 30)
    
    eicar_success = test_eicar_detection()
    access_success = test_file_access()
    
    print(f"\n=== Results ===")
    print(f"EICAR Detection: {'✓ PASS' if eicar_success else '✗ FAIL'}")
    print(f"File Access: {'✓ PASS' if access_success else '✗ FAIL'}")
    
    if eicar_success and access_success:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed")

if __name__ == "__main__":
    main()
