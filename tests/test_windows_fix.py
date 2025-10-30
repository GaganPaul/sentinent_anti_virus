#!/usr/bin/env python3
"""
Quick test for Windows file reading fixes
"""

import os
import time

def test_file_creation_and_reading():
    """Test file creation and reading"""
    print("=== Testing File Creation and Reading ===")
    
    try:
        # Create a test file
        test_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        test_file = "test_eicar_final.txt"
        
        # Write file
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(test_content)
        
        print(f"Created file: {test_file}")
        print(f"File exists: {os.path.exists(test_file)}")
        print(f"File readable: {os.access(test_file, os.R_OK)}")
        
        # Wait a moment for Windows file system
        time.sleep(0.1)
        
        # Test signature detector
        from detectors import SignatureDetector
        detector = SignatureDetector()
        
        result = detector.scan_file(test_file)
        print(f"Detection result: {result}")
        
        # Test YARA detector
        from detectors import YARADetector
        yara_detector = YARADetector("rules")
        
        yara_result = yara_detector.scan_file(test_file)
        print(f"YARA result: {yara_result}")
        
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
            print("✓ File cleaned up")
        
        # Check if EICAR was detected
        if result[0] > 0 or yara_result[0] > 0:
            print("✓ EICAR detected successfully!")
            return True
        else:
            print("✗ EICAR not detected")
            return False
            
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return False

def main():
    """Main test function"""
    print("Windows File Reading Fix Test")
    print("=" * 35)
    
    success = test_file_creation_and_reading()
    
    if success:
        print("\n🎉 SUCCESS! The Windows file reading issue has been fixed!")
    else:
        print("\n⚠️ The issue persists. Further investigation needed.")

if __name__ == "__main__":
    main()

