#!/usr/bin/env python3
"""
Simple EICAR test with better file handling
"""

import os
import tempfile

def test_eicar_simple():
    """Simple EICAR test"""
    print("=== Simple EICAR Test ===")
    
    try:
        from detectors import SignatureDetector
        
        # Create EICAR file in current directory
        eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        eicar_file = "test_eicar.txt"
        
        # Write EICAR content
        with open(eicar_file, 'w') as f:
            f.write(eicar_content)
        
        print(f"Created EICAR file: {eicar_file}")
        print(f"File exists: {os.path.exists(eicar_file)}")
        print(f"File readable: {os.access(eicar_file, os.R_OK)}")
        
        # Test signature detection
        detector = SignatureDetector()
        threat_level, threat_name, method = detector.scan_file(eicar_file)
        
        print(f"Detection result: Level {threat_level}, {threat_name}, Method: {method}")
        
        if threat_level > 0:
            print("✓ EICAR detected successfully!")
            success = True
        else:
            print("✗ EICAR not detected")
            success = False
        
        # Cleanup
        if os.path.exists(eicar_file):
            os.remove(eicar_file)
        
        return success
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return False

def test_yara_simple():
    """Test YARA with simple rule"""
    print("\n=== Simple YARA Test ===")
    
    try:
        import yara
        
        # Create simple rule
        rule_source = """
        rule simple_test {
            strings:
                $test = "test"
            condition:
                $test
        }
        """
        
        # Compile rule
        rule = yara.compile(source=rule_source)
        print("✓ YARA rule compiled successfully")
        
        # Create test file
        test_file = "test_file.txt"
        with open(test_file, 'w') as f:
            f.write("This is a test file")
        
        # Test rule
        matches = rule.match(test_file)
        if matches:
            print(f"✓ Rule matched: {matches[0].rule}")
            success = True
        else:
            print("✗ Rule did not match")
            success = False
        
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
        
        return success
        
    except Exception as e:
        print(f"✗ YARA test failed: {e}")
        return False

def main():
    """Main test function"""
    print("Simple Detection Tests")
    print("=" * 25)
    
    eicar_success = test_eicar_simple()
    yara_success = test_yara_simple()
    
    print(f"\n=== Results ===")
    print(f"EICAR Detection: {'✓ PASS' if eicar_success else '✗ FAIL'}")
    print(f"YARA Basic: {'✓ PASS' if yara_success else '✗ FAIL'}")
    
    if eicar_success and yara_success:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed")

if __name__ == "__main__":
    main()

