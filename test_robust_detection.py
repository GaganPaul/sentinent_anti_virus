#!/usr/bin/env python3
"""
Robust EICAR test that works on Windows
"""

import os

def test_eicar_robust():
    """Robust EICAR test"""
    print("=== Robust EICAR Test ===")
    
    try:
        from detectors import SignatureDetector
        
        # Create EICAR file with explicit path
        eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        eicar_file = os.path.join(os.getcwd(), "eicar_test.txt")
        
        # Write EICAR content
        with open(eicar_file, 'w', encoding='utf-8') as f:
            f.write(eicar_content)
        
        print(f"Created EICAR file: {eicar_file}")
        print(f"File exists: {os.path.exists(eicar_file)}")
        print(f"File readable: {os.access(eicar_file, os.R_OK)}")
        print(f"File size: {os.path.getsize(eicar_file)} bytes")
        
        # Test file reading directly
        try:
            with open(eicar_file, 'rb') as f:
                content = f.read()
                print(f"File content length: {len(content)} bytes")
                print(f"Contains EICAR: {b'EICAR' in content}")
        except Exception as e:
            print(f"Direct file read error: {e}")
        
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
        try:
            if os.path.exists(eicar_file):
                os.remove(eicar_file)
                print("✓ File cleaned up")
        except Exception as e:
            print(f"Cleanup error: {e}")
        
        return success
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return False

def test_signature_detector_directly():
    """Test signature detector with direct content"""
    print("\n=== Direct Signature Test ===")
    
    try:
        from detectors import SignatureDetector
        
        detector = SignatureDetector()
        
        # Test EICAR signature directly
        eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        
        # Check if EICAR signature is in our detector
        if detector.signatures['eicar'] in eicar_content:
            print("✓ EICAR signature matches!")
            return True
        else:
            print("✗ EICAR signature does not match")
            print(f"Expected: {detector.signatures['eicar']}")
            print(f"Actual: {eicar_content}")
            return False
            
    except Exception as e:
        print(f"✗ Direct test failed: {e}")
        return False

def main():
    """Main test function"""
    print("Robust Detection Tests")
    print("=" * 25)
    
    direct_success = test_signature_detector_directly()
    robust_success = test_eicar_robust()
    
    print(f"\n=== Results ===")
    print(f"Direct Signature: {'✓ PASS' if direct_success else '✗ FAIL'}")
    print(f"Robust EICAR: {'✓ PASS' if robust_success else '✗ FAIL'}")
    
    if direct_success and robust_success:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed")

if __name__ == "__main__":
    main()

