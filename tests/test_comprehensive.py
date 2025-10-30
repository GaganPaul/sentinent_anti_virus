#!/usr/bin/env python3
"""
Comprehensive test for all fixes
"""

import os
import tempfile
import time

def test_yara_loading():
    """Test YARA rules loading"""
    print("=== Testing YARA Loading ===")
    
    try:
        from detectors import YARADetector
        
        detector = YARADetector("rules")
        
        if detector.rules:
            print(f"✓ YARA detector initialized successfully")
            print(f"✓ Loaded {detector.rule_stats['loaded_rules']} working rules")
            return True
        else:
            print("✗ YARA detector failed to initialize")
            return False
            
    except Exception as e:
        print(f"✗ YARA loading test failed: {e}")
        return False

def test_file_reading():
    """Test file reading with various methods"""
    print("\n=== Testing File Reading ===")
    
    try:
        # Create a test file
        test_content = "This is a test file for reading"
        test_file = "test_read.txt"
        
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(test_content)
        
        print(f"Created test file: {test_file}")
        
        # Test signature detector
        from detectors import SignatureDetector
        detector = SignatureDetector()
        
        result = detector.scan_file(test_file)
        print(f"File reading result: {result}")
        
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
        
        print("✓ File reading test completed")
        return True
        
    except Exception as e:
        print(f"✗ File reading test failed: {e}")
        return False

def test_eicar_detection():
    """Test EICAR detection"""
    print("\n=== Testing EICAR Detection ===")
    
    try:
        from detectors import SignatureDetector
        
        detector = SignatureDetector()
        
        # Create EICAR file
        eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        eicar_file = "eicar_test.txt"
        
        with open(eicar_file, 'w', encoding='utf-8') as f:
            f.write(eicar_content)
        
        print(f"Created EICAR file: {eicar_file}")
        
        # Test detection
        threat_level, threat_name, method = detector.scan_file(eicar_file)
        print(f"EICAR detection result: Level {threat_level}, {threat_name}, Method: {method}")
        
        # Cleanup
        if os.path.exists(eicar_file):
            os.remove(eicar_file)
        
        if threat_level > 0:
            print("✓ EICAR detected successfully!")
            return True
        else:
            print("✗ EICAR not detected")
            return False
            
    except Exception as e:
        print(f"✗ EICAR detection test failed: {e}")
        return False

def test_yara_eicar():
    """Test YARA EICAR detection"""
    print("\n=== Testing YARA EICAR Detection ===")
    
    try:
        from detectors import YARADetector
        
        detector = YARADetector("rules")
        
        if not detector.rules:
            print("✗ YARA detector not available")
            return False
        
        # Create EICAR file
        eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        eicar_file = "eicar_yara_test.txt"
        
        with open(eicar_file, 'w', encoding='utf-8') as f:
            f.write(eicar_content)
        
        print(f"Created EICAR file for YARA: {eicar_file}")
        
        # Test YARA detection
        threat_level, threat_name, method = detector.scan_file(eicar_file)
        print(f"YARA EICAR result: Level {threat_level}, {threat_name}, Method: {method}")
        
        # Cleanup
        if os.path.exists(eicar_file):
            os.remove(eicar_file)
        
        if threat_level > 0:
            print("✓ YARA detected EICAR successfully!")
            return True
        else:
            print("✗ YARA did not detect EICAR")
            return False
            
    except Exception as e:
        print(f"✗ YARA EICAR test failed: {e}")
        return False

def test_full_detection_pipeline():
    """Test the full detection pipeline"""
    print("\n=== Testing Full Detection Pipeline ===")
    
    try:
        from main import SentinelAntivirus
        
        antivirus = SentinelAntivirus()
        
        # Create EICAR file
        eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        eicar_file = "eicar_pipeline_test.txt"
        
        with open(eicar_file, 'w', encoding='utf-8') as f:
            f.write(eicar_content)
        
        print(f"Created EICAR file for pipeline test: {eicar_file}")
        
        # Test full detection pipeline
        threat_level, threat_name, method = antivirus.detect_malware(eicar_file)
        print(f"Pipeline detection result: Level {threat_level}, {threat_name}, Method: {method}")
        
        # Cleanup
        if os.path.exists(eicar_file):
            os.remove(eicar_file)
        
        if threat_level > 0:
            print("✓ Full pipeline detected EICAR successfully!")
            return True
        else:
            print("✗ Full pipeline did not detect EICAR")
            return False
            
    except Exception as e:
        print(f"✗ Full pipeline test failed: {e}")
        return False

def main():
    """Main test function"""
    print("Comprehensive Fix Test")
    print("=" * 30)
    
    tests = [
        ("YARA Loading", test_yara_loading),
        ("File Reading", test_file_reading),
        ("EICAR Detection", test_eicar_detection),
        ("YARA EICAR", test_yara_eicar),
        ("Full Pipeline", test_full_detection_pipeline)
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
        print("🎉 All tests passed! The project is working correctly!")
    else:
        print("⚠️ Some tests failed. Check the errors above.")

if __name__ == "__main__":
    main()

