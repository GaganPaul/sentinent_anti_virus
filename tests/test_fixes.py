#!/usr/bin/env python3
"""
Test script to verify the fixes for YARA and ML issues
"""

import os
import sys

def test_imports():
    """Test if all imports work correctly"""
    print("Testing imports...")
    try:
        from standalone_antivirus import YARADetector, MLDetector, SentinelAntivirus
        print("✓ All imports successful")
        return True
    except Exception as e:
        print(f"✗ Import error: {e}")
        return False

def test_yara_detector():
    """Test YARA detector initialization"""
    print("\nTesting YARA detector...")
    try:
        from standalone_antivirus import YARADetector
        detector = YARADetector("rules")
        
        if detector.rules:
            stats = detector.get_rule_statistics()
            print(f"✓ YARA detector initialized successfully")
            print(f"  Loaded files: {stats['loaded_files']}")
            print(f"  Total rules: {stats['total_rules']}")
            print(f"  Categories: {len(stats['rule_categories'])}")
            return True
        else:
            print("✗ YARA detector initialized but no rules loaded")
            return False
    except Exception as e:
        print(f"✗ YARA detector error: {e}")
        return False

def test_ml_detector():
    """Test ML detector initialization"""
    print("\nTesting ML detector...")
    try:
        from standalone_antivirus import MLDetector
        detector = MLDetector()
        
        if detector.model and hasattr(detector.model, 'estimators_'):
            print("✓ ML detector initialized successfully")
            print(f"  Model has {len(detector.model.estimators_)} estimators")
            return True
        else:
            print("✗ ML detector not properly initialized")
            return False
    except Exception as e:
        print(f"✗ ML detector error: {e}")
        return False

def test_file_scanning():
    """Test file scanning with both detectors"""
    print("\nTesting file scanning...")
    try:
        from standalone_antivirus import YARADetector, MLDetector
        import tempfile
        
        # Create test file
        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        test_file.write("This is a test file for scanning")
        test_file.close()
        
        # Test YARA scanning
        yara_detector = YARADetector("rules")
        if yara_detector.rules:
            threat_level, threat_name, method = yara_detector.scan_file(test_file.name)
            print(f"✓ YARA scan: Level {threat_level}, {threat_name}, Method: {method}")
        else:
            print("✗ YARA scan failed - no rules loaded")
        
        # Test ML scanning
        ml_detector = MLDetector()
        if ml_detector.model and hasattr(ml_detector.model, 'estimators_'):
            threat_level, threat_name, method = ml_detector.predict(test_file.name)
            print(f"✓ ML scan: Level {threat_level}, {threat_name}, Method: {method}")
        else:
            print("✗ ML scan failed - model not initialized")
        
        # Cleanup
        os.unlink(test_file.name)
        return True
        
    except Exception as e:
        print(f"✗ File scanning error: {e}")
        return False

def main():
    """Main test function"""
    print("Sentinel Antivirus - Fix Verification Test")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_yara_detector,
        test_ml_detector,
        test_file_scanning
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\n=== Test Results ===")
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All tests passed! The fixes are working correctly.")
    else:
        print("✗ Some tests failed. Check the errors above.")
    
    print(f"\nTo run the full application:")
    print(f"python standalone_antivirus.py")

if __name__ == "__main__":
    main()



