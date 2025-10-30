#!/usr/bin/env python3
"""
Test script to verify detection accuracy and fix the over-flagging issues
"""

import os
import sys
import tempfile

def create_test_files():
    """Create test files with known characteristics"""
    test_files = []
    test_dir = tempfile.mkdtemp(prefix="sentinel_accuracy_test_")
    
    # Test file 1: Clean text file
    clean_file = os.path.join(test_dir, "clean_document.txt")
    with open(clean_file, 'w') as f:
        f.write("This is a clean document with normal text content.\nNo malicious patterns here.")
    test_files.append((clean_file, "Clean Document", "Should be CLEAN"))
    
    # Test file 2: EICAR test string (should be detected by YARA)
    eicar_file = os.path.join(test_dir, "eicar_test.txt")
    with open(eicar_file, 'w') as f:
        f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    test_files.append((eicar_file, "EICAR Test", "Should be DETECTED by YARA"))
    
    # Test file 3: Ransomware-like content (should be detected by YARA)
    ransom_file = os.path.join(test_dir, "ransomware_test.txt")
    with open(ransom_file, 'w') as f:
        f.write("""
        Your files have been encrypted!
        To decrypt your files, you need to pay a ransom.
        Bitcoin wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        Payment must be made within 24 hours.
        """)
    test_files.append((ransom_file, "Ransomware Test", "Should be DETECTED by YARA"))
    
    # Test file 4: JavaScript with eval (should be detected by YARA)
    js_file = os.path.join(test_dir, "suspicious.js")
    with open(js_file, 'w') as f:
        f.write("""
        function test() {
            eval("console.log('test')");
            shell_exec("ls -la");
            system("whoami");
        }
        """)
    test_files.append((js_file, "Suspicious JavaScript", "Should be DETECTED by YARA"))
    
    # Test file 5: Normal image file (should be clean)
    image_file = os.path.join(test_dir, "test_image.jpg")
    with open(image_file, 'wb') as f:
        # Write minimal JPEG header
        f.write(b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00')
        f.write(b'This is fake image data for testing')
    test_files.append((image_file, "Image File", "Should be CLEAN"))
    
    return test_files

def test_detection_accuracy():
    """Test detection accuracy with known files"""
    print("=== Detection Accuracy Test ===\n")
    
    try:
        from standalone_antivirus import YARADetector, MLDetector
    except ImportError as e:
        print(f"Error importing detection classes: {e}")
        return
    
    # Initialize detectors
    print("Initializing detectors...")
    yara_detector = YARADetector("rules")
    ml_detector = MLDetector()
    
    # Create test files
    test_files = create_test_files()
    
    print(f"\nTesting {len(test_files)} files:\n")
    
    yara_detections = 0
    ml_detections = 0
    false_positives = 0
    
    for i, (file_path, description, expected) in enumerate(test_files, 1):
        print(f"Test {i}: {description}")
        print(f"Expected: {expected}")
        
        # Test YARA detection
        yara_level, yara_name, yara_method = yara_detector.scan_file(file_path)
        print(f"YARA: Level {yara_level}, {yara_name}, Method: {yara_method}")
        
        # Test ML detection
        ml_level, ml_name, ml_method = ml_detector.predict(file_path)
        print(f"ML:   Level {ml_level}, {ml_name}, Method: {ml_method}")
        
        # Analyze results
        yara_detected = yara_level > 0
        ml_detected = ml_level > 0
        
        if yara_detected:
            yara_detections += 1
        if ml_detected:
            ml_detections += 1
            
        # Check for false positives
        if "CLEAN" in expected and (yara_detected or ml_detected):
            false_positives += 1
            print("⚠️  FALSE POSITIVE!")
        elif "DETECTED" in expected and not (yara_detected or ml_detected):
            print("❌ MISSED DETECTION!")
        else:
            print("✅ CORRECT")
        
        print("-" * 50)
    
    # Summary
    print(f"\n=== Results Summary ===")
    print(f"YARA Detections: {yara_detections}/{len(test_files)}")
    print(f"ML Detections: {ml_detections}/{len(test_files)}")
    print(f"False Positives: {false_positives}")
    
    # Cleanup
    for file_path, _, _ in test_files:
        try:
            os.remove(file_path)
        except:
            pass
    try:
        os.rmdir(os.path.dirname(test_files[0][0]))
    except:
        pass

def test_yara_rules_working():
    """Test if YARA rules are actually working"""
    print("\n=== YARA Rules Test ===\n")
    
    try:
        from standalone_antivirus import YARADetector
        detector = YARADetector("rules")
        
        if not detector.rules:
            print("❌ No YARA rules loaded!")
            return
        
        stats = detector.get_rule_statistics()
        print(f"✓ Loaded {stats['loaded_files']} rule files")
        print(f"✓ Total rules: {stats['total_rules']}")
        print(f"✓ Categories: {list(stats['rule_categories'].keys())}")
        
        # Test with EICAR string
        eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        eicar_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        eicar_file.write(eicar_content)
        eicar_file.close()
        
        level, name, method = detector.scan_file(eicar_file.name)
        print(f"\nEICAR Test:")
        print(f"  Level: {level}")
        print(f"  Name: {name}")
        print(f"  Method: {method}")
        
        if level > 0:
            print("✅ YARA rules are working!")
        else:
            print("❌ YARA rules are NOT working - EICAR should be detected!")
        
        # Cleanup
        os.unlink(eicar_file.name)
        
    except Exception as e:
        print(f"Error testing YARA: {e}")

def main():
    """Main test function"""
    print("Sentinel Antivirus - Accuracy Test")
    print("=" * 50)
    
    test_yara_rules_working()
    test_detection_accuracy()
    
    print(f"\n=== Recommendations ===")
    print("1. If YARA is not detecting EICAR, the rules may not be loading properly")
    print("2. If ML is flagging everything, the model needs better training data")
    print("3. For production use, train ML model with real malware/clean file datasets")

if __name__ == "__main__":
    main()



