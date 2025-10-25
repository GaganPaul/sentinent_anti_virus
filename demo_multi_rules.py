#!/usr/bin/env python3
"""
Demo script for Sentinel Antivirus with Multi-Rule YARA Support
Demonstrates loading and using all rules from the rules folder
"""

import os
import sys
import time
import tempfile

def demo_yara_loading():
    """Demonstrate YARA multi-rule loading"""
    print("=== Sentinel Multi-Rule YARA Demo ===\n")
    
    try:
        from standalone_antivirus import YARADetector
    except ImportError as e:
        print(f"Error importing YARADetector: {e}")
        print("Make sure standalone_antivirus.py is in the same directory")
        return
    
    # Initialize YARA detector with rules folder
    print("1. Initializing YARA Detector with rules folder...")
    yara_detector = YARADetector("rules")
    
    # Get statistics
    stats = yara_detector.get_rule_statistics()
    
    print(f"\n2. YARA Rules Statistics:")
    print(f"   Total Rule Files: {stats['loaded_files']}")
    print(f"   Failed Files: {stats['failed_files']}")
    print(f"   Total Rules: {stats['total_rules']}")
    print(f"   Rule Categories: {len(stats['rule_categories'])}")
    
    print(f"\n3. Rule Categories Breakdown:")
    for category, count in stats['rule_categories'].items():
        print(f"   {category}: {count} files")
    
    print(f"\n4. Sample Rule Files (first 10):")
    for i, rule_file in enumerate(yara_detector.rule_files[:10], 1):
        print(f"   {i}. {os.path.basename(rule_file)}")
    
    if len(yara_detector.rule_files) > 10:
        print(f"   ... and {len(yara_detector.rule_files) - 10} more files")
    
    return yara_detector

def demo_rule_scanning(yara_detector):
    """Demonstrate scanning with multiple rules"""
    print(f"\n5. Testing Rule Scanning:")
    
    if not yara_detector.rules:
        print("   ✗ No YARA rules loaded, cannot test scanning")
        return
    
    # Create test files
    test_files = create_test_files()
    
    for i, (file_path, description) in enumerate(test_files, 1):
        print(f"\n   Test File {i}: {description}")
        print(f"   Path: {file_path}")
        
        try:
            threat_level, threat_name, method = yara_detector.scan_file(file_path)
            print(f"   Result: Level {threat_level}, {threat_name}, Method: {method}")
        except Exception as e:
            print(f"   Error: {e}")
    
    # Cleanup test files
    cleanup_test_files(test_files)

def create_test_files():
    """Create test files for demonstration"""
    test_files = []
    test_dir = tempfile.mkdtemp(prefix="sentinel_demo_")
    
    # Test file 1: EICAR test string
    eicar_file = os.path.join(test_dir, "eicar_test.txt")
    with open(eicar_file, 'w') as f:
        f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    test_files.append((eicar_file, "EICAR Test String"))
    
    # Test file 2: Ransomware-like content
    ransom_file = os.path.join(test_dir, "ransomware_test.txt")
    with open(ransom_file, 'w') as f:
        f.write("""
        Your files have been encrypted!
        To decrypt your files, you need to pay a ransom.
        Bitcoin wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        Payment must be made within 24 hours.
        """)
    test_files.append((ransom_file, "Ransomware-like Content"))
    
    # Test file 3: APT-like content
    apt_file = os.path.join(test_dir, "apt_test.txt")
    with open(apt_file, 'w') as f:
        f.write("""
        APT29 Grizzly Steppe
        Advanced Persistent Threat
        Command and Control Server
        Data Exfiltration
        """)
    test_files.append((apt_file, "APT-like Content"))
    
    # Test file 4: Clean file
    clean_file = os.path.join(test_dir, "clean_file.txt")
    with open(clean_file, 'w') as f:
        f.write("This is a clean file with no malicious content.")
    test_files.append((clean_file, "Clean File"))
    
    return test_files

def cleanup_test_files(test_files):
    """Clean up test files"""
    for file_path, _ in test_files:
        try:
            os.remove(file_path)
        except:
            pass
    
    # Remove test directory
    try:
        test_dir = os.path.dirname(test_files[0][0])
        os.rmdir(test_dir)
    except:
        pass

def demo_performance():
    """Demonstrate performance with multiple rules"""
    print(f"\n6. Performance Testing:")
    
    try:
        from standalone_antivirus import YARADetector
        yara_detector = YARADetector("rules")
        
        if not yara_detector.rules:
            print("   ✗ No YARA rules loaded, cannot test performance")
            return
        
        # Create a test file
        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        test_file.write("Test content for performance testing")
        test_file.close()
        
        # Test scanning performance
        start_time = time.time()
        for _ in range(100):  # Scan 100 times
            yara_detector.scan_file(test_file.name)
        end_time = time.time()
        
        avg_time = (end_time - start_time) / 100
        print(f"   Average scan time: {avg_time:.4f} seconds")
        print(f"   Scans per second: {1/avg_time:.1f}")
        
        # Cleanup
        os.unlink(test_file.name)
        
    except Exception as e:
        print(f"   Error during performance test: {e}")

def main():
    """Main demo function"""
    print("Sentinel Antivirus - Multi-Rule YARA Demo")
    print("=" * 50)
    
    # Check if rules folder exists
    if not os.path.exists("rules"):
        print("Error: 'rules' folder not found!")
        print("Make sure you have the rules folder with YARA rule files.")
        return
    
    # Demo YARA loading
    yara_detector = demo_yara_loading()
    
    # Demo rule scanning
    demo_rule_scanning(yara_detector)
    
    # Demo performance
    demo_performance()
    
    print(f"\n=== Demo Complete ===")
    print(f"✓ Multi-rule YARA loading demonstrated")
    print(f"✓ Rule scanning tested")
    print(f"✓ Performance metrics collected")
    print(f"\nTo run the full GUI application:")
    print(f"python standalone_antivirus.py")

if __name__ == "__main__":
    main()




