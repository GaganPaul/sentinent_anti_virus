#!/usr/bin/env python3
"""
Simple test to verify YARA is working with a basic rule
"""

import os
import tempfile

def test_basic_yara():
    """Test YARA with a simple rule"""
    print("=== Basic YARA Test ===\n")
    
    try:
        import yara
        print("✓ YARA library imported successfully")
    except ImportError:
        print("✗ YARA library not available")
        return
    
    # Create a simple test rule
    simple_rule = """
    rule test_rule {
        strings:
            $a = "test"
        condition:
            $a
    }
    """
    
    try:
        # Compile the simple rule
        rule = yara.compile(source=simple_rule)
        print("✓ Simple rule compiled successfully")
        
        # Create a test file
        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        test_file.write("This is a test file with the word test in it")
        test_file.close()
        
        print(f"✓ Test file created: {test_file.name}")
        
        # Test the rule
        matches = rule.match(test_file.name)
        if matches:
            print(f"✓ Rule matched! Found: {matches[0].rule}")
        else:
            print("✗ Rule did not match")
        
        # Cleanup
        os.unlink(test_file.name)
        
    except Exception as e:
        print(f"✗ Error: {e}")

def test_eicar_rule():
    """Test with EICAR-specific rule"""
    print("\n=== EICAR Rule Test ===\n")
    
    try:
        import yara
        
        # Create EICAR rule
        eicar_rule = """
        rule eicar_test {
            strings:
                $eicar = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            condition:
                $eicar
        }
        """
        
        # Compile the rule
        rule = yara.compile(source=eicar_rule)
        print("✓ EICAR rule compiled successfully")
        
        # Create EICAR test file
        eicar_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        eicar_file.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        eicar_file.close()
        
        print(f"✓ EICAR file created: {eicar_file.name}")
        
        # Test the rule
        matches = rule.match(eicar_file.name)
        if matches:
            print(f"✓ EICAR rule matched! Found: {matches[0].rule}")
        else:
            print("✗ EICAR rule did not match")
        
        # Cleanup
        os.unlink(eicar_file.name)
        
    except Exception as e:
        print(f"✗ Error: {e}")

def test_rules_folder():
    """Test loading from rules folder"""
    print("\n=== Rules Folder Test ===\n")
    
    try:
        from standalone_antivirus import YARADetector
        
        detector = YARADetector("rules")
        
        if detector.rules:
            print("✓ YARA detector initialized")
            
            # Test with EICAR
            eicar_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            eicar_file.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            eicar_file.close()
            
            level, name, method = detector.scan_file(eicar_file.name)
            print(f"EICAR test result: Level {level}, {name}, Method: {method}")
            
            if level > 0:
                print("✓ YARA detector is working!")
            else:
                print("✗ YARA detector not detecting EICAR")
            
            # Cleanup
            os.unlink(eicar_file.name)
        else:
            print("✗ YARA detector not initialized")
            
    except Exception as e:
        print(f"✗ Error: {e}")

def main():
    """Main test function"""
    print("YARA Basic Functionality Test")
    print("=" * 40)
    
    test_basic_yara()
    test_eicar_rule()
    test_rules_folder()
    
    print("\n=== Summary ===")
    print("If all tests pass, YARA is working correctly")
    print("If EICAR test fails, there may be an issue with rule compilation")

if __name__ == "__main__":
    main()



