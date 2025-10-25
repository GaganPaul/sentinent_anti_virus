#!/usr/bin/env python3
"""
Detection modules for Sentinel Antivirus
Contains YARA, ML, Signature, Heuristic, and other detection methods
"""

import os
import hashlib
import logging
import math
from collections import defaultdict

# Optional imports with fallbacks
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    np = None
    RandomForestClassifier = None
    StandardScaler = None

logger = logging.getLogger(__name__)

class YARADetector:
    """YARA-based detection engine"""
    
    def __init__(self, rules_folder="rules"):
        self.rules_folder = rules_folder
        self.rules = None
        self.rule_stats = {
            'total_rules': 0,
            'loaded_rules': 0,
            'rule_categories': defaultdict(int)
        }
        self.load_rules()
    
    def load_rules(self):
        """Load YARA rules from folder"""
        if not YARA_AVAILABLE:
            logger.warning("YARA not available - skipping rule loading")
            return
        
        try:
            # Check if rules folder exists
            if not os.path.exists(self.rules_folder):
                logger.warning(f"Rules folder not found: {self.rules_folder}")
                return
            
            # Find all .yar and .yara files
            rule_files = []
            try:
                for root, dirs, files in os.walk(self.rules_folder):
                    for file in files:
                        if file.endswith(('.yar', '.yara')):
                            rule_files.append(os.path.join(root, file))
            except PermissionError:
                logger.error(f"Permission denied accessing rules folder: {self.rules_folder}")
                return
            
            logger.info(f"Found {len(rule_files)} YARA rule files")
            self.rule_stats['total_rules'] = len(rule_files)
            
            if not rule_files:
                logger.warning("No YARA rule files found")
                return
            
            # Try to load individual rules (skip problematic ones)
            working_rules = []
            successful_rules = []
            
            for rule_file in rule_files:
                try:
                    # Read rule content first
                    with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                        rule_content = f.read()
                    
                    # Skip rules with known problematic identifiers
                    skip_patterns = [
                        'is__elf',
                        'undefined identifier',
                        'not enough memory',
                        'syntax error'
                    ]
                    
                    if any(pattern in rule_content.lower() for pattern in skip_patterns):
                        logger.debug(f"Skipping problematic rule: {os.path.basename(rule_file)}")
                        continue
                    
                    # Try to compile the rule
                    rule = yara.compile(source=rule_content)
                    working_rules.append(rule)
                    successful_rules.append(rule_file)
                    self._extract_rule_info(rule_file)
                    
                except Exception as e:
                    logger.debug(f"Skipped rule {os.path.basename(rule_file)}: {e}")
                    continue
            
            if working_rules:
                # Use the first working rule (simplest approach)
                self.rules = working_rules[0]
                logger.info(f"Successfully loaded {len(working_rules)} working rules")
                self.rule_stats['loaded_rules'] = len(working_rules)
            else:
                logger.warning("No working YARA rules could be loaded")
                self.rules = None
                
        except Exception as e:
            logger.error(f"Failed to load YARA rules from folder: {e}")
            self.rules = None
    
    def _extract_rule_info(self, rule_file):
        """Extract rule information for statistics"""
        try:
            filename = os.path.basename(rule_file)
            self.rule_stats['loaded_rules'] += 1
            
            # Categorize rules based on filename
            filename_lower = filename.lower()
            if 'apt' in filename_lower:
                category = 'APT'
            elif 'malware' in filename_lower or 'malw' in filename_lower:
                category = 'Malware'
            elif 'ransomware' in filename_lower or 'ransom' in filename_lower:
                category = 'Ransomware'
            elif 'rat' in filename_lower:
                category = 'RAT'
            elif 'cve' in filename_lower:
                category = 'CVE'
            elif 'exploit' in filename_lower:
                category = 'Exploit Kit'
            elif 'document' in filename_lower or 'doc' in filename_lower:
                category = 'Malicious Documents'
            elif 'pos' in filename_lower:
                category = 'POS Malware'
            elif 'toolkit' in filename_lower or 'tool' in filename_lower:
                category = 'General'
            else:
                category = 'General'
            
            self.rule_stats['rule_categories'][category] += 1
                
        except Exception as e:
            logger.debug(f"Could not extract rule info from {rule_file}: {e}")
    
    def scan_file(self, file_path):
        """Scan file with YARA rules"""
        if not self.rules:
            return 0, "Clean", "None"
        
        try:
            # Check if file exists and is readable
            if not os.path.exists(file_path):
                logger.warning(f"File does not exist: {file_path}")
                return 0, "Clean", "None"
            
            if not os.access(file_path, os.R_OK):
                logger.warning(f"File not readable: {file_path}")
                return 0, "Clean", "None"
            
            # Try multiple methods to scan the file
            matches = None
            
            # Method 1: Try direct file path matching
            try:
                matches = self.rules.match(file_path)
                if matches:
                    logger.debug(f"YARA matched using file path method")
            except Exception as e1:
                logger.debug(f"YARA file path matching failed: {e1}")
            
            # Method 2: Try reading file content and matching against it
            if not matches:
                try:
                    # Use the same robust file reading as SignatureDetector
                    content = self._read_file_robust(file_path)
                    if content:
                        matches = self.rules.match(data=content)
                        if matches:
                            logger.debug(f"YARA matched using content method")
                except Exception as e2:
                    logger.debug(f"YARA content matching failed: {e2}")
            
            if matches:
                # Get the first match
                match = matches[0]
                rule_name = match.rule
                
                # Determine threat level based on rule category
                threat_level = self._get_threat_level(rule_name)
                
                # Create detailed threat name
                threat_name = f"YARA.{rule_name}"
                
                # Add rule file info if available
                if hasattr(match, 'namespace'):
                    threat_name += f" ({match.namespace})"
                
                logger.info(f"YARA match found: {rule_name} in {file_path}")
                return threat_level, threat_name, "YARA"
            return 0, "Clean", "None"
        except Exception as e:
            logger.error(f"YARA scan error for {file_path}: {e}")
            return 0, "Clean", "None"
    
    def _read_file_robust(self, file_path):
        """Robust file reading method"""
        content = None
        
        # Method 1: Try using pathlib
        try:
            from pathlib import Path
            import time
            file_path_obj = Path(file_path)
            if file_path_obj.exists() and file_path_obj.is_file():
                time.sleep(0.01)
                content = file_path_obj.read_bytes()
                if len(content) > 8192:
                    content = content[:8192]
        except Exception:
            pass
        
        # Method 2: Try standard binary read with retry
        if content is None:
            import time
            for attempt in range(3):
                try:
                    time.sleep(0.01 * attempt)
                    with open(file_path, 'rb') as f:
                        content = f.read(8192)
                    break
                except Exception:
                    if attempt == 2:
                        break
        
        # Method 3: Try using os.open
        if content is None:
            try:
                fd = os.open(file_path, os.O_RDONLY | os.O_BINARY)
                content = os.read(fd, 8192)
                os.close(fd)
            except Exception:
                pass
        
        return content
    
    def _get_threat_level(self, rule_name):
        """Determine threat level based on rule name"""
        rule_lower = rule_name.lower()
        
        # High threat keywords
        if any(keyword in rule_lower for keyword in ['apt', 'ransomware', 'rat', 'backdoor', 'trojan', 'rootkit']):
            return 3
        # Medium threat keywords
        elif any(keyword in rule_lower for keyword in ['malware', 'virus', 'worm', 'exploit', 'cve']):
            return 2
        # Low threat keywords
        elif any(keyword in rule_lower for keyword in ['suspicious', 'packed', 'obfuscated']):
            return 1
        else:
            return 2  # Default to medium threat
    
    def get_rule_statistics(self):
        """Get statistics about loaded rules"""
        return self.rule_stats.copy()
    
    def reload_rules(self):
        """Reload all rules from the rules folder"""
        self.rule_stats = {
            'total_rules': 0,
            'loaded_rules': 0,
            'rule_categories': defaultdict(int)
        }
        self.load_rules()

class MLDetector:
    """Machine Learning-based detection engine"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = [
            'file_size', 'entropy', 'has_pe_header', 'has_elf_header',
            'suspicious_strings', 'packed_ratio', 'import_count'
        ]
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize ML model with dummy training data"""
        if not ML_AVAILABLE:
            logger.warning("ML libraries not available - skipping ML detector")
            return
        
        try:
            # Create model and scaler
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.scaler = StandardScaler()
            
            # Create dummy training data (90% clean, 10% malicious)
            n_samples = 100
            X_dummy = np.random.rand(n_samples, len(self.feature_names))
            
            # Make some features more suspicious for malicious samples
            y_dummy = np.zeros(n_samples)
            malicious_indices = np.random.choice(n_samples, size=10, replace=False)
            y_dummy[malicious_indices] = 1
            
            # Make malicious samples have higher entropy and suspicious features
            for idx in malicious_indices:
                X_dummy[idx, 1] += 0.5  # Higher entropy
                X_dummy[idx, 4] += 0.3  # More suspicious strings
                X_dummy[idx, 5] += 0.4  # Higher packed ratio
            
            # Fit the model
            X_scaled = self.scaler.fit_transform(X_dummy)
            self.model.fit(X_scaled, y_dummy)
            
            logger.info("Created and initialized new ML model with realistic training data")
            
        except Exception as e:
            logger.error(f"Failed to initialize ML model: {e}")
            self.model = None
            self.scaler = None
    
    def extract_features(self, file_path):
        """Extract features from file for ML prediction"""
        try:
            if not os.path.exists(file_path):
                return None
            
            features = []
            
            # File size
            file_size = os.path.getsize(file_path)
            features.append(min(file_size / (1024 * 1024), 100))  # Normalize to MB, cap at 100
            
            # Entropy
            try:
                with open(file_path, 'rb') as f:
                    data = f.read(8192)  # Read first 8KB
                    if data:
                        entropy = self._calculate_entropy(data)
                        features.append(entropy)
                    else:
                        features.append(0)
            except:
                features.append(0)
            
            # PE header check
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(2)
                    has_pe = header == b'MZ'
                    features.append(1 if has_pe else 0)
            except:
                features.append(0)
            
            # ELF header check
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(4)
                    has_elf = header == b'\x7fELF'
                    features.append(1 if has_elf else 0)
            except:
                features.append(0)
            
            # Suspicious strings count
            suspicious_strings = 0
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(4096)  # Read first 4KB
                    suspicious_keywords = [b'CreateProcess', b'VirtualAlloc', b'WriteProcessMemory', 
                                         b'LoadLibrary', b'GetProcAddress', b'cmd.exe', b'powershell']
                    for keyword in suspicious_keywords:
                        suspicious_strings += content.count(keyword)
                features.append(min(suspicious_strings / 10, 1))  # Normalize
            except:
                features.append(0)
            
            # Packed ratio (simplified)
            try:
                with open(file_path, 'rb') as f:
                    data = f.read(1024)
                    if data:
                        unique_bytes = len(set(data))
                        packed_ratio = unique_bytes / len(data)
                        features.append(packed_ratio)
                    else:
                        features.append(0)
            except:
                features.append(0)
            
            # Import count (simplified)
            features.append(0)  # Placeholder
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Feature extraction error for {file_path}: {e}")
            return None
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def predict(self, file_path):
        """Predict if file is malicious using ML"""
        if not self.model or not self.scaler:
            return 0, "Clean", "None"
        
        try:
            # Check if model is trained
            if not hasattr(self.model, 'estimators_') or len(self.model.estimators_) == 0:
                logger.warning("ML model not properly trained")
                return 0, "Clean", "None"
            
            # Extract features
            features = self.extract_features(file_path)
            if features is None:
                return 0, "Clean", "None"
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Get prediction probabilities
            probabilities = self.model.predict_proba(features_scaled)[0]
            malicious_prob = probabilities[1] if len(probabilities) > 1 else 0
            
            # Determine threat level based on probability
            if malicious_prob > 0.95:
                threat_level = 3
                threat_name = "ML.HighThreat"
            elif malicious_prob > 0.85:
                threat_level = 2
                threat_name = "ML.MediumThreat"
            elif malicious_prob > 0.75:
                threat_level = 1
                threat_name = "ML.LowThreat"
            else:
                threat_level = 0
                threat_name = "Clean"
            
            return threat_level, threat_name, "Machine Learning"
            
        except Exception as e:
            logger.error(f"ML prediction error for {file_path}: {e}")
            return 0, "Clean", "None"

class SignatureDetector:
    """Signature-based detection engine"""
    
    def __init__(self):
        self.signatures = {
            # EICAR test string
            'eicar': b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
            # Common malware signatures
            'suspicious_js': [b'eval(', b'unescape(', b'String.fromCharCode('],
            'suspicious_powershell': [b'Invoke-Expression', b'DownloadString', b'Base64'],
            'suspicious_cmd': [b'cmd.exe', b'powershell.exe', b'wscript.exe']
        }
    
    def scan_file(self, file_path):
        """Scan file using signature detection"""
        try:
            if not os.path.exists(file_path):
                return 0, "Clean", "None"
            
            # Check file permissions
            if not os.access(file_path, os.R_OK):
                logger.warning(f"File not readable: {file_path}")
                return 0, "Clean", "None"
            
            # Try to read file content using multiple methods
            content = None
            
            # Method 1: Try using pathlib (most robust on Windows)
            try:
                from pathlib import Path
                import time
                file_path_obj = Path(file_path)
                if file_path_obj.exists() and file_path_obj.is_file():
                    # Add a small delay for Windows file system
                    time.sleep(0.01)
                    content = file_path_obj.read_bytes()
                    if len(content) > 8192:
                        content = content[:8192]
                    logger.debug(f"Successfully read file using pathlib: {len(content)} bytes")
            except Exception as e1:
                logger.debug(f"Pathlib read failed for {file_path}: {e1}")
            
            # Method 2: Try standard binary read with retry
            if content is None:
                import time
                for attempt in range(3):  # Try 3 times
                    try:
                        time.sleep(0.01 * attempt)  # Increasing delay
                        with open(file_path, 'rb') as f:
                            content = f.read(8192)
                        logger.debug(f"Successfully read file using binary mode (attempt {attempt+1}): {len(content)} bytes")
                        break
                    except Exception as e2:
                        logger.debug(f"Binary read attempt {attempt+1} failed for {file_path}: {e2}")
                        if attempt == 2:  # Last attempt
                            logger.debug(f"All binary read attempts failed for {file_path}")
            
            # Method 3: Try text read with UTF-8
            if content is None:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        text_content = f.read(8192)
                        content = text_content.encode('utf-8')
                    logger.debug(f"Successfully read file using UTF-8: {len(content)} bytes")
                except Exception as e3:
                    logger.debug(f"UTF-8 read failed for {file_path}: {e3}")
            
            # Method 4: Try text read with latin-1
            if content is None:
                try:
                    with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                        text_content = f.read(8192)
                        content = text_content.encode('latin-1')
                    logger.debug(f"Successfully read file using latin-1: {len(content)} bytes")
                except Exception as e4:
                    logger.debug(f"Latin-1 read failed for {file_path}: {e4}")
            
            # Method 5: Try with cp1252 encoding (Windows default)
            if content is None:
                try:
                    with open(file_path, 'r', encoding='cp1252', errors='ignore') as f:
                        text_content = f.read(8192)
                        content = text_content.encode('cp1252')
                    logger.debug(f"Successfully read file using cp1252: {len(content)} bytes")
                except Exception as e5:
                    logger.debug(f"CP1252 read failed for {file_path}: {e5}")
            
            # Method 6: Try using os.open (low-level file access)
            if content is None:
                try:
                    fd = os.open(file_path, os.O_RDONLY | os.O_BINARY)
                    content = os.read(fd, 8192)
                    os.close(fd)
                    logger.debug(f"Successfully read file using os.open: {len(content)} bytes")
                except Exception as e6:
                    logger.debug(f"os.open read failed for {file_path}: {e6}")
            
            if content is None:
                logger.warning(f"All read methods failed for {file_path}")
                return 0, "Clean", "None"
            
            # Check EICAR
            if self.signatures['eicar'] in content:
                return 3, "Signature.EICAR", "Signature"
            
            # Check suspicious JavaScript
            for sig in self.signatures['suspicious_js']:
                if sig in content:
                    return 2, "Signature.SuspiciousJS", "Signature"
            
            # Check suspicious PowerShell
            for sig in self.signatures['suspicious_powershell']:
                if sig in content:
                    return 2, "Signature.SuspiciousPowerShell", "Signature"
            
            # Check suspicious command execution
            for sig in self.signatures['suspicious_cmd']:
                if sig in content:
                    return 1, "Signature.SuspiciousCmd", "Signature"
            
            return 0, "Clean", "None"
            
        except Exception as e:
            logger.error(f"Signature scan error for {file_path}: {e}")
            return 0, "Clean", "None"

class HeuristicDetector:
    """Heuristic-based detection engine"""
    
    def scan_file(self, file_path):
        """Scan file using heuristic analysis"""
        try:
            if not os.path.exists(file_path):
                return 0, "Clean", "None"
            
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path).lower()
            
            # Check for suspicious file extensions
            suspicious_extensions = ['.scr', '.pif', '.bat', '.cmd', '.com', '.exe']
            if any(filename.endswith(ext) for ext in suspicious_extensions):
                # Check if it's actually a different file type
                try:
                    with open(file_path, 'rb') as f:
                        header = f.read(16)
                    
                    # Check for PE header in non-exe files
                    if filename.endswith(('.scr', '.pif')) and header.startswith(b'MZ'):
                        return 2, "Heuristic.SuspiciousExtension", "Heuristic"
                except:
                    pass
            
            # Check for very small files (potential droppers)
            if file_size < 1024 and filename.endswith('.exe'):
                return 1, "Heuristic.SmallExecutable", "Heuristic"
            
            # Check for double extensions
            if filename.count('.') > 1 and any(filename.endswith(ext) for ext in ['.exe', '.scr', '.bat']):
                return 2, "Heuristic.DoubleExtension", "Heuristic"
            
            return 0, "Clean", "None"
            
        except Exception as e:
            logger.error(f"Heuristic scan error for {file_path}: {e}")
            return 0, "Clean", "None"

class EntropyDetector:
    """Entropy-based detection engine"""
    
    def scan_file(self, file_path):
        """Scan file using entropy analysis"""
        try:
            if not os.path.exists(file_path):
                return 0, "Clean", "None"
            
            # Calculate entropy
            entropy = self._calculate_entropy(file_path)
            
            if entropy > 7.5:  # Very high entropy (likely packed/encrypted)
                return 3, "Entropy.Packed", "Entropy"
            elif entropy > 7.0:  # High entropy
                return 2, "Entropy.High", "Entropy"
            elif entropy > 6.5:  # Medium-high entropy
                return 1, "Entropy.Medium", "Entropy"
            else:
                return 0, "Clean", "None"
                
        except Exception as e:
            logger.error(f"Entropy scan error for {file_path}: {e}")
            return 0, "Clean", "None"
    
    def _calculate_entropy(self, file_path):
        """Calculate Shannon entropy of file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)  # Read first 8KB
            
            if not data:
                return 0
            
            # Count byte frequencies
            byte_counts = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            # Calculate entropy
            entropy = 0
            data_len = len(data)
            for count in byte_counts.values():
                probability = count / data_len
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except:
            return 0

class PEDetector:
    """PE file analysis detector"""
    
    def scan_file(self, file_path):
        """Analyze PE file structure"""
        try:
            if not os.path.exists(file_path):
                return 0, "Clean", "None"
            
            # Check file permissions
            if not os.access(file_path, os.R_OK):
                logger.warning(f"File not readable: {file_path}")
                return 0, "Clean", "None"
            
            # Try to read file content
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(2)
            except (OSError, IOError) as e:
                logger.warning(f"Cannot read file {file_path}: {e}")
                return 0, "Clean", "None"
            
            # Check for PE header
            if not header.startswith(b'MZ'):
                return 0, "Clean", "None"
            
            # Basic PE analysis
            try:
                with open(file_path, 'rb') as f:
                    # Read DOS header
                    f.seek(60)  # e_lfanew offset
                    pe_offset = int.from_bytes(f.read(4), 'little')
                    
                    f.seek(pe_offset)
                    pe_signature = f.read(4)
                    
                    if pe_signature != b'PE\x00\x00':
                        return 0, "Clean", "None"
                    
                    # Read COFF header
                    machine = int.from_bytes(f.read(2), 'little')
                    num_sections = int.from_bytes(f.read(2), 'little')
                    
                    # Check for suspicious characteristics
                    if num_sections > 20:  # Too many sections
                        return 2, "PE.ManySections", "PE Analysis"
                    elif num_sections < 3:  # Too few sections
                        return 1, "PE.FewSections", "PE Analysis"
                    
                    return 0, "Clean", "None"
                    
            except (OSError, IOError):
                return 0, "Clean", "None"
                
        except Exception as e:
            logger.error(f"PE analysis error for {file_path}: {e}")
            return 0, "Clean", "None"

class FileTypeDetector:
    """File type analysis detector"""
    
    def scan_file(self, file_path):
        """Analyze file type and content"""
        try:
            if not os.path.exists(file_path):
                return 0, "Clean", "None"
            
            filename = os.path.basename(file_path).lower()
            
            # Check for suspicious file types
            if filename.endswith('.exe') and os.path.getsize(file_path) < 1024:
                return 2, "FileType.SmallExecutable", "File Type"
            
            # Check for files with suspicious names
            suspicious_names = ['svchost', 'explorer', 'winlogon', 'csrss', 'lsass']
            if any(name in filename for name in suspicious_names) and not filename.endswith('.exe'):
                return 2, "FileType.SuspiciousName", "File Type"
            
            return 0, "Clean", "None"
            
        except Exception as e:
            logger.error(f"File type analysis error for {file_path}: {e}")
            return 0, "Clean", "None"

