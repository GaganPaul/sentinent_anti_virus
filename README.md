# ⚔️ Sentinel - Advanced Threat Protection System

A timeless watchman guarding your digital realm. Sentinel is a comprehensive antivirus solution built with Python and Tkinter, featuring advanced detection methods, modern UI design, and multi-layered security analysis.

![Sentinel](https://img.shields.io/badge/Sentinel-Advanced%20Threat%20Protection-00ff88?style=for-the-badge&logo=shield&logoColor=white)

## ✨ Features

### 🎨 Modern UI Design
- **Dark Theme**: Sleek dark interface with neon green accents
- **Responsive Layout**: Clean, organized panels for optimal user experience
- **Real-time Progress**: Live progress bars and status updates
- **Professional Styling**: Custom Tkinter styling with modern aesthetics

### 🔍 Advanced Scanning Capabilities
- **File Scan**: Scan individual files for threats
- **Directory Scan**: Recursively scan entire directories
- **System Scan**: Full system-wide threat detection
- **Quick Scan**: Fast scan of common user locations
- **Custom YARA Rules**: Advanced pattern matching with YARA-like syntax
- **Multi-threaded Processing**: Parallel scanning for optimal performance

### 🛡️ Multi-Layer Security Features
- **Signature-Based Detection**: Traditional pattern matching against known malware
- **Heuristic Analysis**: Behavioral and statistical analysis for unknown threats
- **Behavioral Analysis**: Content pattern analysis for malicious behavior
- **Entropy Analysis**: Detection of packed/encrypted content
- **PE File Analysis**: Windows executable structural analysis
- **File Type Analysis**: Magic number and format validation
- **Hash Verification**: MD5/SHA256 comparison against threat databases
- **Real-time Results**: Live threat reporting with detailed classification

### 📊 Advanced Features
- **Progress Tracking**: Real-time scan progress with file counts
- **Threat Statistics**: Live counter of threats found with severity levels
- **Detailed Results**: Comprehensive scan results with detection methods
- **Scan History**: Timestamped results for each scan
- **Threat Classification**: 4-level threat severity system (Clean, Low, Medium, High)
- **Detection Method Tracking**: Shows which detection method identified each threat
- **Performance Optimization**: Chunked reading and early termination for efficiency

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- Windows, macOS, or Linux

### Quick Start
1. **Clone or download** the project files
2. **Install dependencies** (for advanced features):
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the application**:
   ```bash
   python standalone_antivirus.py
   ```

### Advanced Setup (Optional)
For enhanced detection capabilities, install additional packages:
```bash
# For YARA rules support
pip install yara-python

# For machine learning features
pip install scikit-learn numpy

# For advanced file analysis
pip install pefile python-magic

# For network analysis
pip install scapy
   ```

### No Dependencies Required
The application uses only Python's standard library for basic functionality, making it lightweight and portable.

## 🎯 Usage

### Getting Started
1. **Launch Sentinel** by running `standalone_antivirus.py`
2. **Choose your scan type**:
   - 📁 **Scan File**: Select a single file to scan
   - 📂 **Scan Directory**: Choose a folder to scan recursively
   - 💻 **System Scan**: Scan your entire system
   - ⚡ **Quick Scan**: Fast scan of common locations

3. **Start the scan** by clicking the "▶️ Start Scan" button
4. **Monitor progress** in real-time with the progress bar and statistics
5. **Review results** in the detailed results table with threat classifications

### Understanding Results
- **Clean**: File is safe, no threats detected
- **Low**: Suspicious characteristics detected (entropy, file type, etc.)
- **Medium**: Multiple suspicious indicators or behavioral patterns
- **High**: Confirmed threat detected (signature match, malicious behavior)

### Threat Detection Methods
- **Signature**: Traditional pattern matching against known malware
- **Heuristic**: Statistical analysis of file characteristics
- **Behavioral**: Content pattern analysis for malicious behavior
- **Entropy**: Detection of packed/encrypted content
- **PE Analysis**: Windows executable structural analysis
- **File Type**: Magic number and format validation

## 🔧 Technical Details

### Architecture
- **GUI Framework**: Tkinter with custom styling
- **Threading**: Multi-threaded scanning for responsive UI
- **File Processing**: Efficient file traversal and analysis
- **Memory Management**: Optimized for large directory scans
- **Modular Design**: Separate detection engines for different analysis types

### Multi-Layer Security Implementation
- **Signature-based Detection**: Pattern matching against known threats
- **Heuristic Analysis**: Statistical analysis of file characteristics
- **Behavioral Analysis**: Content pattern analysis for malicious behavior
- **Entropy Analysis**: Shannon entropy calculation for packed content detection
- **PE File Analysis**: Windows executable structural validation
- **File Type Analysis**: Magic number and format validation
- **Hash Verification**: MD5/SHA256 checksums for file integrity

### Performance Optimizations
- **Chunked Reading**: Efficient file content analysis (1KB-4KB chunks)
- **Progress Throttling**: UI updates without performance impact
- **Early Termination**: Stop scanning if high threat detected
- **File Limits**: Configurable scan limits for large directories
- **Error Handling**: Graceful handling of inaccessible files
- **Parallel Processing**: Multi-threaded file analysis

## 🎨 UI Components

### Main Interface
- **Header Panel**: Application title and branding
- **Left Panel**: Scan options and controls
- **Right Panel**: Progress tracking and results display

### Scan Options
- **File Selection**: Browse and select individual files
- **Directory Selection**: Choose folders for recursive scanning
- **System Scan**: Full system-wide threat detection
- **Quick Scan**: Fast scan of user directories

### Results Display
- **Progress Bar**: Real-time scan completion percentage
- **Statistics**: Files scanned, threats found, elapsed time
- **Results Table**: Detailed file-by-file scan results
- **Status Updates**: Live scanning status messages

## 🔒 Security Considerations

### Important Notes
- This is a **demonstration antivirus** for educational purposes
- **Not a replacement** for professional antivirus software
- **Limited threat database** compared to commercial solutions
- **Use responsibly** and don't rely solely on this tool

### Recommended Usage
- **Educational purposes**: Learn about antivirus concepts
- **Development testing**: Test application security
- **Personal projects**: Basic file analysis needs
- **Complement existing security**: Use alongside professional tools

## 🛡️ Advanced Detection Methods

### YARA Rules Implementation
YARA is a powerful pattern matching engine used by professional antivirus software. Here's how to implement it:

#### 1. Install YARA Python Bindings
```bash
pip install yara-python
```

#### 2. Create YARA Rules File
Create `rules.yar`:
```yara
rule Trojan_Generic {
    meta:
        description = "Generic Trojan detection"
        author = "Sentinel"
        date = "2024-01-01"
    
    strings:
        $a = "eval(" nocase
        $b = "shell_exec" nocase
        $c = "system(" nocase
        $d = "exec(" nocase
    
    condition:
        2 of them
}

rule Ransomware_Generic {
    meta:
        description = "Generic Ransomware detection"
        author = "Sentinel"
        date = "2024-01-01"
    
    strings:
        $a = "encrypt" nocase
        $b = "decrypt" nocase
        $c = "ransom" nocase
        $d = "bitcoin" nocase
        $e = "payment" nocase
    
    condition:
        3 of them
}

rule PowerShell_Obfuscated {
    meta:
        description = "Obfuscated PowerShell detection"
        author = "Sentinel"
        date = "2024-01-01"
    
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "base64" nocase
        $d = "frombase64string" nocase
    
    condition:
        all of them
}
```

#### 3. Integrate YARA into Sentinel
```python
import yara

class YARADetector:
    def __init__(self, rules_file="rules.yar"):
        self.rules = yara.compile(rules_file)
    
    def scan_file(self, file_path):
        try:
            matches = self.rules.match(file_path)
            if matches:
                return 3, f"YARA.{matches[0].rule}", "YARA"
            return 0, "Clean", "None"
        except:
            return 0, "Clean", "None"
```

### Machine Learning Detection
Implement AI-based threat detection:

#### 1. Install Required Packages
```bash
pip install scikit-learn numpy pandas
```

#### 2. Feature Extraction
```python
import numpy as np
from sklearn.ensemble import RandomForestClassifier

class MLDetector:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100)
        self.features = []
        self.labels = []
    
    def extract_features(self, file_path):
        features = []
        
        # File size
        size = os.path.getsize(file_path)
        features.append(size)
        
        # Entropy
        entropy = self.calculate_entropy(file_path)
        features.append(entropy)
        
        # String patterns
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read(1024)
            features.append(len(re.findall(r'eval\(', content)))
            features.append(len(re.findall(r'shell_exec', content)))
            features.append(len(re.findall(r'http://', content)))
        
        # File extension
        ext = os.path.splitext(file_path)[1].lower()
        features.append(1 if ext in ['.exe', '.bat', '.cmd'] else 0)
        
        return np.array(features)
    
    def train_model(self, training_data):
        X = np.array([self.extract_features(path) for path, label in training_data])
        y = np.array([label for _, label in training_data])
        self.model.fit(X, y)
    
    def predict(self, file_path):
        features = self.extract_features(file_path).reshape(1, -1)
        prediction = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0].max()
        
        if prediction == 1 and probability > 0.8:
            return 3, "ML.Malware", "Machine Learning"
        elif prediction == 1 and probability > 0.6:
            return 2, "ML.Suspicious", "Machine Learning"
        else:
            return 0, "Clean", "None"
```

### Sandbox Analysis
Implement dynamic analysis in isolated environment:

```python
import subprocess
import tempfile
import os

class SandboxDetector:
    def __init__(self):
        self.sandbox_path = tempfile.mkdtemp()
    
    def analyze_file(self, file_path):
        try:
            # Copy file to sandbox
            sandbox_file = os.path.join(self.sandbox_path, "test_file")
            shutil.copy2(file_path, sandbox_file)
            
            # Monitor system calls
            result = subprocess.run(
                ['strace', '-f', '-e', 'trace=file,process,network', sandbox_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Analyze behavior
            if self.detect_suspicious_behavior(result.stderr):
                return 3, "Sandbox.Malware", "Sandbox"
            else:
                return 0, "Clean", "None"
                
        except:
            return 0, "Clean", "None"
    
    def detect_suspicious_behavior(self, strace_output):
        suspicious_patterns = [
            'openat.*/etc/passwd',
            'openat.*/etc/shadow',
            'socket.*AF_INET',
            'execve.*/bin/sh',
            'ptrace.*PTRACE_ATTACH'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, strace_output):
                return True
        return False
```

### Network Analysis
Monitor network traffic for malicious patterns:

```python
import socket
import threading

class NetworkMonitor:
    def __init__(self):
        self.suspicious_connections = []
        self.monitoring = False
    
    def start_monitoring(self):
        self.monitoring = True
        monitor_thread = threading.Thread(target=self._monitor_network)
        monitor_thread.daemon = True
        monitor_thread.start()
    
    def _monitor_network(self):
        # Monitor network connections
        # This is a simplified example
        while self.monitoring:
            # Check for suspicious network activity
            # Implementation depends on platform
            time.sleep(1)
    
    def detect_suspicious_activity(self, connection_data):
        suspicious_indicators = [
            'high_frequency_connections',
            'suspicious_domains',
            'unusual_ports',
            'encrypted_traffic_patterns'
        ]
        
        threat_score = 0
        for indicator in suspicious_indicators:
            if self._check_indicator(connection_data, indicator):
                threat_score += 1
        
        if threat_score >= 3:
            return 3, "Network.Malware", "Network Analysis"
        elif threat_score >= 1:
            return 2, "Network.Suspicious", "Network Analysis"
        else:
            return 0, "Clean", "None"
```

## 🛠️ Customization

### Modifying Scan Behavior
Edit the `load_virus_signatures()` method to add custom threat patterns:
```python
self.virus_signatures = {
    'custom_threat': 'your_pattern_here',
    'another_threat': 'another_pattern'
}
```

### Adding Custom Detection Methods
```python
def custom_detection_method(self, file_path):
    """Add your custom detection logic here"""
    try:
        # Your detection logic
        if self.detect_custom_threat(file_path):
            return 3, "Custom.Threat", "Custom Method"
        return 0, "Clean", "None"
    except:
        return 0, "Clean", "None"

# Add to detection pipeline
def detect_malware(self, file_path):
    # ... existing methods ...
    
    # Add custom method
    threat_level, threat_name = self.custom_detection_method(file_path)
    if threat_level > 0:
        return threat_level, threat_name, "Custom"
```

### UI Customization
Modify colors and styling in the `setup_styles()` method:
```python
style.configure('Custom.TLabel', 
               background='#your_color', 
               foreground='#your_text_color')
```

### Advanced Features
- **Real-time monitoring**: File system watchers
- **Scheduled scans**: Automated scanning
- **Quarantine system**: Isolate threats
- **Cloud signatures**: Online threat database
- **Behavioral analysis**: Runtime monitoring
- **Memory analysis**: Process memory scanning

## 📁 Project Structure
```
sentinent_anti_virus/
├── standalone_antivirus.py    # Main Sentinel application
├── DETECTION_METHODS.md       # Detailed detection methods documentation
├── README.md                  # This documentation
├── rules.yar                  # YARA rules file (create this)
├── requirements.txt           # Python dependencies
└── (future extensions)        # Additional modules
```

## 🚀 Making Your Antivirus the Best

### 1. **Implement YARA Rules**
- Create comprehensive YARA rules for different malware families
- Use community rule sets from GitHub
- Regularly update rules with new threat intelligence

### 2. **Add Machine Learning**
- Train models on large datasets of malware and clean files
- Use ensemble methods for better accuracy
- Implement feature engineering for better detection

### 3. **Enhance Behavioral Analysis**
- Monitor file system changes
- Track network connections
- Analyze process behavior
- Implement sandboxing for dynamic analysis

### 4. **Improve Performance**
- Use multiprocessing for parallel scanning
- Implement caching for frequently scanned files
- Optimize file reading with memory mapping
- Use database for signature storage

### 5. **Add Real-time Protection**
- Implement file system watchers
- Monitor process creation
- Track network connections
- Implement quarantine system

### 6. **Cloud Integration**
- Connect to threat intelligence feeds
- Implement cloud-based signature updates
- Use cloud sandboxing services
- Add reputation-based detection

### 7. **Advanced Features**
- Memory analysis for running processes
- Registry monitoring
- USB device scanning
- Email attachment analysis
- Web traffic monitoring

## 🚀 Quick Start Guide for Advanced Features

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Integrate YARA Rules
1. The `rules.yar` file is already created with comprehensive rules
2. Add YARA detection to your `standalone_antivirus.py`:

```python
import yara

class YARADetector:
    def __init__(self, rules_file="rules.yar"):
        try:
            self.rules = yara.compile(rules_file)
        except:
            self.rules = None
    
    def scan_file(self, file_path):
        if not self.rules:
            return 0, "Clean", "None"
        try:
            matches = self.rules.match(file_path)
            if matches:
                return 3, f"YARA.{matches[0].rule}", "YARA"
            return 0, "Clean", "None"
        except:
            return 0, "Clean", "None"

# Add to your SentinelAntivirus class
def detect_malware(self, file_path):
    # ... existing methods ...
    
    # Add YARA detection
    yara_detector = YARADetector()
    threat_level, threat_name = yara_detector.scan_file(file_path)
    if threat_level > 0:
        return threat_level, threat_name, "YARA"
```

### Step 3: Add Machine Learning Detection
```python
# Add this to your detection pipeline
def ml_detection(self, file_path):
    # Extract features and use ML model
    # Implementation depends on your ML setup
    pass
```

### Step 4: Enhance Performance
- Use multiprocessing for parallel file scanning
- Implement file caching for repeated scans
- Add early termination for high-threat files

### Step 5: Add Real-time Monitoring
```python
import watchdog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileMonitor(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            # Scan new file immediately
            self.scan_file(event.src_path)
```

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Areas for Improvement
- **Enhanced threat detection**: Machine learning algorithms
- **Real-time protection**: File system monitoring
- **Cloud integration**: Online signature updates
- **Performance optimization**: Faster scanning algorithms
- **UI enhancements**: Additional themes and layouts
- **YARA integration**: Advanced pattern matching
- **Sandbox analysis**: Dynamic malware analysis
- **Network monitoring**: Traffic analysis
- **Memory analysis**: Process memory scanning
- **Quarantine system**: Threat isolation

## 📄 License

This project is open source and available under the MIT License.

## ⚠️ Disclaimer

**This software is for educational and demonstration purposes only.** It is not intended to replace professional antivirus solutions. The authors are not responsible for any damage or security issues that may arise from using this software. Always use reputable, professional antivirus software for actual protection.

## 🆘 Support

For questions, issues, or contributions:
- Create an issue in the project repository
- Review the documentation above
- Check the code comments for implementation details

---

**Built with ❤️ using Python and Tkinter**

*Sentinel - A timeless watchman guarding your digital realm*
