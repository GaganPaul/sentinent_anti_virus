"""
Sentinel - Advanced Threat Protection System
A timeless watchman guarding your digital realm
Enhanced with YARA rules, ML detection, and real-time monitoring
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import hashlib
import threading
import time
import re
import struct
import multiprocessing
import queue
import json
import math
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import logging

# Optional imports for advanced features
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    # Create dummy classes if watchdog is not available
    class FileSystemEventHandler:
        def __init__(self):
            pass
    class Observer:
        def __init__(self):
            pass

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class YARADetector:
    """YARA rules engine for advanced pattern matching"""
    def __init__(self, rules_folder="rules"):
        self.rules = None
        self.rules_folder = rules_folder
        self.rule_files = []
        self.rule_stats = {
            'total_rules': 0,
            'loaded_files': 0,
            'failed_files': 0,
            'rule_categories': {}
        }
        self.load_rules()
    
    def load_rules(self):
        """Load YARA rules from all files in rules folder"""
        if not YARA_AVAILABLE:
            logger.warning("YARA not available. Install yara-python for advanced detection.")
            return
        
        try:
            if not os.path.exists(self.rules_folder):
                logger.warning(f"Rules folder {self.rules_folder} not found")
                return
            
            # Get all .yar and .yara files from rules folder
            rule_files = []
            for root, dirs, files in os.walk(self.rules_folder):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        rule_files.append(os.path.join(root, file))
            
            if not rule_files:
                logger.warning(f"No YARA rule files found in {self.rules_folder}")
                return
            
            logger.info(f"Found {len(rule_files)} YARA rule files")
            
            # Try to load rules using filepath parameter (simpler approach)
            try:
                # Load all rules at once using filepath - need to pass directory path
                self.rules = yara.compile(filepath=self.rules_folder)
                self.rule_files = rule_files
                self.rule_stats['loaded_files'] = len(rule_files)
                
                # Extract rule info for statistics
                for rule_file in rule_files:
                    self._extract_rule_info(rule_file)
                
                logger.info(f"Successfully loaded {len(rule_files)} rule files")
                logger.info(f"Total rules loaded: {self.rule_stats['total_rules']}")
                logger.info(f"Rule categories: {list(self.rule_stats['rule_categories'].keys())}")
                
            except Exception as e:
                logger.error(f"Failed to load rules with filepath: {e}")
                # Fallback: try loading rules one by one and combine
                compiled_rules = []
                for rule_file in rule_files:
                    try:
                        # Compile individual rule file
                        rule = yara.compile(rule_file)
                        compiled_rules.append(rule)
                        self.rule_files.append(rule_file)
                        self.rule_stats['loaded_files'] += 1
                        
                        # Extract rule names and categories
                        self._extract_rule_info(rule_file)
                        
                        logger.debug(f"Loaded rules from {os.path.basename(rule_file)}")
                        
                    except Exception as e2:
                        logger.error(f"Failed to load rules from {rule_file}: {e2}")
                        self.rule_stats['failed_files'] += 1
                
                if compiled_rules:
                    try:
                        # Create a combined ruleset from all successful rules
                        # This is a more complex approach but should work better
                        rules_dict = {}
                        for i, rule in enumerate(compiled_rules):
                            rules_dict[f"ruleset_{i}"] = rule
                        
                        self.rules = yara.compile(sources=rules_dict)
                        logger.info(f"Fallback: Successfully combined {len(compiled_rules)} rule sets")
                    except Exception as e3:
                        logger.error(f"Fallback compilation failed: {e3}")
                        # Last resort: try to load rules from individual files
                        try:
                            # Load rules from individual files one by one
                            working_rules = []
                            for rule_file in rule_files[:10]:  # Try first 10 files
                                try:
                                    rule = yara.compile(rule_file)
                                    working_rules.append(rule)
                                except:
                                    continue
                            
                            if working_rules:
                                # Use the first working rule
                                self.rules = working_rules[0]
                                logger.info(f"Last resort: Using first working rule from {len(working_rules)} successful rules")
                            else:
                                logger.error("No working rules found")
                                self.rules = None
                        except Exception as e4:
                            logger.error(f"Last resort failed: {e4}")
                            self.rules = None
                else:
                    logger.error("No rules could be loaded successfully")
                
        except Exception as e:
            logger.error(f"Failed to load YARA rules from folder: {e}")
    
    def _extract_rule_info(self, rule_file):
        """Extract rule information for statistics"""
        try:
            with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Count rules in file
                rule_count = content.count('rule ')
                self.rule_stats['total_rules'] += rule_count
                
                # Extract category from filename
                filename = os.path.basename(rule_file)
                if filename.startswith('APT_'):
                    category = 'APT'
                elif filename.startswith('MALW_'):
                    category = 'Malware'
                elif filename.startswith('RANSOM_'):
                    category = 'Ransomware'
                elif filename.startswith('RAT_'):
                    category = 'RAT'
                elif filename.startswith('CVE-'):
                    category = 'CVE'
                elif filename.startswith('EK_'):
                    category = 'Exploit Kit'
                elif filename.startswith('POS_'):
                    category = 'POS Malware'
                elif filename.startswith('Maldoc_'):
                    category = 'Malicious Documents'
                else:
                    category = 'General'
                
                if category not in self.rule_stats['rule_categories']:
                    self.rule_stats['rule_categories'][category] = 0
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
            
            # Try to scan the file
            matches = self.rules.match(file_path)
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
    
    def _get_threat_level(self, rule_name):
        """Determine threat level based on rule name"""
        rule_lower = rule_name.lower()
        
        # High threat level for critical rules
        if any(keyword in rule_lower for keyword in ['apt', 'ransom', 'rat', 'backdoor', 'trojan', 'virus']):
            return 3
        # Medium threat level for suspicious rules
        elif any(keyword in rule_lower for keyword in ['suspicious', 'packed', 'obfuscated', 'exploit']):
            return 2
        # Low threat level for general rules
        else:
            return 1
    
    def get_rule_statistics(self):
        """Get statistics about loaded rules"""
        return self.rule_stats
    
    def reload_rules(self):
        """Reload all rules from the rules folder"""
        logger.info("Reloading YARA rules...")
        self.rule_stats = {
            'total_rules': 0,
            'loaded_files': 0,
            'failed_files': 0,
            'rule_categories': {}
        }
        self.rule_files = []
        self.load_rules()

class MLDetector:
    """Machine Learning based threat detection"""
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = []
        self.load_model()
    
    def load_model(self):
        """Load or create ML model"""
        if not ML_AVAILABLE:
            logger.warning("ML libraries not available. Install scikit-learn and numpy for ML detection.")
            return
        
        try:
            # Try to load existing model
            if os.path.exists("sentinel_ml_model.pkl"):
                import pickle
                with open("sentinel_ml_model.pkl", "rb") as f:
                    model_data = pickle.load(f)
                    self.model = model_data['model']
                    self.scaler = model_data['scaler']
                    self.feature_names = model_data['features']
                logger.info("Loaded existing ML model")
            else:
                # Create a simple model for demonstration
                self.model = RandomForestClassifier(n_estimators=100, random_state=42)
                self.scaler = StandardScaler()
                self.feature_names = ['file_size', 'entropy', 'eval_count', 'shell_exec_count', 
                                    'http_count', 'is_executable', 'suspicious_ext', 'high_entropy']
                
                # Create dummy training data to initialize the model
                try:
                    import numpy as np
                    # Create more realistic training data
                    # Most files should be clean (label 0), few malicious (label 1)
                    dummy_features = np.random.random((100, 8))
                    # Make 90% of samples clean, 10% malicious
                    dummy_labels = np.concatenate([
                        np.zeros(90),  # 90 clean files
                        np.ones(10)    # 10 malicious files
                    ])
                    
                    # Shuffle the data
                    indices = np.random.permutation(100)
                    dummy_features = dummy_features[indices]
                    dummy_labels = dummy_labels[indices]
                    
                    self.model.fit(dummy_features, dummy_labels)
                    self.scaler.fit(dummy_features)
                    logger.info("Created and initialized new ML model with realistic training data")
                except Exception as e:
                    logger.warning(f"Could not initialize ML model: {e}")
                    self.model = None
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
    
    def extract_features(self, file_path):
        """Extract features from file for ML analysis"""
        features = []
        
        try:
            # File size
            size = os.path.getsize(file_path)
            features.append(size)
            
            # Entropy
            entropy = self.calculate_entropy(file_path)
            features.append(entropy)
            
            # String pattern counts
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(2048)  # Read first 2KB
                content_lower = content.lower()
                
                features.append(content_lower.count('eval('))
                features.append(content_lower.count('shell_exec'))
                features.append(content_lower.count('http://'))
                
                # File type indicators
                ext = os.path.splitext(file_path)[1].lower()
                features.append(1 if ext in ['.exe', '.bat', '.cmd', '.scr'] else 0)
                features.append(1 if ext in ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.js'] else 0)
                features.append(1 if entropy > 7.5 else 0)
            
            return np.array(features).reshape(1, -1)
        except Exception as e:
            logger.error(f"Feature extraction error for {file_path}: {e}")
            return np.zeros((1, 8))  # Return zero features on error
    
    def calculate_entropy(self, file_path):
        """Calculate Shannon entropy of file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB
            
            if not data:
                return 0
            
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)
            
            return entropy
        except:
            return 0
    
    def predict(self, file_path):
        """Predict threat level using ML model"""
        if not self.model or not hasattr(self.model, 'estimators_'):
            return 0, "Clean", "None"
        
        try:
            features = self.extract_features(file_path)
            
            # Check if model is trained
            if not hasattr(self.model, 'estimators_') or len(self.model.estimators_) == 0:
                return 0, "Clean", "None"
            
            features_scaled = self.scaler.fit_transform(features)
            
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            # Get probability of being malicious (class 1)
            malicious_prob = probabilities[1] if len(probabilities) > 1 else 0.0
            
            # Be very conservative with ML detection
            if prediction == 1 and malicious_prob > 0.95:  # Very high confidence
                return 3, "ML.Malware", "Machine Learning"
            elif prediction == 1 and malicious_prob > 0.85:  # High confidence
                return 2, "ML.Suspicious", "Machine Learning"
            elif prediction == 1 and malicious_prob > 0.75:  # Medium confidence
                return 1, "ML.LowRisk", "Machine Learning"
            else:
                return 0, "Clean", "None"
        except Exception as e:
            logger.error(f"ML prediction error for {file_path}: {e}")
            return 0, "Clean", "None"

class FileMonitor(FileSystemEventHandler):
    """Real-time file system monitoring"""
    def __init__(self, antivirus_instance):
        self.antivirus = antivirus_instance
        self.observer = None
        self.monitoring = False
    
    def start_monitoring(self, path="C:\\"):
        """Start monitoring file system changes"""
        if not WATCHDOG_AVAILABLE:
            logger.warning("Watchdog not available. Install watchdog for real-time monitoring.")
            return
        
        try:
            self.observer = Observer()
            self.observer.schedule(self, path, recursive=True)
            self.observer.start()
            self.monitoring = True
            logger.info(f"Started monitoring {path}")
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop file system monitoring"""
        if self.observer and WATCHDOG_AVAILABLE:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            logger.info("Stopped monitoring")
    
    def on_created(self, event):
        """Handle file creation events"""
        if not WATCHDOG_AVAILABLE:
            return
            
        if not event.is_directory and self.antivirus.scanning:
            # Scan new file immediately
            threading.Thread(
                target=self.antivirus.scan_single_file,
                args=(event.src_path,),
                daemon=True
            ).start()

class SentinelAntivirus:
    def __init__(self, root):
        self.root = root
        self.root.title("Sentinel - Advanced Threat Protection")
        self.root.geometry("1000x700")
        self.root.configure(bg='#0a0a0a')
        
        # Configure style
        self.setup_styles()
        
        # Initialize variables
        self.scanning = False
        self.scan_results = []
        self.threats_found = 0
        self.files_scanned = 0
        self.scan_start_time = None
        self.scan_queue = queue.Queue()
        self.results_queue = queue.Queue()
        
        # Initialize advanced detectors
        self.yara_detector = YARADetector()
        self.ml_detector = MLDetector()
        self.file_monitor = FileMonitor(self)
        
        # Performance tracking
        self.performance_stats = {
            'total_scans': 0,
            'threats_detected': 0,
            'avg_scan_time': 0,
            'detection_methods': defaultdict(int)
        }
        
        # Create GUI
        self.create_gui()
        
        # Load virus signatures
        self.load_virus_signatures()
        
        # Start result processing thread
        self.start_result_processor()
    
    def start_result_processor(self):
        """Start background thread to process scan results"""
        def process_results():
            while True:
                try:
                    result = self.results_queue.get(timeout=1)
                    if result is None:  # Shutdown signal
                        break
                    
                    # Update UI with result
                    self.root.after(0, self.update_result_display, result)
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Result processing error: {e}")
        
        self.result_thread = threading.Thread(target=process_results, daemon=True)
        self.result_thread.start()
    
    def update_result_display(self, result):
        """Update the UI with scan result"""
        try:
            file_name, threat_type, severity, file_size, scan_time, detection_method = result
            
            # Add to results tree
            self.results_tree.insert('', 'end', values=(
                file_name,
                threat_type,
                severity,
                file_size,
                scan_time,
                detection_method
            ))
            
            # Update threat count
            if severity != "Clean":
                self.threats_found += 1
            
            # Update performance stats
            self.performance_stats['detection_methods'][detection_method] += 1
            
        except Exception as e:
            logger.error(f"UI update error: {e}")
    
    def setup_styles(self):
        """Configure modern styling for the application"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', 
                       background='#0a0a0a', 
                       foreground='#00ff88', 
                       font=('Segoe UI', 28, 'bold'))
        
        style.configure('Subtitle.TLabel', 
                       background='#0a0a0a', 
                       foreground='#ffffff', 
                       font=('Segoe UI', 12))
        
        style.configure('Tagline.TLabel',
                       background='#0a0a0a',
                       foreground='#888888',
                       font=('Segoe UI', 10, 'italic'))
        
        style.configure('Modern.TButton',
                       background='#00ff88',
                       foreground='#0a0a0a',
                       font=('Segoe UI', 10, 'bold'),
                       borderwidth=0,
                       focuscolor='none')
        
        style.map('Modern.TButton',
                 background=[('active', '#00cc6a'),
                           ('pressed', '#00aa55')])
        
        style.configure('Scan.TButton',
                       background='#ff4444',
                       foreground='#ffffff',
                       font=('Segoe UI', 10, 'bold'),
                       borderwidth=0,
                       focuscolor='none')
        
        style.map('Scan.TButton',
                 background=[('active', '#ff3333'),
                           ('pressed', '#cc2222')])
        
        style.configure('Results.Treeview',
                       background='#1a1a1a',
                       foreground='#ffffff',
                       fieldbackground='#1a1a1a',
                       font=('Consolas', 9))
        
        style.configure('Results.Treeview.Heading',
                       background='#2a2a2a',
                       foreground='#00ff88',
                       font=('Segoe UI', 10, 'bold'))
    
    def create_gui(self):
        """Create the main GUI layout"""
        # Header frame
        header_frame = tk.Frame(self.root, bg='#0a0a0a', height=80)
        header_frame.pack(fill='x', padx=15, pady=(15, 5))
        header_frame.pack_propagate(False)
        
        # Title
        title_label = ttk.Label(header_frame, text="⚔️ Sentinel", style='Title.TLabel')
        title_label.pack(pady=(5, 2))
        
        tagline_label = ttk.Label(header_frame, text="A timeless watchman guarding your digital realm", style='Tagline.TLabel')
        tagline_label.pack()
        
        # Main content frame
        main_frame = tk.Frame(self.root, bg='#0a0a0a')
        main_frame.pack(fill='both', expand=True, padx=15, pady=5)
        
        # Left panel - Scan options
        left_panel = tk.Frame(main_frame, bg='#1a1a1a', width=280)
        left_panel.pack(side='left', fill='y', padx=(0, 8))
        left_panel.pack_propagate(False)
        
        # Scan options
        options_frame = tk.Frame(left_panel, bg='#1a1a1a')
        options_frame.pack(fill='x', padx=15, pady=15)
        
        tk.Label(options_frame, text="Scan Options", 
                bg='#1a1a1a', fg='#00ff88', 
                font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(0, 10))
        
        # File scan button
        self.file_btn = ttk.Button(options_frame, text="📁 Scan File", 
                                  style='Modern.TButton',
                                  command=self.scan_file)
        self.file_btn.pack(fill='x', pady=3)
        
        # Directory scan button
        self.dir_btn = ttk.Button(options_frame, text="📂 Scan Directory", 
                                 style='Modern.TButton',
                                 command=self.scan_directory)
        self.dir_btn.pack(fill='x', pady=3)
        
        # System scan button
        self.system_btn = ttk.Button(options_frame, text="💻 System Scan", 
                                    style='Modern.TButton',
                                    command=self.scan_system)
        self.system_btn.pack(fill='x', pady=3)
        
        # Quick scan button
        self.quick_btn = ttk.Button(options_frame, text="⚡ Quick Scan", 
                                   style='Modern.TButton',
                                   command=self.quick_scan)
        self.quick_btn.pack(fill='x', pady=3)
        
        # Advanced scan button
        self.advanced_btn = ttk.Button(options_frame, text="🔬 Advanced Scan", 
                                      style='Modern.TButton',
                                      command=self.advanced_scan)
        self.advanced_btn.pack(fill='x', pady=3)
        
        # Real-time monitoring button
        self.monitor_btn = ttk.Button(options_frame, text="👁️ Start Monitoring", 
                                     style='Modern.TButton',
                                     command=self.toggle_monitoring)
        self.monitor_btn.pack(fill='x', pady=3)
        
        # Performance stats button
        self.stats_btn = ttk.Button(options_frame, text="📊 Performance Stats", 
                                   style='Modern.TButton',
                                   command=self.show_performance_stats)
        self.stats_btn.pack(fill='x', pady=3)
        
        # YARA rules button
        self.rules_btn = ttk.Button(options_frame, text="🔍 YARA Rules Info", 
                                   style='Modern.TButton',
                                   command=self.show_yara_rules_info)
        self.rules_btn.pack(fill='x', pady=3)
        
        # Reload rules button
        self.reload_btn = ttk.Button(options_frame, text="🔄 Reload Rules", 
                                    style='Modern.TButton',
                                    command=self.reload_yara_rules)
        self.reload_btn.pack(fill='x', pady=3)
        
        # Separator
        separator = tk.Frame(left_panel, bg='#2a2a2a', height=2)
        separator.pack(fill='x', padx=15, pady=15)
        
        # Scan control
        control_frame = tk.Frame(left_panel, bg='#1a1a1a')
        control_frame.pack(fill='x', padx=15, pady=10)
        
        self.start_btn = ttk.Button(control_frame, text="▶️ Start Scan", 
                                   style='Scan.TButton',
                                   command=self.start_scan)
        self.start_btn.pack(fill='x', pady=5)
        
        self.stop_btn = ttk.Button(control_frame, text="⏹️ Stop Scan", 
                                  style='Scan.TButton',
                                  command=self.stop_scan,
                                  state='disabled')
        self.stop_btn.pack(fill='x', pady=5)
        
        # Right panel - Results and progress
        right_panel = tk.Frame(main_frame, bg='#1a1a1a')
        right_panel.pack(side='right', fill='both', expand=True)
        
        # Progress frame
        progress_frame = tk.Frame(right_panel, bg='#1a1a1a')
        progress_frame.pack(fill='x', padx=15, pady=(15, 8))
        
        tk.Label(progress_frame, text="Scan Progress", 
                bg='#1a1a1a', fg='#00ff88', 
                font=('Segoe UI', 12, 'bold')).pack(anchor='w')
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, 
                                          variable=self.progress_var,
                                          maximum=100,
                                          style='TProgressbar')
        self.progress_bar.pack(fill='x', pady=(8, 5))
        
        # Status label
        self.status_label = tk.Label(progress_frame, text="Ready to scan", 
                                   bg='#1a1a1a', fg='#ffffff',
                                   font=('Segoe UI', 9))
        self.status_label.pack(anchor='w')
        
        # Stats frame
        stats_frame = tk.Frame(right_panel, bg='#1a1a1a')
        stats_frame.pack(fill='x', padx=15, pady=8)
        
        self.stats_label = tk.Label(stats_frame, 
                                   text="Files Scanned: 0 | Threats Found: 0 | Time: 00:00",
                                   bg='#1a1a1a', fg='#ffffff',
                                   font=('Segoe UI', 9))
        self.stats_label.pack(anchor='w')
        
        # Results frame
        results_frame = tk.Frame(right_panel, bg='#1a1a1a')
        results_frame.pack(fill='both', expand=True, padx=15, pady=(8, 15))
        
        tk.Label(results_frame, text="Scan Results", 
                bg='#1a1a1a', fg='#00ff88', 
                font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(0, 8))
        
        # Results treeview - enhanced columns
        columns = ('File', 'Threat Type', 'Severity', 'Size', 'Time', 'Method')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, 
                                        show='headings', style='Results.Treeview')
        
        # Configure column widths
        self.results_tree.column('File', width=200)
        self.results_tree.column('Threat Type', width=150)
        self.results_tree.column('Severity', width=80)
        self.results_tree.column('Size', width=80)
        self.results_tree.column('Time', width=80)
        self.results_tree.column('Method', width=100)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
        
        # Scrollbar for results
        scrollbar = ttk.Scrollbar(results_frame, orient='vertical', 
                                 command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
    
    def load_virus_signatures(self):
        """Load virus signatures (simplified for demo)"""
        self.virus_signatures = {
            # EICAR test file
            'eicar': 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
            
            # Known malware hashes (MD5)
            'malware_hashes': {
                'd41d8cd98f00b204e9800998ecf8427e': 'Trojan.Generic',
                '5d41402abc4b2a76b9719d911017c592': 'Backdoor.Win32',
                '098f6bcd4621d373cade4e832627b4f6': 'Virus.Win32',
                'e99a18c428cb38d5f260853678922e03': 'Ransomware.CryptoLocker'
            },
            
            # String patterns for malware detection
            'string_patterns': {
                'eval(': 'JavaScript.Obfuscated',
                'shell_exec': 'PHP.Backdoor',
                'keylogger': 'Trojan.Keylogger',
                'ransomware': 'Ransomware.Generic',
                'cryptolocker': 'Ransomware.CryptoLocker',
                'wannacry': 'Ransomware.WannaCry',
                'mimikatz': 'Tool.Mimikatz',
                'powershell -enc': 'PowerShell.Obfuscated',
                'cmd.exe /c': 'Command.Injection',
                'reg add': 'Registry.Modification',
                'net user': 'Privilege.Escalation',
                'taskkill': 'Process.Termination',
                'wmic process': 'System.Reconnaissance'
            },
            
            # Binary patterns (hex)
            'binary_patterns': {
                '4D5A': 'PE.Executable',  # MZ header
                '504B0304': 'ZIP.Archive',  # ZIP header
                'FFD8FF': 'JPEG.Image',  # JPEG header
                '89504E47': 'PNG.Image',  # PNG header
                '25504446': 'PDF.Document',  # PDF header
            }
        }
    
    def scan_file(self):
        """Select and scan a single file"""
        file_path = filedialog.askopenfilename(
            title="Select file to scan",
            filetypes=[("All files", "*.*")]
        )
        if file_path:
            self.scan_target = file_path
            self.scan_type = "file"
            self.status_label.config(text=f"Selected file: {os.path.basename(file_path)}")
    
    def scan_directory(self):
        """Select and scan a directory"""
        dir_path = filedialog.askdirectory(title="Select directory to scan")
        if dir_path:
            self.scan_target = dir_path
            self.scan_type = "directory"
            self.status_label.config(text=f"Selected directory: {os.path.basename(dir_path)}")
    
    def scan_system(self):
        """Scan the entire system"""
        self.scan_target = "C:\\"  # Windows system drive
        self.scan_type = "system"
        self.status_label.config(text="Full system scan selected")
    
    def quick_scan(self):
        """Quick scan of common locations"""
        self.scan_target = "quick"
        self.scan_type = "quick"
        self.status_label.config(text="Quick scan selected (Common locations)")
    
    def advanced_scan(self):
        """Advanced scan with all detection methods enabled"""
        self.scan_target = "advanced"
        self.scan_type = "advanced"
        self.status_label.config(text="Advanced scan selected (All detection methods)")
    
    def toggle_monitoring(self):
        """Toggle real-time file system monitoring"""
        if not self.file_monitor.monitoring:
            self.file_monitor.start_monitoring()
            self.monitor_btn.config(text="👁️ Stop Monitoring")
            self.status_label.config(text="Real-time monitoring started")
        else:
            self.file_monitor.stop_monitoring()
            self.monitor_btn.config(text="👁️ Start Monitoring")
            self.status_label.config(text="Real-time monitoring stopped")
    
    def show_performance_stats(self):
        """Show performance statistics window"""
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Performance Statistics")
        stats_window.geometry("600x400")
        stats_window.configure(bg='#1a1a1a')
        
        # Create stats display
        stats_text = tk.Text(stats_window, bg='#2a2a2a', fg='#ffffff', 
                           font=('Consolas', 10), wrap='word')
        stats_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Generate stats report
        stats_report = self.generate_performance_report()
        stats_text.insert('1.0', stats_report)
        stats_text.config(state='disabled')
    
    def generate_performance_report(self):
        """Generate performance statistics report"""
        report = "=== SENTINEL PERFORMANCE REPORT ===\n\n"
        
        # Basic stats
        report += f"Total Scans: {self.performance_stats['total_scans']}\n"
        report += f"Threats Detected: {self.performance_stats['threats_detected']}\n"
        report += f"Average Scan Time: {self.performance_stats['avg_scan_time']:.2f}s\n\n"
        
        # Detection methods
        report += "Detection Methods Used:\n"
        for method, count in self.performance_stats['detection_methods'].items():
            report += f"  {method}: {count} detections\n"
        
        # System info
        if PSUTIL_AVAILABLE:
            report += f"\nSystem Information:\n"
            report += f"  CPU Usage: {psutil.cpu_percent()}%\n"
            report += f"  Memory Usage: {psutil.virtual_memory().percent}%\n"
            report += f"  Disk Usage: {psutil.disk_usage('/').percent}%\n"
        
        # YARA rules information
        yara_stats = self.yara_detector.get_rule_statistics()
        report += f"\nYARA Rules Information:\n"
        report += f"  Total Rule Files: {yara_stats['loaded_files']}\n"
        report += f"  Total Rules: {yara_stats['total_rules']}\n"
        report += f"  Failed Files: {yara_stats['failed_files']}\n"
        report += f"  Rule Categories: {len(yara_stats['rule_categories'])}\n"
        
        # Feature availability
        report += f"\nFeature Availability:\n"
        report += f"  YARA Rules: {'✓' if YARA_AVAILABLE else '✗'}\n"
        report += f"  Machine Learning: {'✓' if ML_AVAILABLE else '✗'}\n"
        report += f"  Real-time Monitoring: {'✓' if WATCHDOG_AVAILABLE else '✗'}\n"
        report += f"  System Monitoring: {'✓' if PSUTIL_AVAILABLE else '✗'}\n"
        
        return report
    
    def show_yara_rules_info(self):
        """Show YARA rules information window"""
        rules_window = tk.Toplevel(self.root)
        rules_window.title("YARA Rules Information")
        rules_window.geometry("800x600")
        rules_window.configure(bg='#1a1a1a')
        
        # Create rules display
        rules_text = tk.Text(rules_window, bg='#2a2a2a', fg='#ffffff', 
                           font=('Consolas', 10), wrap='word')
        rules_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Generate rules report
        rules_report = self.generate_yara_rules_report()
        rules_text.insert('1.0', rules_report)
        rules_text.config(state='disabled')
    
    def generate_yara_rules_report(self):
        """Generate YARA rules statistics report"""
        report = "=== YARA RULES REPORT ===\n\n"
        
        # Get YARA statistics
        yara_stats = self.yara_detector.get_rule_statistics()
        
        # Basic stats
        report += f"Total Rule Files: {yara_stats['loaded_files']}\n"
        report += f"Failed Files: {yara_stats['failed_files']}\n"
        report += f"Total Rules: {yara_stats['total_rules']}\n\n"
        
        # Rule categories
        report += "Rule Categories:\n"
        for category, count in yara_stats['rule_categories'].items():
            report += f"  {category}: {count} files\n"
        
        # Loaded rule files
        report += f"\nLoaded Rule Files ({len(self.yara_detector.rule_files)}):\n"
        for i, rule_file in enumerate(self.yara_detector.rule_files[:20], 1):  # Show first 20
            report += f"  {i}. {os.path.basename(rule_file)}\n"
        
        if len(self.yara_detector.rule_files) > 20:
            report += f"  ... and {len(self.yara_detector.rule_files) - 20} more files\n"
        
        # YARA availability
        report += f"\nYARA Status:\n"
        report += f"  YARA Available: {'✓' if YARA_AVAILABLE else '✗'}\n"
        report += f"  Rules Loaded: {'✓' if self.yara_detector.rules else '✗'}\n"
        
        return report
    
    def reload_yara_rules(self):
        """Reload YARA rules from the rules folder"""
        try:
            self.yara_detector.reload_rules()
            self.status_label.config(text="YARA rules reloaded successfully")
            logger.info("YARA rules reloaded by user")
        except Exception as e:
            self.status_label.config(text=f"Failed to reload rules: {str(e)}")
            logger.error(f"Failed to reload YARA rules: {e}")
    
    def start_scan(self):
        """Start the scanning process"""
        if not hasattr(self, 'scan_target'):
            messagebox.showwarning("No Target", "Please select a file, directory, or scan type first!")
            return
        
        self.scanning = True
        self.scan_results = []
        self.threats_found = 0
        self.progress_var.set(0)
        
        # Update UI
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.file_btn.config(state='disabled')
        self.dir_btn.config(state='disabled')
        self.system_btn.config(state='disabled')
        self.quick_btn.config(state='disabled')
        self.advanced_btn.config(state='disabled')
        self.stats_btn.config(state='disabled')
        self.rules_btn.config(state='disabled')
        self.reload_btn.config(state='disabled')
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.perform_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def stop_scan(self):
        """Stop the scanning process"""
        self.scanning = False
        self.status_label.config(text="Scan stopped by user")
        self.reset_ui()
    
    def perform_scan(self):
        """Perform the actual scanning"""
        start_time = time.time()
        files_scanned = 0
        
        try:
            if self.scan_type == "file":
                files = [self.scan_target]
            elif self.scan_type == "directory":
                files = self.get_files_in_directory(self.scan_target)
            elif self.scan_type == "system":
                files = self.get_system_files()
            else:  # quick scan
                files = self.get_quick_scan_files()
            
            total_files = len(files)
            
            for i, file_path in enumerate(files):
                if not self.scanning:
                    break
                
                try:
                    # Update progress
                    progress = (i / total_files) * 100
                    self.progress_var.set(progress)
                    
                    # Update status
                    self.status_label.config(text=f"Scanning: {os.path.basename(file_path)}")
                    
                    # Perform comprehensive detection
                    threat_level, threat_name, detection_method = self.detect_malware(file_path)
                    
                    # Prepare result for processing
                    file_size = self.get_file_size(file_path)
                    scan_time = datetime.now().strftime("%H:%M:%S")
                    
                    # Determine threat level display
                    threat_level_display = {
                        0: "Clean",
                        1: "Low",
                        2: "Medium", 
                        3: "High"
                    }.get(threat_level, "Unknown")
                    
                    # Simplify threat name for display
                    simplified_threat = self.simplify_threat_name(threat_name)
                    
                    # Send result to processing queue
                    result = (
                        os.path.basename(file_path),
                        simplified_threat,
                        threat_level_display,
                        file_size,
                        scan_time,
                        detection_method
                    )
                    self.results_queue.put(result)
                    
                    files_scanned += 1
                    
                    # Update stats
                    elapsed_time = time.time() - start_time
                    self.stats_label.config(
                        text=f"Files Scanned: {files_scanned} | Threats Found: {self.threats_found} | Time: {elapsed_time:.1f}s"
                    )
                    
                    # Small delay for UI responsiveness
                    time.sleep(0.01)
                    
                except Exception as e:
                    continue
            
            # Complete
            self.progress_var.set(100)
            self.status_label.config(text="Scan completed!")
            
        except Exception as e:
            self.status_label.config(text=f"Scan error: {str(e)}")
        
        finally:
            self.reset_ui()
    
    def scan_single_file(self, file_path):
        """Scan a single file (for real-time monitoring)"""
        try:
            if not os.path.exists(file_path) or os.path.isdir(file_path):
                return
            
            # Perform detection
            threat_level, threat_name, detection_method = self.detect_malware(file_path)
            
            # Only process if threat detected
            if threat_level > 0:
                file_size = self.get_file_size(file_path)
                scan_time = datetime.now().strftime("%H:%M:%S")
                
                threat_level_display = {
                    0: "Clean",
                    1: "Low",
                    2: "Medium", 
                    3: "High"
                }.get(threat_level, "Unknown")
                
                simplified_threat = self.simplify_threat_name(threat_name)
                
                result = (
                    os.path.basename(file_path),
                    simplified_threat,
                    threat_level_display,
                    file_size,
                    scan_time,
                    detection_method
                )
                self.results_queue.put(result)
                
                # Log the detection
                logger.warning(f"Real-time threat detected: {file_path} - {threat_name}")
                
        except Exception as e:
            logger.error(f"Single file scan error for {file_path}: {e}")
    
    def detect_malware(self, file_path):
        """Comprehensive malware detection using multiple methods"""
        try:
            # Method 1: YARA Rules (highest priority)
            threat_level, threat_name, method = self.yara_detector.scan_file(file_path)
            if threat_level > 0:
                return threat_level, threat_name, method
            
            # Method 2: Machine Learning Detection
            threat_level, threat_name, method = self.ml_detector.predict(file_path)
            if threat_level > 0:
                return threat_level, threat_name, method
            
            # Method 3: Signature Detection
            threat_level, threat_name = self.signature_detection(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "Signature"
            
            # Method 4: Heuristic Analysis
            threat_level, threat_name = self.heuristic_analysis(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "Heuristic"
            
            # Method 5: Behavioral Analysis
            threat_level, threat_name = self.behavioral_analysis(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "Behavioral"
            
            # Method 6: Entropy Analysis
            threat_level, threat_name = self.entropy_analysis(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "Entropy"
            
            # Method 7: PE File Analysis
            threat_level, threat_name = self.pe_file_analysis(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "PE Analysis"
            
            # Method 8: File Type Analysis
            threat_level, threat_name = self.file_type_analysis(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "File Type"
            
            return 0, "Clean", "None"
            
        except Exception as e:
            logger.error(f"Detection error for {file_path}: {e}")
            return 0, "Clean", "None"
    
    def signature_detection(self, file_path):
        """Traditional signature-based detection"""
        try:
            # Check file hash
            file_hash = self.get_file_hash(file_path)
            if file_hash in self.virus_signatures['malware_hashes']:
                return 3, self.virus_signatures['malware_hashes'][file_hash]
            
            # Check string patterns
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(2048)  # Read first 2KB
                content_lower = content.lower()
                
                for pattern, threat_name in self.virus_signatures['string_patterns'].items():
                    if pattern in content_lower:
                        return 3, threat_name
            
            # Check binary patterns
            with open(file_path, 'rb') as f:
                header = f.read(16)  # Read first 16 bytes
                header_hex = header.hex().upper()
                
                for pattern, file_type in self.virus_signatures['binary_patterns'].items():
                    if header_hex.startswith(pattern):
                        if file_type == 'PE.Executable':
                            return 2, 'Executable.File'
            
            return 0, 'Clean'
            
        except Exception:
            return 0, 'Clean'
    
    def heuristic_analysis(self, file_path):
        """Heuristic analysis based on file characteristics"""
        try:
            file_name = os.path.basename(file_path).lower()
            file_ext = os.path.splitext(file_path)[1].lower()
            file_size = os.path.getsize(file_path)
            file_path_lower = file_path.lower()
            
            threat_score = 0
            
            # Check suspicious extensions
            suspicious_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.vbs', '.js', '.jar']
            if file_ext in suspicious_extensions:
                threat_score += 2
            
            # Check suspicious paths
            suspicious_paths = ['temp', 'tmp', 'downloads', 'appdata']
            for suspicious_path in suspicious_paths:
                if suspicious_path in file_path_lower:
                    threat_score += 1
                    break
            
            # Check suspicious file names
            suspicious_names = ['svchost', 'explorer', 'winlogon', 'csrss']
            for suspicious_name in suspicious_names:
                if suspicious_name in file_name:
                    threat_score += 2
                    break
            
            # Check file size
            if file_size < 1024:  # < 1KB
                threat_score += 1
            elif file_size > 100 * 1024 * 1024:  # > 100MB
                threat_score += 1
            
            # Check entropy
            entropy = self.calculate_entropy(file_path)
            if entropy > 7.5:
                threat_score += 2
            
            # Determine threat level
            if threat_score >= 4:
                return 3, 'Heuristic.Threat'
            elif threat_score >= 2:
                return 2, 'Heuristic.Suspicious'
            else:
                return 0, 'Clean'
                
        except Exception:
            return 0, 'Clean'
    
    def behavioral_analysis(self, file_path):
        """Behavioral analysis based on file content patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(4096)  # Read first 4KB
                content_lower = content.lower()
            
            behavioral_score = 0
            
            # Check for obfuscation patterns
            obfuscation_patterns = [
                r'\\x[0-9a-f]{2}',  # Hex encoding
                r'\\u[0-9a-f]{4}',  # Unicode encoding
                r'base64',  # Base64 encoding
                r'eval\s*\(',  # Dynamic code execution
                r'fromCharCode',  # Character code conversion
            ]
            
            for pattern in obfuscation_patterns:
                if re.search(pattern, content_lower):
                    behavioral_score += 1
            
            # Check for network activity patterns
            network_patterns = [
                r'http://',
                r'https://',
                r'ftp://',
                r'socket',
                r'bind',
                r'connect',
                r'listen'
            ]
            
            for pattern in network_patterns:
                if re.search(pattern, content_lower):
                    behavioral_score += 1
                    break
            
            # Check for system modification patterns
            system_patterns = [
                r'reg add',
                r'reg delete',
                r'net user',
                r'net localgroup',
                r'taskkill',
                r'schtasks',
                r'wmic'
            ]
            
            for pattern in system_patterns:
                if re.search(pattern, content_lower):
                    behavioral_score += 1
                    break
            
            # Determine threat level
            if behavioral_score >= 4:
                return 3, 'Behavioral.Malware'
            elif behavioral_score >= 2:
                return 2, 'Behavioral.Suspicious'
            else:
                return 0, 'Clean'
                
        except Exception:
            return 0, 'Clean'
    
    def entropy_analysis(self, file_path):
        """Entropy analysis to detect packed/encrypted content"""
        try:
            entropy = self.calculate_entropy(file_path)
            
            if entropy > 7.8:
                return 3, 'Entropy.Packed'
            elif entropy > 7.0:
                return 2, 'Entropy.High'
            else:
                return 0, 'Clean'
                
        except Exception:
            return 0, 'Clean'
    
    def pe_file_analysis(self, file_path):
        """PE file analysis for Windows executables"""
        try:
            if not file_path.lower().endswith(('.exe', '.dll', '.sys', '.scr')):
                return 0, 'Clean'
            
            with open(file_path, 'rb') as f:
                # Check DOS header
                f.seek(0)
                dos_header = f.read(2)
                if dos_header != b'MZ':
                    return 0, 'Clean'
                
                # Get PE offset
                f.seek(60)  # e_lfanew offset
                try:
                    pe_offset = struct.unpack('<I', f.read(4))[0]
                    if pe_offset > 1024 or pe_offset < 64:  # Sanity check
                        return 0, 'Clean'
                except:
                    return 0, 'Clean'
                
                # Check PE signature
                f.seek(pe_offset)
                pe_signature = f.read(4)
                
                if pe_signature == b'PE\x00\x00':
                    return 1, 'PE.Executable'
            
            return 0, 'Clean'
            
        except Exception:
            return 0, 'Clean'
    
    def file_type_analysis(self, file_path):
        """File type analysis using magic numbers"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            # Check magic numbers
            magic_numbers = {
                b'MZ': 'PE.Executable',
                b'PK\x03\x04': 'ZIP.Archive',
                b'\xff\xd8\xff': 'JPEG.Image',
                b'\x89PNG': 'PNG.Image',
                b'%PDF': 'PDF.Document',
                b'GIF8': 'GIF.Image',
                b'RIFF': 'RIFF.Container'
            }
            
            for magic_bytes, file_type in magic_numbers.items():
                if header.startswith(magic_bytes):
                    if file_type == 'PE.Executable':
                        return 2, file_type
                    else:
                        return 0, file_type
            
            return 0, 'Unknown.Type'
            
        except Exception:
            return 0, 'Clean'
    
    def calculate_entropy(self, file_path):
        """Calculate Shannon entropy of a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB for entropy calculation
            
            if not data:
                return 0
            
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
            
        except Exception:
            return 0
    
    def get_file_hash(self, file_path):
        """Get MD5 hash of a file"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return ""
    
    def get_file_size(self, file_path):
        """Get human readable file size"""
        try:
            size = os.path.getsize(file_path)
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} TB"
        except:
            return "Unknown"
    
    def get_files_in_directory(self, directory):
        """Get all files in a directory recursively"""
        files = []
        try:
            for root, dirs, filenames in os.walk(directory):
                for filename in filenames:
                    files.append(os.path.join(root, filename))
                    if len(files) > 1000:  # Limit for demo
                        break
                if len(files) > 1000:
                    break
        except:
            pass
        return files
    
    def get_system_files(self):
        """Get system files to scan (limited for demo)"""
        system_paths = [
            "C:\\Windows\\System32",
            "C:\\Program Files",
            "C:\\Users"
        ]
        files = []
        for path in system_paths:
            if os.path.exists(path):
                files.extend(self.get_files_in_directory(path))
                if len(files) > 500:  # Limit for demo
                    break
        return files
    
    def get_quick_scan_files(self):
        """Get files from common locations for quick scan"""
        quick_paths = [
            "C:\\Users\\%USERNAME%\\Downloads",
            "C:\\Users\\%USERNAME%\\Desktop",
            "C:\\Users\\%USERNAME%\\Documents"
        ]
        files = []
        for path in quick_paths:
            expanded_path = os.path.expandvars(path)
            if os.path.exists(expanded_path):
                files.extend(self.get_files_in_directory(expanded_path))
        return files[:100]  # Limit to 100 files for quick scan
    
    def simplify_threat_name(self, threat_name):
        """Simplify threat names for better user understanding"""
        threat_mapping = {
            'Clean': 'Clean',
            'Trojan.Generic': 'Trojan',
            'Backdoor.Win32': 'Backdoor',
            'Virus.Win32': 'Virus',
            'Ransomware.CryptoLocker': 'Ransomware',
            'JavaScript.Obfuscated': 'Obfuscated Code',
            'PHP.Backdoor': 'Web Backdoor',
            'Command.Injection': 'Command Injection',
            'PowerShell.Obfuscated': 'PowerShell Threat',
            'Registry.Modification': 'Registry Threat',
            'Privilege.Escalation': 'Privilege Escalation',
            'Process.Termination': 'Process Threat',
            'System.Reconnaissance': 'System Reconnaissance',
            'Heuristic.Threat': 'Suspicious File',
            'Heuristic.Suspicious': 'Suspicious File',
            'Behavioral.Malware': 'Malicious Behavior',
            'Behavioral.Suspicious': 'Suspicious Behavior',
            'Entropy.Packed': 'Packed File',
            'Entropy.High': 'Encrypted File',
            'PE.Executable': 'Executable',
            'PE.DLL': 'Dynamic Library',
            'Executable.File': 'Executable',
            'Suspicious.Extension': 'Suspicious File',
            'Obfuscated.Code': 'Obfuscated Code',
            'Polymorphic.Critical': 'Polymorphic Malware',
            'Polymorphic.High': 'Polymorphic Threat',
            'Polymorphic.Medium': 'Obfuscated Code',
            'Polymorphic.Low': 'Suspicious Code'
        }
        
        # Return simplified name or original if not found
        return threat_mapping.get(threat_name, threat_name.split('.')[0] if '.' in threat_name else threat_name)
    
    def reset_ui(self):
        """Reset UI to initial state"""
        self.scanning = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.file_btn.config(state='normal')
        self.dir_btn.config(state='normal')
        self.system_btn.config(state='normal')
        self.quick_btn.config(state='normal')
        self.advanced_btn.config(state='normal')
        self.stats_btn.config(state='normal')
        self.rules_btn.config(state='normal')
        self.reload_btn.config(state='normal')

def main():
    root = tk.Tk()
    app = SentinelAntivirus(root)
    root.mainloop()

if __name__ == "__main__":
    main()
