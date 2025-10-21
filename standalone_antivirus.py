"""
Sentinel - Advanced Threat Protection System
A timeless watchman guarding your digital realm
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import hashlib
import threading
import time
import re
import struct
from pathlib import Path
from datetime import datetime

class SentinelAntivirus:
    def __init__(self, root):
        self.root = root
        self.root.title("Sentinel - Advanced Threat Protection")
        self.root.geometry("900x600")
        self.root.configure(bg='#0a0a0a')
        
        # Configure style
        self.setup_styles()
        
        # Initialize variables
        self.scanning = False
        self.scan_results = []
        self.threats_found = 0
        
        # Create GUI
        self.create_gui()
        
        # Load virus signatures
        self.load_virus_signatures()
    
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
        
        # Results treeview - simplified columns
        columns = ('File', 'Threat Type', 'Severity', 'Size', 'Time')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, 
                                        show='headings', style='Results.Treeview')
        
        # Configure column widths
        self.results_tree.column('File', width=250)
        self.results_tree.column('Threat Type', width=150)
        self.results_tree.column('Severity', width=80)
        self.results_tree.column('Size', width=80)
        self.results_tree.column('Time', width=80)
        
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
                    
                    # Add to results
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
                    
                    self.results_tree.insert('', 'end', values=(
                        os.path.basename(file_path),
                        simplified_threat,
                        threat_level_display,
                        file_size,
                        scan_time
                    ))
                    
                    if threat_level > 0:
                        self.threats_found += 1
                    
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
    
    def detect_malware(self, file_path):
        """Comprehensive malware detection using multiple methods"""
        try:
            # Method 1: Signature Detection
            threat_level, threat_name = self.signature_detection(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "Signature"
            
            # Method 2: Heuristic Analysis
            threat_level, threat_name = self.heuristic_analysis(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "Heuristic"
            
            # Method 3: Behavioral Analysis
            threat_level, threat_name = self.behavioral_analysis(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "Behavioral"
            
            # Method 4: Entropy Analysis
            threat_level, threat_name = self.entropy_analysis(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "Entropy"
            
            # Method 5: PE File Analysis
            threat_level, threat_name = self.pe_file_analysis(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "PE Analysis"
            
            # Method 6: File Type Analysis
            threat_level, threat_name = self.file_type_analysis(file_path)
            if threat_level > 0:
                return threat_level, threat_name, "File Type"
            
            return 0, "Clean", "None"
            
        except Exception:
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

def main():
    root = tk.Tk()
    app = SentinelAntivirus(root)
    root.mainloop()

if __name__ == "__main__":
    main()
