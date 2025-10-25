#!/usr/bin/env python3
"""
Main application file for Sentinel Antivirus
Coordinates all modules and provides the main application logic
"""

import os
import sys
import logging
import threading
import time
import queue
import multiprocessing
from datetime import datetime
from collections import defaultdict

# Import our modules
from detectors import (
    YARADetector, MLDetector, SignatureDetector, 
    HeuristicDetector, EntropyDetector, PEDetector, FileTypeDetector
)
from file_monitor import FileMonitor, BatchFileProcessor, FileSystemScanner
from gui import SentinelGUI, PerformanceStatsWindow, YARARulesWindow

# Optional imports
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

class SentinelAntivirus:
    """Main application class for Sentinel Antivirus"""
    
    def __init__(self):
        self.setup_logging()
        
        # Initialize detectors
        self.yara_detector = YARADetector("rules")
        self.ml_detector = MLDetector()
        self.signature_detector = SignatureDetector()
        self.heuristic_detector = HeuristicDetector()
        self.entropy_detector = EntropyDetector()
        self.pe_detector = PEDetector()
        self.file_type_detector = FileTypeDetector()
        
        # Initialize file monitoring
        self.file_monitor = FileMonitor(self.scan_single_file)
        self.batch_processor = BatchFileProcessor(self.scan_single_file)
        self.file_scanner = FileSystemScanner(self.scan_single_file)
        
        # Application state
        self.scanning = False
        self.monitoring = False
        self.scan_type = "basic"  # basic, advanced
        self.scan_queue = queue.Queue()
        self.results_queue = queue.Queue()
        
        # Scan results
        self.scan_results = []
        self.threats_found = 0
        self.files_scanned = 0
        self.scan_start_time = None
        
        # Statistics
        self.performance_stats = {
            'total_scans': 0,
            'threats_detected': 0,
            'clean_files': 0,
            'scan_errors': 0,
            'start_time': time.time(),
            'last_scan_time': 0,
            'detection_methods': defaultdict(int)
        }
        
        # GUI components (will be set by GUI)
        self.gui = None
        self.performance_window = None
        self.yara_rules_window = None
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('sentinel.log'),
                logging.StreamHandler()
            ]
        )
        global logger
        logger = logging.getLogger(__name__)
    
    def set_gui(self, gui):
        """Set the GUI reference"""
        self.gui = gui
        self.performance_window = PerformanceStatsWindow(gui.root, self)
        self.yara_rules_window = YARARulesWindow(gui.root, self)
    
    def detect_malware(self, file_path):
        """Main detection pipeline"""
        if not os.path.exists(file_path):
            return 0, "Clean", "None"
        
        start_time = time.time()
        
        try:
            # Detection pipeline (in order of priority)
            detectors = [
                ("YARA", self.yara_detector.scan_file),
                ("ML", lambda path: self.ml_detector.predict(path)),
                ("Signature", self.signature_detector.scan_file),
                ("Heuristic", self.heuristic_detector.scan_file),
                ("Entropy", self.entropy_detector.scan_file),
                ("PE", self.pe_detector.scan_file),
                ("FileType", self.file_type_detector.scan_file)
            ]
            
            # Run detection pipeline
            for detector_name, detector_func in detectors:
                try:
                    threat_level, threat_name, method = detector_func(file_path)
                    if threat_level > 0:
                        scan_time = time.time() - start_time
                        logger.info(f"Threat detected by {detector_name}: {threat_name} (Level {threat_level})")
                        return threat_level, threat_name, method
                except Exception as e:
                    logger.error(f"Detection error in {detector_name} for {file_path}: {e}")
                    continue
            
            # No threat detected
            scan_time = time.time() - start_time
            return 0, "Clean", "None"
            
        except Exception as e:
            logger.error(f"Detection error for {file_path}: {e}")
            self.performance_stats['scan_errors'] += 1
            return 0, "Clean", "None"
    
    def scan_single_file(self, file_path):
        """Scan a single file and add result to queue"""
        try:
            if not os.path.exists(file_path):
                return
            
            start_time = time.time()
            file_size = os.path.getsize(file_path)
            threat_level, threat_name, method = self.detect_malware(file_path)
            scan_time = time.time() - start_time
            
            # Update statistics
            self.performance_stats['total_scans'] += 1
            self.files_scanned += 1
            if threat_level > 0:
                self.performance_stats['threats_detected'] += 1
                self.threats_found += 1
            else:
                self.performance_stats['clean_files'] += 1
            
            # Format result for GUI - ensure proper display
            file_name = os.path.basename(file_path)
            threat_type = threat_name if threat_name != "Clean" else "Clean"
            severity = self.get_threat_level_name(threat_level)
            size_str = f"{file_size / 1024:.1f} KB"
            time_str = datetime.now().strftime("%H:%M:%S")
            
            # Add result to GUI queue - this ensures results are visible
            if self.gui:
                self.gui.add_result(file_name, threat_type, severity, size_str, time_str, method)
                logger.info(f"Added result to GUI: {file_name} - {threat_type} ({severity})")
            
        except Exception as e:
            logger.error(f"Single file scan error for {file_path}: {e}")
            self.performance_stats['scan_errors'] += 1
    
    def get_threat_level_name(self, threat_level):
        """Convert threat level number to name"""
        if threat_level >= 3:
            return "High"
        elif threat_level >= 2:
            return "Medium"
        elif threat_level >= 1:
            return "Low"
        else:
            return "Clean"
    
    def scan_file(self, file_path):
        """Scan a single file"""
        if self.scanning:
            logger.warning("Scan already in progress")
            if self.gui:
                self.gui.update_status("⚠️ Scan already in progress")
            return
        
        self.scanning = True
        self.scan_start_time = time.time()
        
        if self.gui:
            self.gui.update_status(f"🔍 Scanning: {os.path.basename(file_path)}")
            self.gui.update_progress(0)
        
        try:
            # Clear previous results for single file scan
            if self.gui:
                self.gui.clear_results()
            
            self.scan_single_file(file_path)
            
            if self.gui:
                self.gui.update_progress(100)
                self.gui.update_status("✅ File scan completed")
                logger.info(f"File scan completed: {file_path}")
        except Exception as e:
            logger.error(f"File scan error: {e}")
            if self.gui:
                self.gui.update_status(f"❌ Scan error: {e}")
        finally:
            self.scanning = False
            if self.gui:
                self.gui.update_status("Ready to scan")
    
    def scan_directory(self, folder_path):
        """Scan a folder recursively"""
        if self.scanning:
            logger.warning("Scan already in progress")
            if self.gui:
                self.gui.update_status("⚠️ Scan already in progress")
            return
        
        self.scanning = True
        self.scan_start_time = time.time()
        
        if self.gui:
            self.gui.update_status(f"📂 Scanning folder: {os.path.basename(folder_path)}")
            self.gui.update_progress(0)
        
        try:
            # Count files first for progress tracking
            file_count = 0
            for root, dirs, files in os.walk(folder_path):
                file_count += len(files)
            
            if self.gui:
                self.gui.update_status(f"📂 Found {file_count} files to scan")
            
            # Clear previous results for directory scan
            if self.gui:
                self.gui.clear_results()
            
            # Scan files directly instead of using file scanner
            scanned_count = 0
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if not self.scanning:  # Check if scan was stopped
                        break
                    file_path = os.path.join(root, file)
                    try:
                        self.scan_single_file(file_path)
                        scanned_count += 1
                        
                        # Update progress
                        if file_count > 0:
                            progress = (scanned_count / file_count) * 100
                            if self.gui:
                                self.gui.update_progress(progress)
                                self.gui.update_status(f"📂 Scanning: {file} ({scanned_count}/{file_count})")
                    except Exception as e:
                        logger.error(f"Error scanning {file_path}: {e}")
                
                if not self.scanning:  # Check if scan was stopped
                    break
            
            if self.gui:
                self.gui.update_progress(100)
                self.gui.update_status("✅ Folder scan completed")
                logger.info(f"Directory scan completed: {folder_path}")
        except Exception as e:
            logger.error(f"Directory scan error: {e}")
            if self.gui:
                self.gui.update_status(f"❌ Scan error: {e}")
        finally:
            self.scanning = False
            if self.gui:
                self.gui.update_status("Ready to scan")
    
    def scan_system(self):
        """Start system scan"""
        if self.scanning:
            logger.warning("Scan already in progress")
            if self.gui:
                self.gui.update_status("⚠️ Scan already in progress")
            return
        
        self.scanning = True
        self.scan_start_time = time.time()
        
        if self.gui:
            self.gui.update_status("💻 Starting system scan...")
            self.gui.update_progress(0)
        
        try:
            # Scan common system directories
            system_paths = [
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents")
            ]
            
            total_files = 0
            for path in system_paths:
                if os.path.exists(path):
                    for root, dirs, files in os.walk(path):
                        total_files += len(files)
            
            if self.gui:
                self.gui.update_status(f"💻 System scan: {total_files} files found")
                # Clear previous results for system scan
                self.gui.clear_results()
            
            scanned_count = 0
            for i, path in enumerate(system_paths):
                if os.path.exists(path) and self.scanning:
                    if self.gui:
                        progress = ((i + 1) / len(system_paths)) * 100
                        self.gui.update_progress(progress)
                        self.gui.update_status(f"💻 Scanning: {os.path.basename(path)}")
                    
                    # Scan files directly
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            if not self.scanning:
                                break
                            file_path = os.path.join(root, file)
                            try:
                                self.scan_single_file(file_path)
                                scanned_count += 1
                            except Exception as e:
                                logger.error(f"Error scanning {file_path}: {e}")
                        
                        if not self.scanning:
                            break
            
            if self.gui:
                self.gui.update_progress(100)
                self.gui.update_status("✅ System scan completed")
                logger.info("System scan completed")
        except Exception as e:
            logger.error(f"System scan error: {e}")
            if self.gui:
                self.gui.update_status(f"❌ Scan error: {e}")
        finally:
            self.scanning = False
            if self.gui:
                self.gui.update_status("Ready to scan")
    
    def quick_scan(self):
        """Start quick scan"""
        if self.scanning:
            logger.warning("Scan already in progress")
            if self.gui:
                self.gui.update_status("⚠️ Scan already in progress")
            return
        
        self.scanning = True
        self.scan_start_time = time.time()
        
        if self.gui:
            self.gui.update_status("⚡ Starting quick scan...")
            self.gui.update_progress(0)
        
        try:
            # Quick scan of Downloads folder only
            downloads_path = os.path.expanduser("~/Downloads")
            if os.path.exists(downloads_path):
                # Count files for progress
                file_count = len([f for f in os.listdir(downloads_path) 
                                if os.path.isfile(os.path.join(downloads_path, f))])
                
                if self.gui:
                    self.gui.update_status(f"⚡ Quick scan: {file_count} files in Downloads")
                    # Clear previous results for quick scan
                    self.gui.clear_results()
                
                # Scan files directly
                for file in os.listdir(downloads_path):
                    if not self.scanning:
                        break
                    file_path = os.path.join(downloads_path, file)
                    if os.path.isfile(file_path):
                        try:
                            self.scan_single_file(file_path)
                        except Exception as e:
                            logger.error(f"Error scanning {file_path}: {e}")
                
                if self.gui:
                    self.gui.update_progress(100)
                    self.gui.update_status("✅ Quick scan completed")
                    logger.info("Quick scan completed")
            else:
                if self.gui:
                    self.gui.update_status("❌ Downloads folder not found")
        except Exception as e:
            logger.error(f"Quick scan error: {e}")
            if self.gui:
                self.gui.update_status(f"❌ Scan error: {e}")
        finally:
            self.scanning = False
            if self.gui:
                self.gui.update_status("Ready to scan")
    
    def start_scan(self):
        """Start scan process"""
        if self.scanning:
            logger.warning("Scan already in progress")
            if self.gui:
                self.gui.update_status("⚠️ Scan already in progress")
            return
        
        self.scanning = True
        self.scan_start_time = time.time()
        
        if self.gui:
            self.gui.enable_scan_buttons(False)
            self.gui.update_status("🚀 Scan started - Ready for scanning")
            self.gui.update_progress(0)
        logger.info("Scan started")
    
    def stop_scan(self):
        """Stop scan process"""
        self.scanning = False
        
        if self.gui:
            self.gui.enable_scan_buttons(True)
            self.gui.update_status("⏹️ Scan stopped")
            self.gui.update_progress(0)
        logger.info("Scan stopped")
    
    def advanced_scan(self):
        """Start advanced scan mode"""
        self.scan_type = "advanced"
        if self.gui:
            self.gui.update_status("🔬 Advanced scan mode enabled")
        logger.info("Advanced scan mode enabled")
    
    def toggle_monitoring(self):
        """Toggle file system monitoring"""
        if self.monitoring:
            # Stop monitoring
            self.file_monitor.stop_monitoring()
            self.batch_processor.stop_processing()
            self.monitoring = False
            if self.gui:
                self.gui.update_status("👁️ Monitoring stopped")
            logger.info("File monitoring stopped")
        else:
            # Start monitoring
            # Get common monitoring paths
            monitor_paths = [
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents")
            ]
            
            # Start monitoring
            for path in monitor_paths:
                if os.path.exists(path):
                    self.file_monitor.start_monitoring(path, recursive=True)
                    self.batch_processor.start_processing()
                    break
            
            self.monitoring = True
            if self.gui:
                self.gui.update_status("👁️ Real-time monitoring active")
            logger.info("File monitoring started")
    
    def show_performance_stats(self):
        """Show performance statistics window"""
        if self.performance_window:
            self.performance_window.show()
    
    def show_yara_rules_info(self):
        """Show YARA rules information window"""
        if self.yara_rules_window:
            self.yara_rules_window.show()
    
    def reload_yara_rules(self):
        """Reload YARA rules"""
        if self.gui:
            self.gui.update_status("🔄 Reloading YARA rules...")
        
        self.yara_detector.load_rules()
        
        if self.gui:
            stats = self.yara_detector.get_rule_statistics()
            self.gui.update_status(f"✅ YARA rules reloaded: {stats['loaded_rules']} rules active")
        logger.info("YARA rules reloaded")
    
    def reset_ui(self):
        """Reset UI state"""
        self.scanning = False
        self.scan_type = "basic"
        
        if self.gui:
            self.gui.reset_ui()
            self.gui.update_status("🔄 UI reset - Ready for new scan")
        logger.info("UI reset")
    
    def generate_performance_report(self):
        """Generate performance report"""
        uptime = time.time() - self.performance_stats['start_time']
        
        report = f"""Sentinel Antivirus - Performance Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

=== Scan Statistics ===
Total Files Scanned: {self.performance_stats['total_scans']}
Threats Detected: {self.performance_stats['threats_detected']}
Clean Files: {self.performance_stats['clean_files']}
Scan Errors: {self.
        performance_stats['scan_errors']}

=== Detection Methods ===
YARA Rules: {'Available' if self.yara_detector.rules else 'Not Available'}
ML Detection: {'Available' if self.ml_detector.model else 'Not Available'}
Signature Detection: Available
Heuristic Detection: Available
Entropy Analysis: Available
PE Analysis: Available
File Type Analysis: Available

=== YARA Rules Statistics ===
{self.get_yara_rules_info()}

=== System Information ===
{self.get_system_info()}

=== Performance Metrics ===
Uptime: {uptime:.2f} seconds
Average Scan Rate: {self.performance_stats['total_scans'] / max(uptime, 1):.2f} files/second
Threat Detection Rate: {(self.performance_stats['threats_detected'] / max(self.performance_stats['total_scans'], 1)) * 100:.2f}%

=== File Monitoring ===
Monitoring Active: {'Yes' if self.monitoring else 'No'}
Monitor Stats: {self.file_monitor.get_stats() if self.monitoring else 'N/A'}
"""
        return report
    
    def get_yara_rules_info(self):
        """Get YARA rules information"""
        stats = self.yara_detector.get_rule_statistics()
        
        info = f"""Total Rule Files: {stats['total_rules']}
Loaded Rules: {stats['loaded_rules']}
Rule Categories: {dict(stats['rule_categories'])}

YARA Status: {'Active' if self.yara_detector.rules else 'Inactive'}
"""
        return info
    
    def get_system_info(self):
        """Get system information"""
        try:
            if PSUTIL_AVAILABLE:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                info = f"""CPU Usage: {cpu_percent}%
Memory Usage: {memory.percent}% ({memory.used / (1024**3):.1f} GB / {memory.total / (1024**3):.1f} GB)
Disk Usage: {disk.percent}% ({disk.used / (1024**3):.1f} GB / {disk.total / (1024**3):.1f} GB)
"""
            else:
                info = "System information not available (psutil not installed)"
        except Exception as e:
            info = f"Error getting system info: {e}"
        
        return info

def main():
    """Main application entry point"""
    try:
        # Create main window
        root = tk.Tk()
        
        # Create antivirus application
        antivirus_app = SentinelAntivirus()
        
        # Create clean GUI
        gui = SentinelGUI(root, antivirus_app)
        antivirus_app.set_gui(gui)
        
        # Initialize GUI components
        gui.update_status("Ready to scan")
        
        # Start the application
        logger.info("Starting Sentinel Antivirus with Clean GUI...")
        logger.info("Features: Clean design, Real-time results, Professional layout")
        
        # Show welcome message
        gui.update_status("🛡️ Sentinel Ready - Advanced Threat Protection Active")
        
        root.mainloop()
        
    except Exception as e:
        logger.error(f"Application error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Import tkinter here to avoid issues in headless environments
    import tkinter as tk
    main()

