#!/usr/bin/env python3
"""
File system monitoring module for Sentinel Antivirus
Handles real-time file system monitoring using watchdog
"""

import os
import logging
import threading
import time

# Optional imports with fallbacks
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    # Create dummy classes if watchdog is not available
    class FileSystemEventHandler:
        def on_created(self, event):
            pass
        def on_modified(self, event):
            pass
        def on_deleted(self, event):
            pass
        def on_moved(self, event):
            pass
    
    class Observer:
        def __init__(self):
            self.is_alive = False
        def schedule(self, handler, path, recursive=False):
            pass
        def start(self):
            self.is_alive = True
        def stop(self):
            self.is_alive = False
        def join(self):
            pass

logger = logging.getLogger(__name__)

class FileMonitor(FileSystemEventHandler):
    """Real-time file system monitor"""
    
    def __init__(self, scan_callback=None):
        self.scan_callback = scan_callback
        self.observer = None
        self.monitoring = False
        self.monitored_paths = set()
        
        # Statistics
        self.stats = {
            'files_created': 0,
            'files_modified': 0,
            'files_deleted': 0,
            'files_moved': 0,
            'scan_errors': 0,
            'start_time': None
        }
    
    def start_monitoring(self, paths, recursive=True):
        """Start monitoring specified paths"""
        if not WATCHDOG_AVAILABLE:
            logger.warning("Watchdog not available - file monitoring disabled")
            return False
        
        try:
            if self.observer and self.observer.is_alive:
                logger.warning("File monitoring already active")
                return True
            
            self.observer = Observer()
            self.observer.schedule(self, path=paths, recursive=recursive)
            self.observer.start()
            
            self.monitoring = True
            self.monitored_paths.add(paths)
            self.stats['start_time'] = time.time()
            
            logger.info(f"Started monitoring: {paths}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start file monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop file monitoring"""
        try:
            if self.observer and self.observer.is_alive:
                self.observer.stop()
                self.observer.join()
            
            self.monitoring = False
            self.monitored_paths.clear()
            
            logger.info("Stopped file monitoring")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop file monitoring: {e}")
            return False
    
    def on_created(self, event):
        """Handle file creation events"""
        if event.is_directory:
            return
        
        self.stats['files_created'] += 1
        logger.debug(f"File created: {event.src_path}")
        
        if self.scan_callback:
            try:
                self.scan_callback(event.src_path)
            except Exception as e:
                logger.error(f"Scan callback error for {event.src_path}: {e}")
                self.stats['scan_errors'] += 1
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
        
        self.stats['files_modified'] += 1
        logger.debug(f"File modified: {event.src_path}")
        
        if self.scan_callback:
            try:
                self.scan_callback(event.src_path)
            except Exception as e:
                logger.error(f"Scan callback error for {event.src_path}: {e}")
                self.stats['scan_errors'] += 1
    
    def on_deleted(self, event):
        """Handle file deletion events"""
        if event.is_directory:
            return
        
        self.stats['files_deleted'] += 1
        logger.debug(f"File deleted: {event.src_path}")
    
    def on_moved(self, event):
        """Handle file move events"""
        if event.is_directory:
            return
        
        self.stats['files_moved'] += 1
        logger.debug(f"File moved: {event.src_path} -> {event.dest_path}")
        
        if self.scan_callback:
            try:
                self.scan_callback(event.dest_path)
            except Exception as e:
                logger.error(f"Scan callback error for {event.dest_path}: {e}")
                self.stats['scan_errors'] += 1
    
    def is_monitoring(self):
        """Check if monitoring is active"""
        return self.monitoring and self.observer and self.observer.is_alive
    
    def get_stats(self):
        """Get monitoring statistics"""
        stats = self.stats.copy()
        if self.stats['start_time']:
            stats['uptime'] = time.time() - self.stats['start_time']
        else:
            stats['uptime'] = 0
        return stats
    
    def reset_stats(self):
        """Reset monitoring statistics"""
        self.stats = {
            'files_created': 0,
            'files_modified': 0,
            'files_deleted': 0,
            'files_moved': 0,
            'scan_errors': 0,
            'start_time': time.time() if self.monitoring else None
        }

class BatchFileProcessor:
    """Process multiple files in batches for performance"""
    
    def __init__(self, scan_callback, batch_size=10, delay=1.0):
        self.scan_callback = scan_callback
        self.batch_size = batch_size
        self.delay = delay
        self.file_queue = []
        self.processing = False
        self.thread = None
        
        # Statistics
        self.stats = {
            'files_processed': 0,
            'batches_processed': 0,
            'processing_errors': 0,
            'start_time': None
        }
    
    def add_file(self, file_path):
        """Add file to processing queue"""
        if file_path not in self.file_queue:
            self.file_queue.append(file_path)
            logger.debug(f"Added to queue: {file_path}")
    
    def start_processing(self):
        """Start batch processing thread"""
        if self.processing:
            return
        
        self.processing = True
        self.stats['start_time'] = time.time()
        self.thread = threading.Thread(target=self._process_loop, daemon=True)
        self.thread.start()
        logger.info("Started batch file processing")
    
    def stop_processing(self):
        """Stop batch processing"""
        self.processing = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Stopped batch file processing")
    
    def _process_loop(self):
        """Main processing loop"""
        while self.processing:
            if self.file_queue:
                # Process batch
                batch = self.file_queue[:self.batch_size]
                self.file_queue = self.file_queue[self.batch_size:]
                
                for file_path in batch:
                    try:
                        if os.path.exists(file_path):
                            self.scan_callback(file_path)
                            self.stats['files_processed'] += 1
                    except Exception as e:
                        logger.error(f"Batch processing error for {file_path}: {e}")
                        self.stats['processing_errors'] += 1
                
                self.stats['batches_processed'] += 1
                logger.debug(f"Processed batch of {len(batch)} files")
            
            time.sleep(self.delay)
    
    def get_stats(self):
        """Get processing statistics"""
        stats = self.stats.copy()
        if self.stats['start_time']:
            stats['uptime'] = time.time() - self.stats['start_time']
        else:
            stats['uptime'] = 0
        stats['queue_size'] = len(self.file_queue)
        return stats
    
    def clear_queue(self):
        """Clear the processing queue"""
        self.file_queue.clear()
        logger.info("Cleared processing queue")

class FileSystemScanner:
    """Scan files and directories recursively"""
    
    def __init__(self, scan_callback, file_extensions=None, exclude_dirs=None):
        self.scan_callback = scan_callback
        self.file_extensions = file_extensions or ['.exe', '.dll', '.sys', '.scr', '.pif', '.bat', '.cmd', '.com']
        self.exclude_dirs = exclude_dirs or ['$Recycle.Bin', 'System Volume Information', 'Windows', 'Program Files']
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'directories_scanned': 0,
            'scan_errors': 0,
            'threats_found': 0,
            'start_time': None
        }
    
    def scan_directory(self, directory_path, recursive=True):
        """Scan directory for files"""
        if not os.path.exists(directory_path):
            logger.error(f"Directory does not exist: {directory_path}")
            return
        
        self.stats['start_time'] = time.time()
        logger.info(f"Starting directory scan: {directory_path}")
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    # Filter out excluded directories
                    dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
                    
                    self.stats['directories_scanned'] += 1
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        self._scan_file(file_path)
            else:
                # Non-recursive scan
                self.stats['directories_scanned'] = 1
                for item in os.listdir(directory_path):
                    item_path = os.path.join(directory_path, item)
                    if os.path.isfile(item_path):
                        self._scan_file(item_path)
        
        except Exception as e:
            logger.error(f"Directory scan error: {e}")
            self.stats['scan_errors'] += 1
        
        logger.info(f"Directory scan completed: {self.stats['files_scanned']} files scanned")
    
    def _scan_file(self, file_path):
        """Scan individual file"""
        try:
            # Check file extension
            if self.file_extensions:
                file_ext = os.path.splitext(file_path)[1].lower()
                if file_ext not in self.file_extensions:
                    return
            
            # Call scan callback
            result = self.scan_callback(file_path)
            self.stats['files_scanned'] += 1
            
            # Count threats
            if result and len(result) >= 2 and result[1] != "Clean":
                self.stats['threats_found'] += 1
            
        except Exception as e:
            logger.error(f"File scan error for {file_path}: {e}")
            self.stats['scan_errors'] += 1
    
    def get_stats(self):
        """Get scanning statistics"""
        stats = self.stats.copy()
        if self.stats['start_time']:
            stats['scan_duration'] = time.time() - self.stats['start_time']
        else:
            stats['scan_duration'] = 0
        return stats
    
    def reset_stats(self):
        """Reset scanning statistics"""
        self.stats = {
            'files_scanned': 0,
            'directories_scanned': 0,
            'scan_errors': 0,
            'threats_found': 0,
            'start_time': None
        }


