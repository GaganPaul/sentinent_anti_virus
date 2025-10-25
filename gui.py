#!/usr/bin/env python3
"""
Redesigned GUI module for Sentinel Antivirus
Matching the clean, professional design from the image
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import queue
import os
import time
from datetime import datetime
import webbrowser

logger = None  # Will be set by main application

class SentinelGUI:
    """Redesigned GUI class matching the clean design"""
    
    def __init__(self, root, antivirus_app):
        self.root = root
        self.antivirus_app = antivirus_app
        
        # Configure root window
        self.root.title("Sentinel")
        self.root.geometry("1200x800")
        self.root.configure(bg='#0a0a0a')
        self.root.minsize(1000, 700)
        
        # Configure style
        self.setup_clean_styles()
        
        # Initialize variables
        self.scanning = False
        self.monitoring = False
        self.scan_results = []
        self.threats_found = 0
        self.files_scanned = 0
        self.scan_start_time = None
        
        # Create GUI
        self.create_clean_gui()
        
        # Threading
        self.result_queue = queue.Queue()
        self.start_result_processor()
        
        # Start status update timer
        self.update_status_timer()
    
    def setup_clean_styles(self):
        """Configure clean, professional styling"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Clean color scheme
        colors = {
            'bg_dark': '#0a0a0a',
            'bg_panel': '#1a1a1a',
            'bg_accent': '#2a2a2a',
            'cyber_green': '#00ff88',
            'cyber_red': '#ff4444',
            'text_primary': '#ffffff',
            'text_secondary': '#cccccc',
            'text_muted': '#888888',
            'border': '#333333'
        }
        
        # Title styles
        style.configure('CleanTitle.TLabel',
                       background=colors['bg_dark'],
                       foreground=colors['cyber_green'],
                       font=('Segoe UI', 24, 'bold'))
        
        style.configure('CleanSubtitle.TLabel',
                       background=colors['bg_dark'],
                       foreground=colors['text_primary'],
                       font=('Segoe UI', 12))
        
        style.configure('CleanTagline.TLabel',
                       background=colors['bg_dark'],
                       foreground=colors['text_muted'],
                       font=('Segoe UI', 10, 'italic'))
        
        # Button styles
        style.configure('CleanPrimary.TButton',
                       background=colors['cyber_green'],
                       foreground=colors['bg_dark'],
                       font=('Segoe UI', 10, 'bold'),
                       borderwidth=0,
                       focuscolor='none',
                       padding=(10, 8))
        
        style.map('CleanPrimary.TButton',
                 background=[('active', '#00cc6a'),
                           ('pressed', '#00aa55')])
        
        style.configure('CleanDanger.TButton',
                       background=colors['cyber_red'],
                       foreground=colors['text_primary'],
                       font=('Segoe UI', 10, 'bold'),
                       borderwidth=0,
                       focuscolor='none',
                       padding=(10, 8))
        
        style.map('CleanDanger.TButton',
                 background=[('active', '#cc3333'),
                           ('pressed', '#aa2222')])
        
        # Panel styles
        style.configure('CleanPanel.TFrame',
                        background=colors['bg_panel'],
                        relief='flat',
                        borderwidth=1)
        
        # Treeview styles
        style.configure('CleanTreeview.Treeview',
                       background=colors['bg_panel'],
                       foreground=colors['text_primary'],
                       fieldbackground=colors['bg_panel'],
                       font=('Consolas', 9),
                       rowheight=22)
        
        style.configure('CleanTreeview.Treeview.Heading',
                       background=colors['bg_accent'],
                       foreground=colors['cyber_green'],
                       font=('Segoe UI', 10, 'bold'),
                       relief='flat')
        
        # Progress bar style
        style.configure('CleanProgress.TProgressbar',
                       background=colors['cyber_green'],
                       troughcolor=colors['bg_accent'],
                       borderwidth=0)
        
        # Label styles
        style.configure('CleanLabel.TLabel',
                       background=colors['bg_panel'],
                       foreground=colors['text_primary'],
                       font=('Segoe UI', 9))
        
        style.configure('CleanLabelSecondary.TLabel',
                       background=colors['bg_panel'],
                       foreground=colors['text_secondary'],
                       font=('Segoe UI', 8))
    
    def create_clean_gui(self):
        """Create the clean, professional GUI"""
        # Main container
        main_container = tk.Frame(self.root, bg='#0a0a0a')
        main_container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Header section
        self.create_header(main_container)
        
        # Main content area
        content_frame = tk.Frame(main_container, bg='#0a0a0a')
        content_frame.pack(fill='both', expand=True, pady=(20, 0))
        
        # Left panel - Scan Options
        self.create_left_panel(content_frame)
        
        # Right panel - Scan Progress and Results
        self.create_right_panel(content_frame)
    
    def create_header(self, parent):
        """Create the header section"""
        header_frame = tk.Frame(parent, bg='#0a0a0a', height=120)
        header_frame.pack(fill='x', pady=(0, 20))
        header_frame.pack_propagate(False)
        
        # Logo and title container
        logo_frame = tk.Frame(header_frame, bg='#0a0a0a')
        logo_frame.pack(expand=True, fill='both')
        
        # Logo (stylized S) - larger and more prominent
        self.logo_label = tk.Label(logo_frame, text="S", 
                                  bg='#0a0a0a', fg='#00ff88', 
                                  font=('Segoe UI', 72, 'bold'))
        self.logo_label.pack(pady=(10, 0))
        
        # Title - "Sentinel" text
        self.title_label = tk.Label(logo_frame, text="Sentinel", 
                                   bg='#0a0a0a', fg='#00ff88', 
                                   font=('Segoe UI', 28, 'bold'))
        self.title_label.pack(pady=(5, 0))
        
        # Tagline
        self.tagline_label = tk.Label(logo_frame, text="A timeless watchman guarding your digital realm", 
                                     bg='#0a0a0a', fg='#cccccc', 
                                     font=('Segoe UI', 12, 'italic'))
        self.tagline_label.pack(pady=(5, 10))
    
    def create_left_panel(self, parent):
        """Create the left panel with scan options"""
        left_frame = tk.Frame(parent, bg='#1a1a1a', width=300)
        left_frame.pack(side='left', fill='y', padx=(0, 20))
        left_frame.pack_propagate(False)
        
        # Scan Options title
        options_title = tk.Label(left_frame, text="Scan Options", 
                               bg='#1a1a1a', fg='#00ff88', 
                               font=('Segoe UI', 14, 'bold'))
        options_title.pack(pady=(20, 15), padx=20, anchor='w')
        
        # Scan option buttons
        scan_options = [
            ("📄", "Scan File", self.scan_file),
            ("📁", "Scan Directory", self.scan_directory),
            ("💻", "System Scan", self.scan_system),
            ("⚡", "Quick Scan", self.quick_scan),
            ("🔍", "Advanced Scan", self.advanced_scan),
            ("👁️", "Start Monitoring", self.toggle_monitoring),
            ("📊", "Performance Stats", self.show_performance_stats),
            ("🔍", "YARA Rules Info", self.show_yara_rules_info),
            ("🔄", "Reload Rules", self.reload_yara_rules)
        ]
        
        for icon, text, command in scan_options:
            btn = tk.Button(left_frame, text=f"{icon} {text}", 
                           bg='#00ff88', fg='#000000',
                           font=('Segoe UI', 10, 'bold'),
                           command=command,
                           relief='flat',
                           padx=10, pady=8)
            btn.pack(fill='x', padx=20, pady=3)
        
        # Action buttons
        action_frame = tk.Frame(left_frame, bg='#1a1a1a')
        action_frame.pack(fill='x', padx=20, pady=(20, 0))
        
        self.start_scan_btn = tk.Button(action_frame, text="▶️ Start Scan", 
                                       bg='#ff4444', fg='#ffffff',
                                       font=('Segoe UI', 10, 'bold'),
                                       command=self.start_scan,
                                       relief='flat',
                                       padx=10, pady=8)
        self.start_scan_btn.pack(fill='x', pady=3)
        
        self.stop_scan_btn = tk.Button(action_frame, text="⏹️ Stop Scan", 
                                      bg='#ff4444', fg='#ffffff',
                                      font=('Segoe UI', 10, 'bold'),
                                      command=self.stop_scan,
                                      relief='flat',
                                      padx=10, pady=8,
                                      state='disabled')
        self.stop_scan_btn.pack(fill='x', pady=3)
    
    def create_right_panel(self, parent):
        """Create the right panel with progress and results"""
        right_frame = tk.Frame(parent, bg='#1a1a1a')
        right_frame.pack(side='right', fill='both', expand=True)
        
        # Scan Progress section
        self.create_progress_section(right_frame)
        
        # Scan Results section
        self.create_results_section(right_frame)
    
    def create_progress_section(self, parent):
        """Create scan progress section"""
        progress_frame = tk.Frame(parent, bg='#1a1a1a')
        progress_frame.pack(fill='x', padx=20, pady=(20, 10))
        
        # Progress title
        progress_title = tk.Label(progress_frame, text="Scan Progress", 
                                bg='#1a1a1a', fg='#00ff88', 
                                font=('Segoe UI', 14, 'bold'))
        progress_title.pack(anchor='w', pady=(0, 10))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, 
                                          variable=self.progress_var,
                                          maximum=100,
                                          length=400)
        self.progress_bar.pack(fill='x', pady=(0, 10))
        
        # Status text
        self.progress_text = tk.Label(progress_frame, text="Ready to scan", 
                                     bg='#1a1a1a', fg='#ffffff',
                                     font=('Segoe UI', 10))
        self.progress_text.pack(anchor='w')
        
        # Statistics
        self.stats_text = tk.Label(progress_frame, text="Files Scanned: 0 | Threats Found: 0 | Time: 00:00", 
                                  bg='#1a1a1a', fg='#cccccc',
                                  font=('Segoe UI', 9))
        self.stats_text.pack(anchor='w', pady=(5, 0))
    
    def create_results_section(self, parent):
        """Create scan results section"""
        results_frame = tk.Frame(parent, bg='#1a1a1a')
        results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Results title
        results_title = tk.Label(results_frame, text="Scan Results", 
                                bg='#1a1a1a', fg='#00ff88', 
                                font=('Segoe UI', 14, 'bold'))
        results_title.pack(anchor='w', pady=(0, 10))
        
        # Create treeview container
        tree_container = tk.Frame(results_frame, bg='#1a1a1a')
        tree_container.pack(fill='both', expand=True)
        
        # Results treeview
        columns = ('File', 'Threat Type', 'Severity', 'Size', 'Time', 'Method')
        self.results_tree = ttk.Treeview(tree_container, columns=columns, 
                                        show='headings', style='CleanTreeview.Treeview',
                                        height=20)
        
        # Configure columns
        self.results_tree.heading('File', text='File')
        self.results_tree.heading('Threat Type', text='Threat Type')
        self.results_tree.heading('Severity', text='Severity')
        self.results_tree.heading('Size', text='Size')
        self.results_tree.heading('Time', text='Time')
        self.results_tree.heading('Method', text='Method')
        
        # Configure column widths
        self.results_tree.column('File', width=200)
        self.results_tree.column('Threat Type', width=150)
        self.results_tree.column('Severity', width=80)
        self.results_tree.column('Size', width=80)
        self.results_tree.column('Time', width=80)
        self.results_tree.column('Method', width=100)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_container, orient='vertical', 
                                   command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_container, orient='horizontal', 
                                   command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, 
                                   xscrollcommand=h_scrollbar.set)
        
        # Pack layout
        self.results_tree.pack(side='left', fill='both', expand=True)
        v_scrollbar.pack(side='right', fill='y')
        h_scrollbar.pack(side='bottom', fill='x')
        
        # Context menu
        self.create_context_menu()
    
    def create_context_menu(self):
        """Create right-click context menu"""
        self.context_menu = tk.Menu(self.root, tearoff=0, bg='#2a2a2a', fg='#ffffff')
        self.context_menu.add_command(label="📁 Open File Location", command=self.open_file_location)
        self.context_menu.add_command(label="🔍 Rescan File", command=self.rescan_selected)
        self.context_menu.add_command(label="❌ Remove from List", command=self.remove_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📋 Copy File Path", command=self.copy_file_path)
        self.context_menu.add_command(label="📊 Show Details", command=self.show_file_details)
        
        # Bind right-click event
        self.results_tree.bind("<Button-3>", self.show_context_menu)
    
    def start_result_processor(self):
        """Start background thread to process scan results"""
        def process_results():
            while True:
                try:
                    result = self.result_queue.get(timeout=1)
                    if result is None:  # Shutdown signal
                        break
                    
                    # Update UI with result
                    self.root.after(0, self.update_result_display, result)
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    if logger:
                        logger.error(f"Result processing error: {e}")
        
        self.result_thread = threading.Thread(target=process_results, daemon=True)
        self.result_thread.start()
    
    def update_result_display(self, result):
        """Update the UI with scan result"""
        try:
            file_name, threat_type, severity, file_size, scan_time, detection_method = result
            
            # Determine row color based on threat level
            tags = []
            if severity == "High":
                tags.append('high_threat')
            elif severity == "Medium":
                tags.append('medium_threat')
            elif severity == "Low":
                tags.append('low_threat')
            else:
                tags.append('clean')
            
            # Add to results tree
            item = self.results_tree.insert('', 'end', values=(
                file_name,
                threat_type,
                severity,
                file_size,
                scan_time,
                detection_method
            ), tags=tags)
            
            # Configure tag colors
            self.results_tree.tag_configure('high_threat', background='#ff4444', foreground='#ffffff')
            self.results_tree.tag_configure('medium_threat', background='#ff8800', foreground='#ffffff')
            self.results_tree.tag_configure('low_threat', background='#ffaa00', foreground='#000000')
            self.results_tree.tag_configure('clean', background='#00ff88', foreground='#000000')
            
            # Update statistics
            self.update_statistics()
            
            # Scroll to bottom
            self.results_tree.see(item)
            
            # Force GUI update
            self.root.update_idletasks()
            
        except Exception as e:
            if logger:
                logger.error(f"UI update error: {e}")
            print(f"UI update error: {e}")  # Fallback logging
    
    def update_statistics(self):
        """Update statistics display"""
        try:
            # Count items in treeview
            total_files = len(self.results_tree.get_children())
            threats = 0
            clean = 0
            
            for item in self.results_tree.get_children():
                values = self.results_tree.item(item, 'values')
                if values and len(values) > 2:
                    severity = values[2]
                    if severity != "Clean":
                        threats += 1
                    else:
                        clean += 1
            
            # Update statistics text
            elapsed_time = "00:00"
            if self.scan_start_time:
                elapsed = time.time() - self.scan_start_time
                minutes = int(elapsed // 60)
                seconds = int(elapsed % 60)
                elapsed_time = f"{minutes:02d}:{seconds:02d}"
            
            self.stats_text.config(text=f"Files Scanned: {total_files} | Threats Found: {threats} | Time: {elapsed_time}")
            
        except Exception as e:
            if logger:
                logger.error(f"Statistics update error: {e}")
    
    def update_status_timer(self):
        """Update status periodically"""
        self.root.after(5000, self.update_status_timer)
    
    # Button command methods
    def scan_file(self):
        """Open file selection dialog and start scan"""
        file_path = filedialog.askopenfilename(
            title="Select file to scan",
            filetypes=[("All files", "*.*"), ("Executables", "*.exe"), ("Documents", "*.pdf;*.doc;*.docx")]
        )
        if file_path:
            self.antivirus_app.scan_file(file_path)
    
    def scan_directory(self):
        """Open folder selection dialog and start scan"""
        folder_path = filedialog.askdirectory(title="Select folder to scan")
        if folder_path:
            self.antivirus_app.scan_directory(folder_path)
    
    def scan_system(self):
        """Start system scan"""
        self.antivirus_app.scan_system()
    
    def quick_scan(self):
        """Start quick scan"""
        self.antivirus_app.quick_scan()
    
    def advanced_scan(self):
        """Start advanced scan"""
        self.antivirus_app.advanced_scan()
    
    def toggle_monitoring(self):
        """Toggle file system monitoring"""
        self.antivirus_app.toggle_monitoring()
        self.monitoring = not self.monitoring
    
    def show_performance_stats(self):
        """Show performance statistics window"""
        self.antivirus_app.show_performance_stats()
    
    def show_yara_rules_info(self):
        """Show YARA rules information window"""
        self.antivirus_app.show_yara_rules_info()
    
    def reload_yara_rules(self):
        """Reload YARA rules"""
        self.antivirus_app.reload_yara_rules()
    
    def start_scan(self):
        """Start scan process"""
        self.antivirus_app.start_scan()
        self.scanning = True
        self.scan_start_time = time.time()
        self.start_scan_btn.config(state='disabled')
        self.stop_scan_btn.config(state='normal')
        self.update_status("Scan started - Ready for scanning")
    
    def stop_scan(self):
        """Stop scan process"""
        self.antivirus_app.stop_scan()
        self.scanning = False
        self.start_scan_btn.config(state='normal')
        self.stop_scan_btn.config(state='disabled')
        self.update_status("Scan stopped")
    
    def update_status(self, message):
        """Update status display"""
        self.progress_text.config(text=message)
    
    def update_progress(self, value):
        """Update progress bar"""
        self.progress_var.set(value)
    
    def add_result(self, file_name, threat_type, severity, file_size, scan_time, detection_method):
        """Add scan result to display"""
        result = (file_name, threat_type, severity, file_size, scan_time, detection_method)
        self.result_queue.put(result)
    
    def clear_results(self):
        """Clear all scan results"""
        self.results_tree.delete(*self.results_tree.get_children())
        self.update_statistics()
    
    def reset_ui(self):
        """Reset UI and clear results"""
        self.results_tree.delete(*self.results_tree.get_children())
        self.progress_var.set(0)
        self.update_status("Ready to scan")
        self.scanning = False
        self.start_scan_btn.config(state='normal')
        self.stop_scan_btn.config(state='disabled')
        self.scan_start_time = None
        self.update_statistics()
    
    def enable_scan_buttons(self, enabled=True):
        """Enable or disable scan buttons"""
        state = 'normal' if enabled else 'disabled'
        # Note: Individual scan buttons don't need to be disabled during scanning
    
    # Context menu methods
    def show_context_menu(self, event):
        """Show right-click context menu"""
        try:
            item = self.results_tree.selection()[0]
            self.context_menu.post(event.x_root, event.y_root)
        except IndexError:
            pass
    
    def open_file_location(self):
        """Open file location in file explorer"""
        try:
            item = self.results_tree.selection()[0]
            values = self.results_tree.item(item, 'values')
            if values:
                file_path = values[0]
                if os.path.exists(file_path):
                    os.startfile(os.path.dirname(file_path))
                else:
                    messagebox.showerror("Error", "File not found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file location: {e}")
    
    def rescan_selected(self):
        """Rescan selected file"""
        try:
            item = self.results_tree.selection()[0]
            values = self.results_tree.item(item, 'values')
            if values:
                file_path = values[0]
                self.antivirus_app.scan_file(file_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to rescan file: {e}")
    
    def remove_selected(self):
        """Remove selected item from results"""
        try:
            item = self.results_tree.selection()[0]
            self.results_tree.delete(item)
            self.update_statistics()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove item: {e}")
    
    def copy_file_path(self):
        """Copy file path to clipboard"""
        try:
            item = self.results_tree.selection()[0]
            values = self.results_tree.item(item, 'values')
            if values:
                file_path = values[0]
                self.root.clipboard_clear()
                self.root.clipboard_append(file_path)
                messagebox.showinfo("Success", "File path copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy file path: {e}")
    
    def show_file_details(self):
        """Show detailed file information"""
        try:
            item = self.results_tree.selection()[0]
            values = self.results_tree.item(item, 'values')
            if values:
                file_path = values[0]
                threat_type = values[1]
                severity = values[2]
                size = values[3]
                scan_time = values[4]
                method = values[5]
                
                details = f"""File Details:

File Path: {file_path}
Threat Type: {threat_type}
Severity: {severity}
Size: {size}
Scan Time: {scan_time}
Detection Method: {method}

File Exists: {'Yes' if os.path.exists(file_path) else 'No'}
File Readable: {'Yes' if os.access(file_path, os.R_OK) else 'No'}
"""
                
                messagebox.showinfo("File Details", details)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show file details: {e}")

class PerformanceStatsWindow:
    """Performance statistics window"""
    
    def __init__(self, parent, antivirus_app):
        self.parent = parent
        self.antivirus_app = antivirus_app
        self.window = None
    
    def show(self):
        """Show performance statistics window"""
        if self.window and self.window.winfo_exists():
            self.window.lift()
            return
        
        self.window = tk.Toplevel(self.parent)
        self.window.title("📊 Performance Statistics - Sentinel")
        self.window.geometry("800x600")
        self.window.configure(bg='#0a0a0a')
        
        # Create notebook for tabs
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Performance tab
        self.create_performance_tab(notebook)
        
        # YARA Rules tab
        self.create_yara_tab(notebook)
        
        # System Info tab
        self.create_system_tab(notebook)
        
        # Update data
        self.update_data()
    
    def create_performance_tab(self, notebook):
        """Create performance statistics tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Performance")
        
        # Performance text
        self.perf_text = scrolledtext.ScrolledText(frame, height=20, width=80,
                                                  bg='#1a1a1a', fg='#ffffff',
                                                  font=('Consolas', 10))
        self.perf_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_yara_tab(self, notebook):
        """Create YARA rules tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="YARA Rules")
        
        # YARA text
        self.yara_text = scrolledtext.ScrolledText(frame, height=20, width=80,
                                                  bg='#1a1a1a', fg='#ffffff',
                                                  font=('Consolas', 10))
        self.yara_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_system_tab(self, notebook):
        """Create system information tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="System Info")
        
        # System text
        self.sys_text = scrolledtext.ScrolledText(frame, height=20, width=80,
                                                 bg='#1a1a1a', fg='#ffffff',
                                                 font=('Consolas', 10))
        self.sys_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def update_data(self):
        """Update all data in the window"""
        if not self.window or not self.window.winfo_exists():
            return
        
        # Update performance data
        perf_data = self.antivirus_app.generate_performance_report()
        self.perf_text.delete(1.0, tk.END)
        self.perf_text.insert(tk.END, perf_data)
        
        # Update YARA data
        yara_data = self.antivirus_app.get_yara_rules_info()
        self.yara_text.delete(1.0, tk.END)
        self.yara_text.insert(tk.END, yara_data)
        
        # Update system data
        sys_data = self.antivirus_app.get_system_info()
        self.sys_text.delete(1.0, tk.END)
        self.sys_text.insert(tk.END, sys_data)
        
        # Schedule next update
        self.window.after(5000, self.update_data)

class YARARulesWindow:
    """YARA rules information window"""
    
    def __init__(self, parent, antivirus_app):
        self.parent = parent
        self.antivirus_app = antivirus_app
        self.window = None
    
    def show(self):
        """Show YARA rules information window"""
        if self.window and self.window.winfo_exists():
            self.window.lift()
            return
        
        self.window = tk.Toplevel(self.parent)
        self.window.title("🔍 YARA Rules Information - Sentinel")
        self.window.geometry("900x700")
        self.window.configure(bg='#0a0a0a')
        
        # Create text widget
        text_widget = scrolledtext.ScrolledText(self.window, height=30, width=100,
                                               bg='#1a1a1a', fg='#ffffff',
                                               font=('Consolas', 10))
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Get YARA rules info
        yara_info = self.antivirus_app.get_yara_rules_info()
        text_widget.insert(tk.END, yara_info)
        text_widget.config(state=tk.DISABLED)