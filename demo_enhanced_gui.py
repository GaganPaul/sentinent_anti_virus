#!/usr/bin/env python3
"""
Enhanced GUI Demo for Sentinel Antivirus
"""

import tkinter as tk
import os
import tempfile
import time
import threading

def create_demo_files():
    """Create demo files for testing"""
    demo_files = []
    
    # Create EICAR test file
    eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_file = "demo_eicar.txt"
    with open(eicar_file, 'w', encoding='utf-8') as f:
        f.write(eicar_content)
    demo_files.append(eicar_file)
    
    # Create clean file
    clean_file = "demo_clean.txt"
    with open(clean_file, 'w', encoding='utf-8') as f:
        f.write("This is a clean file for testing purposes.")
    demo_files.append(clean_file)
    
    # Create suspicious file
    suspicious_file = "demo_suspicious.js"
    with open(suspicious_file, 'w', encoding='utf-8') as f:
        f.write("eval(atob('d2luZG93LmxvY2F0aW9uPSJodHRwczovL2V4YW1wbGUuY29tIjs='));")
    demo_files.append(suspicious_file)
    
    return demo_files

def demo_scan_simulation(gui, antivirus_app):
    """Simulate scanning with demo files"""
    demo_files = create_demo_files()
    
    def scan_files():
        time.sleep(1)  # Initial delay
        
        for i, file_path in enumerate(demo_files):
            # Update progress
            progress = ((i + 1) / len(demo_files)) * 100
            gui.update_progress(progress)
            gui.update_status(f"Scanning {os.path.basename(file_path)}...")
            
            # Simulate scan
            time.sleep(0.5)
            
            # Add result based on file type
            if "eicar" in file_path.lower():
                gui.add_result(file_path, "EICAR Test", "High", "68.0", "12:34:56", "Signature")
            elif "suspicious" in file_path.lower():
                gui.add_result(file_path, "Suspicious JavaScript", "Medium", "45.0", "12:34:57", "Heuristic")
            else:
                gui.add_result(file_path, "Clean", "Clean", "32.0", "12:34:58", "None")
        
        # Final status
        gui.update_progress(100)
        gui.update_status("Demo scan completed!")
        
        # Cleanup demo files
        for file_path in demo_files:
            if os.path.exists(file_path):
                os.remove(file_path)
    
    # Start scanning in background thread
    scan_thread = threading.Thread(target=scan_files, daemon=True)
    scan_thread.start()

def main():
    """Main demo function"""
    print("🛡️ Sentinel Antivirus - Enhanced GUI Demo")
    print("=" * 50)
    print("This demo showcases the enhanced cyber-themed GUI")
    print("with professional styling and advanced features.")
    print()
    
    try:
        from main import SentinelAntivirus
        from gui import SentinelGUI
        
        # Create main window
        root = tk.Tk()
        
        # Create antivirus application
        antivirus_app = SentinelAntivirus()
        
        # Create enhanced GUI
        gui = SentinelGUI(root, antivirus_app)
        antivirus_app.set_gui(gui)
        
        # Add demo button
        demo_frame = tk.Frame(gui.root, bg='#1a1a1a')
        demo_frame.pack(fill='x', padx=20, pady=10)
        
        demo_btn = tk.Button(demo_frame, 
                           text="🎬 Start Demo Scan", 
                           bg='#aa44ff', 
                           fg='#ffffff',
                           font=('Segoe UI', 12, 'bold'),
                           command=lambda: demo_scan_simulation(gui, antivirus_app))
        demo_btn.pack(pady=10)
        
        # Add info label
        info_label = tk.Label(demo_frame, 
                            text="Click 'Start Demo Scan' to see the enhanced GUI in action!",
                            bg='#1a1a1a', 
                            fg='#cccccc',
                            font=('Segoe UI', 10))
        info_label.pack(pady=5)
        
        print("✓ Enhanced GUI created successfully!")
        print("✓ Cyber theme applied")
        print("✓ All features available")
        print()
        print("GUI Features:")
        print("• Professional cyber-themed interface")
        print("• Real-time scan results display")
        print("• Advanced scan controls")
        print("• Performance statistics")
        print("• YARA rules management")
        print("• File system monitoring")
        print("• Context menus and file operations")
        print()
        print("🎉 The enhanced GUI is ready!")
        print("Close the window to exit the demo.")
        
        # Start the GUI
        root.mainloop()
        
    except Exception as e:
        print(f"✗ Demo failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
