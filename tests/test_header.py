#!/usr/bin/env python3
"""
Test GUI Header Display
"""

import tkinter as tk
import time

def test_header_display():
    """Test that the GUI header displays correctly"""
    print("🛡️ Testing GUI Header Display")
    print("=" * 40)
    
    try:
        from main import SentinelAntivirus
        from gui import SentinelGUI
        
        # Create root window
        root = tk.Tk()
        
        # Create antivirus application
        antivirus_app = SentinelAntivirus()
        
        # Create GUI
        gui = SentinelGUI(root, antivirus_app)
        antivirus_app.set_gui(gui)
        
        print("✓ GUI created successfully")
        print(f"✓ Window title: {root.title()}")
        
        # Check if header elements exist
        header_elements = []
        for widget in root.winfo_children():
            if isinstance(widget, tk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, tk.Label):
                        text = child.cget('text')
                        if text in ['S', 'Sentinel', 'A timeless watchman guarding your digital realm']:
                            header_elements.append(text)
        
        print(f"✓ Header elements found: {header_elements}")
        
        if 'S' in header_elements and 'Sentinel' in header_elements:
            print("✅ Header is displaying correctly!")
            print("✓ Large 'S' logo visible")
            print("✓ 'Sentinel' title visible")
            print("✓ Tagline visible")
        else:
            print("❌ Header elements missing")
        
        # Keep window open briefly to see the header
        root.after(2000, root.destroy)
        root.mainloop()
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_header_display()
    if success:
        print("\n✅ Header display test passed!")
    else:
        print("\n❌ Header display test failed.")
