"""
Main entry point for ELK Stack Installation Script Generator
Modular version with improved architecture and maintainability
"""

import sys
from ui.menu_interface import MenuInterface

def main():
    """Main function"""
    try:
        print("🔧 ELK Stack Installation Script Generator")
        print("📋 Modular Architecture Version")
        print("="*50)
        
        # Initialize and run the menu interface
        menu = MenuInterface()
        menu.run()
        
    except KeyboardInterrupt:
        print("\n\n👋 Installation script generator terminated by user.")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
