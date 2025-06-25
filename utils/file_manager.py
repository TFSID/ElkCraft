"""
File management utilities for script generation
"""

import os
from datetime import datetime

class FileManager:
    """Handles file operations for generated scripts"""
    
    @staticmethod
    def save_script(content, filename, make_executable=False):
        """Save script content to file"""
        try:
            with open(filename, 'w', encoding='utf-8', newline='\n') as f:
                f.write(content)
            
            print(f"✅ Script saved successfully: {filename}")
            
            # Make Linux script executable
            if make_executable and filename.endswith('.sh'):
                os.chmod(filename, 0o755)
                print(f"✅ Made script executable: chmod +x {filename}")
                
            return True
            
        except Exception as e:
            print(f"❌ Error saving script: {e}")
            return False
    
    @staticmethod
    def generate_filename(platform, timestamp=None):
        """Generate filename for script"""
        if timestamp is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        extension = '.sh' if platform.lower() == 'linux' else '.bat'
        return f"install_elk_{platform.lower()}_{timestamp}{extension}"
    
    @staticmethod
    def create_directory(directory):
        """Create directory if it doesn't exist"""
        try:
            os.makedirs(directory, exist_ok=True)
            return True
        except Exception as e:
            print(f"❌ Error creating directory {directory}: {e}")
            return False
