import PyInstaller.__main__
import os
import sys

def build():
    # Define paths
    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
    main_script = os.path.join(src_dir, "main.py")
    
    # PyInstaller arguments
    args = [
        main_script,
        '--name=BahaaIT',
        '--onefile',
        '--windowed',
        '--add-data=src/ui/styles.qss;ui', # Add QSS to bundle
        '--clean',
    ]
    
    # If we had icons or other assets:
    # args.append('--add-data=assets;assets')
    # args.append('--icon=assets/icon.ico')

    print(f"Building with arguments: {' '.join(args)}")
    PyInstaller.__main__.run(args)

if __name__ == "__main__":
    build()
