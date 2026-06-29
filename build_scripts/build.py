import PyInstaller.__main__
import os
import sys

def build():
    # Define paths
    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
    main_script = os.path.join(src_dir, "main.py")
    
    # 1. Automatically extract version from updater.py
    version = "2.0.0"
    updater_path = os.path.join(src_dir, "utils", "updater.py")
    if os.path.exists(updater_path):
        try:
            with open(updater_path, "r", encoding="utf-8") as f:
                for line in f:
                    if "CURRENT_VERSION =" in line:
                        version = line.split("=")[-1].strip().replace('"', '').replace("'", "").replace("v", "")
                        break
        except Exception as e:
            print(f"Warning: Could not read version from updater.py: {e}")
            
    # 2. Update setup_compiler.iss to match this version
    iss_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "setup_compiler.iss"))
    if os.path.exists(iss_path):
        try:
            with open(iss_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            new_lines = []
            for line in lines:
                if line.startswith("AppVersion="):
                    line = f"AppVersion={version}\n"
                elif line.startswith("OutputBaseFilename="):
                    line = f"OutputBaseFilename=Install_BahaaIT_v{version}\n"
                new_lines.append(line)
                
            with open(iss_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            print(f"Successfully synchronized setup_compiler.iss to version v{version}")
        except Exception as e:
            print(f"Warning: Could not update setup_compiler.iss: {e}")
    
    # PyInstaller arguments
    args = [
        main_script,
        '--name=BahaaIT',
        '--onedir',
        '--windowed',
        '--add-data=src/ui/styles.qss;ui', # Add QSS to bundle
        '--clean',
    ]
    
    # Include icons and other assets
    args.append('--add-data=assets;assets')
    args.append('--add-data=src/assets;src/assets')
    if os.path.exists(os.path.join(os.path.dirname(__file__), "..", "assets", "app_icon.ico")):
        args.append('--icon=assets/app_icon.ico')

    print(f"Building with arguments: {' '.join(args)}")
    PyInstaller.__main__.run(args)

if __name__ == "__main__":
    build()
