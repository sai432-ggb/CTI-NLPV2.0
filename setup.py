#!/usr/bin/env python3
# ========================================
# CTI-NLP Enhanced Analyzer - Setup Script
# ========================================

import os
import sys
from pathlib import Path
import subprocess

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60 + "\n")

def check_python_version():
    """Ensure Python 3.7+ is installed"""
    print("Checking Python version...")
    if sys.version_info < (3, 7):
        print("❌ Error: Python 3.7 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python {sys.version.split()[0]} detected")
    return True

def create_directories():
    """Create necessary project directories"""
    print("\nCreating project directories...")
    
    directories = [
        'data',
        'modules',
        'logs',
        'quarantine'
    ]
    
    for directory in directories:
        path = Path(directory)
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            print(f"✅ Created: {directory}/")
        else:
            print(f"⏭️  Exists: {directory}/")
    
    # Create __init__.py for modules
    init_file = Path('modules') / '__init__.py'
    if not init_file.exists():
        init_file.write_text('# CTI-NLP Modules Package\n')
        print(f"✅ Created: modules/__init__.py")

def install_dependencies():
    """Install required Python packages"""
    print("\nInstalling dependencies...")
    print("This may take a few minutes...\n")
    
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ])
        print("\n✅ All dependencies installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("\n❌ Error installing dependencies")
        print("   Try manually: pip install -r requirements.txt")
        return False
    except FileNotFoundError:
        print("\n❌ requirements.txt not found")
        print("   Please ensure requirements.txt exists in the project directory")
        return False

def check_data_files():
    """Check if required data files exist"""
    print("\nChecking data files...")
    
    data_files = {
        'data/url_dataset.csv': 'URL training dataset',
        'data/cyber-threat-intelligence-all.csv': 'CTI training dataset (optional)',
        'data/malicious_ips.csv': 'Malicious IPs database',
        'data/virus_signatures.json': 'Virus signatures',
        'data/trusted_ips.txt': 'Trusted IPs whitelist (optional)'
    }
    
    missing_required = []
    
    for file_path, description in data_files.items():
        path = Path(file_path)
        if path.exists():
            print(f"✅ Found: {file_path}")
        else:
            if 'optional' in description:
                print(f"⚠️  Missing (optional): {file_path}")
            else:
                print(f"❌ Missing (required): {file_path}")
                missing_required.append(file_path)
    
    if missing_required:
        print(f"\n⚠️  Warning: {len(missing_required)} required file(s) missing")
        print("   Some files will be created automatically on first run")
        print("   For full functionality, provide:")
        for file in missing_required:
            print(f"     - {file}")
    
    return len(missing_required) == 0

def check_model_files():
    """Check if trained models exist"""
    print("\nChecking trained models...")
    
    model_files = [
        'model.pkl',
        'feature_list.pkl',
        'threat_encoder.pkl',
        'url_model.pkl',
        'url_feature_names.pkl',
        'url_label_encoder.pkl'
    ]
    
    missing = []
    for file in model_files:
        if Path(file).exists():
            print(f"✅ Found: {file}")
        else:
            print(f"❌ Missing: {file}")
            missing.append(file)
    
    if missing:
        print(f"\n⚠️  {len(missing)} model file(s) missing")
        print("   You need to train the models first!")
        print("   Run: jupyter notebook model_training.ipynb")
        return False
    
    return True

def create_config_if_missing():
    """Create config.py if it doesn't exist"""
    config_file = Path('config.py')
    
    if config_file.exists():
        print("\n✅ config.py exists")
        return
    
    print("\n⚠️  config.py not found, using defaults")
    print("   For custom configuration, create config.py manually")

def check_ports():
    """Check if required ports are available"""
    print("\nChecking port availability...")
    
    import socket
    
    def is_port_open(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result != 0
        except:
            return True
    
    ports_to_check = {
        5000: 'Flask Backend API',
        8000: 'Frontend HTTP Server'
    }
    
    all_available = True
    for port, description in ports_to_check.items():
        if is_port_open(port):
            print(f"✅ Port {port} available ({description})")
        else:
            print(f"⚠️  Port {port} in use ({description})")
            all_available = False
    
    if not all_available:
        print("\n⚠️  Some ports are in use. You may need to:")
        print("   - Stop existing services")
        print("   - Use different ports (modify code)")
    
    return all_available

def print_next_steps():
    """Print instructions for next steps"""
    print_header("SETUP COMPLETE!")
    
    print("📋 Next Steps:\n")
    
    print("1️⃣  Train Models (if not already done):")
    print("   jupyter notebook model_training.ipynb")
    print("   - Run all cells to generate .pkl files\n")
    
    print("2️⃣  Start Backend API:")
    print("   python app.py")
    print("   - Keep this terminal open\n")
    
    print("3️⃣  Start Frontend Server (new terminal):")
    print("   python -m http.server 8000\n")
    
    print("4️⃣  Access Dashboard:")
    print("   http://127.0.0.1:8000/index.html\n")
    
    print("📖 For detailed documentation, see README.md")
    print("🔧 For configuration options, edit config.py")
    print("🧪 To test modules: python modules/ip_tracker.py")
    
    print("\n" + "=" * 60)
    print("  🛡️  CTI-NLP Enhanced Analyzer v2.0")
    print("  Ready for Deployment!")
    print("=" * 60 + "\n")

def main():
    """Main setup function"""
    print_header("CTI-NLP Enhanced Analyzer - Setup")
    
    print("This script will:")
    print("  ✓ Check Python version")
    print("  ✓ Create necessary directories")
    print("  ✓ Install dependencies")
    print("  ✓ Verify data files")
    print("  ✓ Check model files")
    print("  ✓ Verify port availability\n")
    
    input("Press Enter to continue...")
    
    # Step 1: Check Python version
    print_header("Step 1: Python Version Check")
    if not check_python_version():
        sys.exit(1)
    
    # Step 2: Create directories
    print_header("Step 2: Create Directories")
    create_directories()
    
    # Step 3: Install dependencies
    print_header("Step 3: Install Dependencies")
    install_choice = input("\nInstall dependencies now? (y/n): ").lower()
    if install_choice == 'y':
        if not install_dependencies():
            print("\n⚠️  Continuing despite dependency errors...")
    else:
        print("⏭️  Skipped dependency installation")
        print("   Remember to run: pip install -r requirements.txt")
    
    # Step 4: Check data files
    print_header("Step 4: Data Files Check")
    check_data_files()
    
    # Step 5: Check models
    print_header("Step 5: Model Files Check")
    models_exist = check_model_files()
    if not models_exist:
        print("\n⚠️  Models not found - training required before running")
    
    # Step 6: Config file
    print_header("Step 6: Configuration Check")
    create_config_if_missing()
    
    # Step 7: Check ports
    print_header("Step 7: Port Availability Check")
    check_ports()
    
    # Final steps
    print_next_steps()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Setup failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)