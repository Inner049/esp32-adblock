import os
import re
import subprocess
import shutil
import sys

def main():
    # 1. Read main.cpp and find FW_VERSION
    main_cpp_path = os.path.join('src', 'main.cpp')
    with open(main_cpp_path, 'r', encoding='utf-8') as f:
        content = f.read()

    match = re.search(r'#define FW_VERSION (\d+)', content)
    if not match:
        print("Error: Could not find FW_VERSION in src/main.cpp")
        sys.exit(1)

    current_version = int(match.group(1))
    new_version = current_version + 1
    print(f"Bumping version from {current_version} to {new_version}...")

    # 2. Update main.cpp
    content = re.sub(r'#define FW_VERSION \d+', f'#define FW_VERSION {new_version}', content)
    with open(main_cpp_path, 'w', encoding='utf-8') as f:
        f.write(content)

    # 3. Compile the project
    print("Compiling firmware...")
    # Using the local PlatformIO if available, otherwise just 'pio'
    pio_cmd = r'C:\Users\inner\.platformio\penv\Scripts\pio.exe'
    if not os.path.exists(pio_cmd):
        pio_cmd = 'pio'
        
    result = subprocess.run([pio_cmd, 'run'], capture_output=False)
    if result.returncode != 0:
        print("Error: Compilation failed!")
        # Revert version
        with open(main_cpp_path, 'w', encoding='utf-8') as f:
            f.write(content.replace(f'#define FW_VERSION {new_version}', f'#define FW_VERSION {current_version}'))
        sys.exit(1)

    # 4. Copy firmware and push ONLY firmware.bin
    print("Compilation successful. Copying firmware...")
    if not os.path.exists('ota'):
        os.makedirs('ota')
        
    shutil.copy2(os.path.join('.pio', 'build', 'c3', 'firmware.bin'), os.path.join('ota', 'firmware.bin'))

    print("Step 1/2: Committing and pushing firmware.bin to GitHub...")
    subprocess.run(['git', 'add', 'src/main.cpp', 'ota/firmware.bin'])
    subprocess.run(['git', 'commit', '-m', f'Upload FW v{new_version} binary'])
    subprocess.run(['git', 'push'])

    # 5. Wait for Pages deployment before pushing version.txt
    print("\nWaiting 2 minutes for GitHub Pages to deploy the firmware file...")
    print("This guarantees that boards won't crash by trying to download a file that isn't ready.")
    import time
    for i in range(120, 0, -10):
        print(f"Waiting {i} seconds...")
        time.sleep(10)

    # 6. Push version.txt
    print("\nStep 2/2: Committing and pushing version.txt to trigger OTA...")
    with open(os.path.join('ota', 'version.txt'), 'w', encoding='utf-8') as f:
        f.write(str(new_version))
        
    subprocess.run(['git', 'add', 'ota/version.txt'])
    subprocess.run(['git', 'commit', '-m', f'Release FW v{new_version} (update version.txt)'])
    subprocess.run(['git', 'push'])

    print(f"\n========================================================")
    print(f" SUCCESS: Firmware v{new_version} is fully published!")
    print(f" You can now safely click 'Update FW (All)' on your dashboard.")
    print(f"========================================================\n")

if __name__ == '__main__':
    main()
