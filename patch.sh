#!/usr/bin/env bash

# Change directory to the folder where this shell script is located
cd "$(dirname "$0")"

# Execute Python script
python3 run_patches.py

# Keep terminal window open until user presses Enter
read -p "Press Enter to exit..."