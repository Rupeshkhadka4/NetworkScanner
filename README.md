#  Nmap Port Scanner Web App

A simple web-based port scanner built using **Python Flask** and **Nmap**.

## Features

- Scan multiple hosts at once
- Choose scan types:
  - All ports
  - Custom range
  - Top 10/20/30 common ports
- View results directly in browser
- Uses fast TCP SYN scanning (`-sS`) with Nmap
- Clean and responsive UI using HTML/CSS

## Requirements

- Python 3.x
- Nmap installed on system
- Install dependencies:
  ```bash
  pip install -r requirements.txt

  