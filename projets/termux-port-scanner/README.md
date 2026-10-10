# termux-port-scanner

Multithreaded TCP port scanner built on Android Termux - Offline first.

**Features:**
- Fast multithreaded scan (Python threading)
- JSON export for Blue Team analysis
- Works 100% offline on Termux

**Usage:**
```bash
python3 scanner.py --target 127.0.0.1 --ports 1-1024 --output results.json
