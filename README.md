# 🎵 MP3 Extractor & Downloader (Windows)

A modern Windows desktop application for extracting and downloading **MP3 files** from:
- Large / minified HTML source code
- Lists of webpage URLs

Built with **Python + PySide6 (Qt)** and designed to handle **very large sources** efficiently.

---

## ✨ Features

- 📋 **Paste-based input** (no file selection required)
  - Paste **HTML source code**
  - OR paste **a list of page URLs** (one per line)
- 🔍 **Fast & safe scanning**
  - Chunk-by-chunk text scanning
  - Works with huge, minified, single-line HTML
- 🎧 **MP3 detection**
  - Finds `.mp3` links anywhere in text
  - Supports relative links (with optional Base URL)
- 📊 **Results preview**
  - View all found MP3 links before downloading
  - Filter downloadable (`http/https`) links
- ⬇️ **Safe downloading**
  - Background downloads (UI never freezes)
  - Progress bar with percentage
- 🏷️ **Smart file renaming**
  - Automatically rename files using ID3 tags  
    `Artist - Title.mp3`
- 🖥️ **Modern UI**
  - Dark theme
  - Clean, Windows-friendly design
- 📦 **Portable**
  - Single `.exe` file (no Python required)

---

## 🧠 How It Works

### Input Modes
Choose input type using the checkbox:

- ✅ **URLs mode**
  - Paste one webpage URL per line
  - The app fetches each page and scans it for MP3 links

- ⬜ **HTML Source mode**
  - Paste raw HTML source code
  - The app scans the text directly (no HTML parsing)

### Base URL (Optional)
Used to resolve relative MP3 paths in pasted HTML:
