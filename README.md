# Go Fish Phishy 🎣

A desktop application for detecting phishing attempts by analyzing email headers. Go Fish Phishy helps you catch suspicious emails before they catch you!

## Description

Go Fish Phishy is a user-friendly GUI application built with Python and PyQt5 that analyzes email headers to identify potential phishing attempts. The application checks critical email authentication mechanisms including SPF, DKIM, and DMARC, and compares sender information to detect inconsistencies commonly found in phishing emails.

### Key Features

- **Email Authentication Analysis**: Validates SPF, DKIM, and DMARC records
- **Sender Verification**: Compares From, Return-Path, and Reply-To addresses
- **Multiple Input Methods**:
  - Paste raw email headers directly
  - Load .eml email files
  - Load .msg email files (Outlook format)
- **Detailed Explanations**: Each check includes educational information about what it means
- **Interactive Tutorials**: Built-in guides for accessing email headers from different email clients
- **Modern GUI**: Clean, intuitive interface with color-coded results

## Prerequisites

Before installing Go Fish Phishy, ensure you have the following:

- **Python 3.7 or higher** (tested with Python 3.12)
- **pip** (Python package installer)
- **Operating System**: 
  - Windows (for full .msg file support with pywin32)
  - macOS or Linux (limited .msg support)

## Installation

### Step 1: Clone or Download the Repository

```bash
git clone https://github.com/LukeZem/go-fish-phishy.git
cd go-fish-phishy
```

Alternatively, download and extract the ZIP file from GitHub.

### Step 2: Install Dependencies

Install the required Python packages using pip:

```bash
pip install -r requirements.txt
```

**Note**: On Windows, if you encounter issues with `pywin32`, you may need to install it separately:

```bash
pip install pywin32
```

On macOS/Linux, `pywin32` is Windows-specific and may not install correctly, but the application will still work for .eml files and header text.

### Optional: Create a Virtual Environment

It's recommended to use a virtual environment to avoid conflicts with other Python packages:

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## How to Launch

### Running the Application

Once dependencies are installed, launch the application with:

```bash
python roughv1.py
```

Or on some systems:

```bash
python3 roughv1.py
```

The application window will open, displaying the main interface.

## Usage Guide

### Method 1: Paste Raw Email Headers

1. Launch the application
2. In your email client, access the email headers:
   - **Outlook**: Open email → File → Properties → Internet headers
   - **Gmail**: Open email → Three-dot menu → Show original
   - **Apple Mail**: View → Message → All Headers
3. Copy the raw header text
4. Paste it into the text area in Go Fish Phishy
5. Results will appear automatically in the table above

### Method 2: Load Email Files

1. Click the **"Load Email File"** button
2. Navigate to your email file (.eml or .msg format)
3. Select the file and click Open
4. The application will parse the headers and display results

### Method 3: Save and Load from Outlook

For Outlook users:
1. Drag an email from Outlook to your desktop (this saves it as .msg)
2. Use the "Load Email File" button to open the saved .msg file

### Understanding the Results

The application checks five key aspects:

- **SPF (Sender Policy Framework)**: Verifies the sending server is authorized
- **DKIM (DomainKeys Identified Mail)**: Confirms email hasn't been tampered with
- **DMARC (Domain-based Message Authentication)**: Validates domain authentication policy
- **From/Return-Path Match**: Ensures sender consistency
- **From/Reply-To Match**: Detects reply-to hijacking

Each check shows:
- ✅ **Pass**: Indicates legitimate authentication
- ❌ **Fail**: Warning sign of potential phishing

### Accessing Tutorials

Click the **"Show Tutorials"** button to access built-in guides for:
- Accessing email header data from different clients
- Understanding Outlook drag-and-drop limitations
- Finding email files on your system

## Dependencies

- **PyQt5** (≥5.15.0): GUI framework
- **extract-msg** (≥0.28.7): For parsing Outlook .msg files
- **pywin32** (≥227): Windows-specific functionality for .msg files

## Troubleshooting

### Application Won't Start

- Ensure Python 3.7+ is installed: `python --version`
- Verify all dependencies are installed: `pip list | grep -E "PyQt5|extract-msg"`
- Try reinstalling dependencies: `pip install -r requirements.txt --force-reinstall`

### .msg Files Won't Load

- On Windows, ensure `pywin32` is properly installed
- On macOS/Linux, .msg support is limited; use .eml files instead
- Try saving the email as .eml format from your email client

### No Results Displayed

- Ensure you've pasted complete header information
- Headers should include authentication results (SPF, DKIM, DMARC)
- Try loading a different email file to verify functionality

## Security Note

Go Fish Phishy analyzes email headers locally on your machine. No data is sent to external servers. This tool helps identify potential phishing attempts but should not be the sole method for determining email legitimacy. Always exercise caution with suspicious emails.

## Contributing

Contributions are welcome! Please feel free to submit issues, fork the repository, and create pull requests.

## License

This project is open source. Please check the repository for license information.

## Author

Developed by LukeZem

---

**Stay safe and keep phishing at bay! 🎣🛡️**
