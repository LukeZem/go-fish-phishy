import sys
import time
import os
import re
import struct
import tempfile
from email import policy
from email.parser import BytesParser
import extract_msg

from PyQt5.QtCore import Qt, QPropertyAnimation, QTimer
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QTextEdit,
    QLabel,
    QFileDialog,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
)
from PyQt5.QtGui import QFont


# ======================================== Header Parsing Functions ========================================


def extract_field(text, pattern):
    """
    Uses a regex pattern to extract a header field from the provided text.
    Returns the first matched group or an empty string.
    """
    match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def extract_email(header_value: str):
    """
    Extracts an email address from a header value which may be in the form:
    "Display Name <email@domain.com>".
    """
    email_match = re.search(r"[\w\.-]+@[\w\.-]+", header_value)
    return email_match.group(0).strip() if email_match else header_value.strip()


def parse_email_headers(header_text) -> dict:
    """
    Parses a raw header text and extracts relevant fields.
    Returns a dictionary of header values.
    """
    headers = {}
    headers["from"] = extract_field(header_text, r"^From:\s*(.*)$")
    headers["return_path"] = extract_field(header_text, r"^Return-Path:\s*<(.*)>$")
    headers["reply_to"] = extract_field(header_text, r"^Reply-To:\s*(.*)$")
    headers["spf"] = extract_field(header_text, r"spf=(\w+)")
    headers["dkim"] = extract_field(header_text, r"dkim=(\w+)")
    headers["dmarc"] = extract_field(header_text, r"dmarc=(\w+)")
    return headers


def analyze_header_results(headers) -> list:
    """
    Analyzes the extracted headers and returns a list of tuples,
    where each tuple is (Check, Status Icon, Explanation).
    The explanations provide detailed insights into each authentication mechanism.
    """
    results = []

    # SPF Check
    spf_result = headers.get("spf", "").lower()
    if spf_result == "pass":
        results.append(
            (
                "SPF",
                "✅",
                "SPF (Sender Policy Framework) is an email authentication protocol that allows domain owners to specify which mail servers are permitted to send emails on their behalf. "
                "A PASS result indicates that the IP address of the sending server is listed in the domain's SPF record, suggesting the email is coming from an authorized source.",
            )
        )
    else:
        results.append(
            (
                "SPF",
                "❌",
                "SPF check failed. The sending server's IP address is not found in the domain's SPF record. This failure raises the possibility that the email is spoofed or unauthorized.",
            )
        )

    # DKIM Check
    dkim_result = headers.get("dkim", "").lower()
    if dkim_result == "pass":
        results.append(
            (
                "DKIM",
                "✅",
                "DKIM (DomainKeys Identified Mail) uses cryptographic signatures to verify that an email has not been tampered with. "
                "A PASS result indicates that the signature is valid, confirming both the email's integrity and the authenticity of the sender.",
            )
        )
    else:
        results.append(
            (
                "DKIM",
                "❌",
                "DKIM check failed. The DKIM signature is either missing or invalid, which could mean the email was altered or is not from the claimed sender.",
            )
        )

    # DMARC Check
    dmarc_result = headers.get("dmarc", "").lower()
    if dmarc_result == "pass":
        results.append(
            (
                "DMARC",
                "✅",
                "DMARC (Domain-based Message Authentication, Reporting & Conformance) builds on SPF and DKIM by allowing domain owners to publish policies for email authentication. "
                "A PASS result means the email aligns with the domain's DMARC policy, providing extra assurance of its legitimacy.",
            )
        )
    else:
        results.append(
            (
                "DMARC",
                "❌",
                "DMARC check failed. The email does not meet the domain's DMARC policy, which is a strong indicator that the email may be spoofed or improperly authenticated.",
            )
        )

    # From vs Return-Path Check
    from_addr = extract_email(headers.get("from", ""))
    return_path = headers.get("return_path", "")
    if from_addr and return_path and from_addr.lower() == return_path.lower():
        results.append(
            (
                "From / Return-Path",
                "✅",
                "The 'From' address matches the 'Return-Path'. This consistency suggests that the email's sender information is reliable and follows standard email practices.",
            )
        )
    else:
        results.append(
            (
                "From / Return-Path",
                "❌",
                "Mismatch between 'From' and 'Return-Path'. This discrepancy can be a red flag, indicating the possibility that the email has been spoofed.",
            )
        )

    # From vs Reply-To Check
    reply_to = extract_email(headers.get("reply_to", ""))
    if from_addr and reply_to and from_addr.lower() == reply_to.lower():
        results.append(
            (
                "From / Reply-To",
                "✅",
                "The 'From' and 'Reply-To' addresses match, ensuring that replies will be directed to the actual sender. This is a good sign of legitimacy.",
            )
        )
    else:
        results.append(
            (
                "From / Reply-To",
                "❌",
                "Mismatch between 'From' and 'Reply-To'. This inconsistency is often exploited in phishing attempts to redirect responses to an attacker.",
            )
        )

    return results


############################## Main GUI Application Class ##############################


class GoFishPhishy(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phishing! Catch and DON't Release")
        self.resize(900, 700)
        self.setup_ui()

    def setup_ui(self):
        # Create the main horizontal layout
        self.main_layout = QHBoxLayout(self)

        # Left side: Primary content
        self.content_layout = QVBoxLayout()

        # Results table
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(3)
        self.result_table.setHorizontalHeaderLabels(["Check", "Status", "Explanation"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.content_layout.addWidget(self.result_table)

        # Raw header text area (for drag-drop, file load, or copy-paste)
        self.raw_text = QTextEdit()
        self.raw_text.setPlaceholderText("Paste raw header text here...")
        self.raw_text.textChanged.connect(self.on_raw_text_changed)
        self.content_layout.addWidget(self.raw_text)

        # Load file button
        self.load_button = QPushButton("Load Email File")
        self.load_button.clicked.connect(self.load_file)
        self.content_layout.addWidget(self.load_button)

        # Sidebar toggle button
        self.sidebar_toggle_button = QPushButton("Show Tutorials")
        self.sidebar_toggle_button.clicked.connect(self.toggle_sidebar)
        self.content_layout.addWidget(self.sidebar_toggle_button)

        self.main_layout.addLayout(self.content_layout)

        # Right side: Sidebar for tutorials (initially hidden with width 0)
        self.sidebar = QWidget(self)
        self.sidebar.setFixedWidth(0)
        self.sidebar_layout = QVBoxLayout(self.sidebar)
        self.sidebar_layout.setContentsMargins(10, 10, 10, 10)

        # Tutorial buttons
        self.tutorial_button1 = QPushButton("Accessing Header Data Directly")
        self.tutorial_button1.clicked.connect(lambda: self.show_tutorial(1))
        self.sidebar_layout.addWidget(self.tutorial_button1)

        self.tutorial_button2 = QPushButton("Outlook Drag-and-Drop Limitations")
        self.tutorial_button2.clicked.connect(lambda: self.show_tutorial(2))
        self.sidebar_layout.addWidget(self.tutorial_button2)

        self.tutorial_button3 = QPushButton("Where to Find Email Files Locally")
        self.tutorial_button3.clicked.connect(lambda: self.show_tutorial(3))
        self.sidebar_layout.addWidget(self.tutorial_button3)

        # Tutorial content display area
        self.sidebar_content = QTextEdit()
        self.sidebar_content.setReadOnly(True)
        self.sidebar_layout.addWidget(self.sidebar_content)

        self.main_layout.addWidget(self.sidebar)

        # Apply modern styling for a fresh look
        self.setStyleSheet(
            """
            QWidget {
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3e8e41;
            }
            QTextEdit {
                border: 1px solid #ccc;
                padding: 8px;
                border-radius: 4px;
            }
            QTableWidget {
                border: 1px solid #ccc;
            }
            QHeaderView::section {
                background-color: #f2f2f2;
                padding: 4px;
                border: 1px solid #ddd;
            }
        """
        )

    def on_raw_text_changed(self):
        """
        When the raw header text area changes, attempt to process the data.
        """
        text = self.raw_text.toPlainText().strip()
        if text:
            headers = parse_email_headers(text)
            results = analyze_header_results(headers)
            self.update_table(results)
        else:
            self.result_table.setRowCount(0)

    def update_table(self, results):
        self.result_table.setRowCount(len(results))
        for row, (check, status, explanation) in enumerate(results):
            self.result_table.setItem(row, 0, QTableWidgetItem(check))
            status_item = QTableWidgetItem(status)
            status_item.setTextAlignment(Qt.AlignCenter)
            self.result_table.setItem(row, 1, status_item)
            self.result_table.setItem(row, 2, QTableWidgetItem(explanation))

    def load_file(self):
        """
        Opens a file dialog for the user to choose an email file.
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Email File", "", "Email Files (*.eml *.msg);;All Files (*)"
        )
        if file_path:
            self.parse_email_file(file_path, temporary=False)

    def parse_email_file(self, file_path, temporary: bool = False):
        """
        Parses an email file (.eml or .msg), extracts header text, and populates the raw text area.
        If 'temporary' is True, the file is deleted after processing.
        """
        try:
            if file_path.endswith(".eml"):
                with open(file_path, "rb") as eml_file:
                    msg = BytesParser(policy=policy.default).parse(eml_file)
                header_text = msg.as_string().split("\n\n", 1)[0]
            elif file_path.endswith(".msg"):
                msg = extract_msg.Message(file_path)
                msg.extract()
                header_text = msg.header
            self.raw_text.setText(header_text)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to parse email file:\n{str(e)}")
        finally:
            if temporary and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception as e:
                    QMessageBox.warning(
                        self, "Warning", f"Failed to delete temporary file:\n{str(e)}"
                    )

    def toggle_sidebar(self):
        """
        Animates the sidebar to slide in/out.
        """
        current_width = self.sidebar.width()
        target_width = 300 if current_width == 0 else 0
        self.animation = QPropertyAnimation(self.sidebar, b"maximumWidth")
        self.animation.setDuration(300)
        self.animation.setStartValue(current_width)
        self.animation.setEndValue(target_width)
        self.animation.start()

    def show_tutorial(self, tutorial_number):
        """
        Populates the sidebar content area with the selected tutorial.
        """
        if tutorial_number == 1:
            tutorial_text = """
            <h2>Accessing Header Data Directly</h2>
            <p>Learn how to access email header data from common email clients:</p>
            <ul>
                <li><b>Outlook:</b> Open an email, go to File &gt; Properties, and locate the Internet headers section.</li>
                <li><b>Apple Mail:</b> Open an email and select View &gt; Message &gt; All Headers or Raw Source.</li>
                <li><b>Gmail (Native App):</b> Open the email, click the three-dot menu, and choose "Show original".</li>
            </ul>
            <p>You can copy the raw header data from these interfaces and paste it into the text area for analysis.</p>
            """
        elif tutorial_number == 2:
            tutorial_text = """
            <h2>Outlook Drag-and-Drop Limitations</h2>
            <p style="color:red; font-weight:bold;">Important:</p>
            <p>Outlook handles email drag-and-drop differently. You cannot drag an email directly from Outlook unless it is saved as a .msg file first.</p>
            <p>This is due to how Outlook exposes email data in transit.</p>
            <ul>
                <li>For Outlook emails, consider using the "Save As" feature to save the email as a .msg file.</li>
                <li>Alternatively, you can drag and drop the email onto your desktop and Windows will automatically save it as a .msg file.</li>
            </ul>
            """
        elif tutorial_number == 3:
            tutorial_text = """
            <h2>Where to Find Email Files Locally</h2>
            <p>For non-tech-savvy users, finding email files can be challenging. Here are some tips:</p>
            <ul>
                <li><b>Apple Mail &amp; Gmail:</b> These clients typically do not store emails as separate files. You may need to use export tools or print to PDF.</li>
            </ul>
            <p>If you are unsure, use the drag-and-drop or copy-paste features instead.</p>
            """
        else:
            tutorial_text = "<p>No tutorial available.</p>"
        self.sidebar_content.setHtml(tutorial_text)


if __name__ == "__main__":
    # Enable high-DPI scaling
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)

    # Create the application
    app = QApplication(sys.argv)

    # Set a default font size for better readability
    font = QFont("Segoe UI", 12)  # Adjust the font size as needed
    app.setFont(font)

    # Launch the application
    window = GoFishPhishy()
    window.show()
    sys.exit(app.exec_())
