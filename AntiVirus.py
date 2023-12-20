import os
import threading

import requests
from dotenv import load_dotenv
from PyQt5.QtCore import pyqtSignal, pyqtSlot
from PyQt5.QtWidgets import (QApplication, QFileDialog, QHBoxLayout, QLabel, 
                             QMessageBox, QPushButton, QTextEdit, QVBoxLayout,
                             QWidget, QComboBox)

# Load environment variables
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


class VirusTotalScanner(QWidget):

    # Signal emitted to append result to the UI
    appendResult = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.selected_path = ""
        self.initUI()
            # Theme methods 
    def set_dark_theme(self):
        self.stylesheet = """
            QWidget {
                background-color: #232323;
                color: #fff; 
            }
        """
        self.setStyleSheet(self.stylesheet)

    def set_light_theme(self):
        self.stylesheet = """
            QWidget {
                background-color: #fff;
                color: #000; 
            }
        """
        self.setStyleSheet(self.stylesheet)
        
    def set_blue_theme(self):
        self.stylesheet = """
            QWidget {
                background-color: #45aaf2;
                color: #fff;
            }
        """
        self.setStyleSheet(self.stylesheet)

    def set_green_theme(self):
        self.stylesheet = """
            QWidget {
                background-color: #86BB71;
                color: #232323;
            }
        """
        self.setStyleSheet(self.stylesheet)
        
    def change_theme(self, index):
        if index == 0:
            self.set_dark_theme()
        elif index == 1:
            self.set_light_theme() 
        elif index == 2:
            self.set_blue_theme()
        else:
            self.set_green_theme()

    def initUI(self):
        """
        Initialize the user interface of the application.
        """
        self.setWindowTitle("VirusTotal File Scanner")
        self.setGeometry(100, 100, 600, 400)
        # Set dark mode
        dark_style = """
        QWidget {
            background-color: #232323;
            color: #fff;
        }

        /* Set color for other widgets */
        """

        self.setStyleSheet(dark_style)


        layout = QVBoxLayout()


        button_layout = QHBoxLayout()

                # Theme combo box
        self.theme_combo = QComboBox(self)
        self.theme_combo.addItems(["Dark", "Light", "Blue", "Green"])
        self.theme_combo.setFixedWidth(100)

        layout.addWidget(self.theme_combo) 

        self.theme_combo.activated.connect(self.change_theme)



        self.browse_button = QPushButton("Browse Folder", self)
        self.browse_button.clicked.connect(self.browse_folder)
        button_layout.addWidget(self.browse_button)

        self.scan_button = QPushButton("Scan Now", self)
        self.scan_button.clicked.connect(self.scan_folder)
        button_layout.addWidget(self.scan_button)

        self.select_files_button = QPushButton("Scan Files", self)
        self.select_files_button.clicked.connect(self.select_files)
        button_layout.addWidget(self.select_files_button)

        self.clear_button = QPushButton("Clear", self)
        self.clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_button)

        layout.addLayout(button_layout)

        self.file_label = QLabel("Scanning: None", self)
        layout.addWidget(self.file_label)

        self.result_text = QTextEdit(self)
        layout.addWidget(self.result_text)

        self.setLayout(layout)

        # Connect signal
        self.appendResult.connect(self.append_result)

    @pyqtSlot(str)
    def append_result(self, result):
        """
        Append the result to the result_text QTextEdit widget.

        Args:
            result (str): The result to be appended.
        """
        if "clean" in result:
            colored_result = f'<font color="green">{result}</font>'
        elif "malicious" in result:
            colored_result = f'<font color="red">{result}</font>'
        else:
            colored_result = result

        self.result_text.append(colored_result)

    def clear_results(self):
        """
        Clear the result_text QTextEdit widget.
        """
        self.result_text.clear()

    def set_current_file_label(self, file_path):
        """
        Set the text of the file_label QLabel widget to the current file path being scanned.

        Args:
            file_path (str): The file path being scanned.
        """
        self.file_label.setText(f"Scanning: {file_path}")
        QApplication.processEvents()

    def reset_current_file_label(self):
        """
        Reset the text of the file_label QLabel widget to "Scanning: None".
        """
        self.file_label.setText("Scanning: None")

    def scan_file(self, file_path):
        """
        Scan a single file using the VirusTotal API.

        Args:
            file_path (str): The path of the file to scan.

        Returns:
            str: The scan ID of the file.

        Raises:
            requests.exceptions.HTTPError: If there is an HTTP error.
            requests.exceptions.ConnectionError: If there is an error connecting.
            requests.exceptions.Timeout: If there is a timeout error.
            requests.exceptions.RequestException: If there is any other request exception.
        """
        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "accept": "application/json",
            'x-apikey': VIRUSTOTAL_API_KEY
        }

        try:
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file)}
                response = requests.post(url, headers=headers, files=files)

            response.raise_for_status()
            result = response.json()
            scan_id = result['data']['id']
            return scan_id

        except requests.exceptions.HTTPError as errh:
            QMessageBox.critical(self, "Error", f"HTTP Error: {errh}")
        except requests.exceptions.ConnectionError as errc:
            QMessageBox.critical(self, "Error", f"Error Connecting: {errc}")
        except requests.exceptions.Timeout as errt:
            QMessageBox.critical(self, "Error", f"Timeout Error: {errt}")
        except requests.exceptions.RequestException as err:
            QMessageBox.critical(
                self, "Error", f"Oops! Something went wrong: {err}")

    def get_report(self, scan_id):
        """
        Get the scan report for a given scan ID using the VirusTotal API.

        Args:
            scan_id (str): The scan ID of the file.

        Returns:
            dict: The scan report.

        Raises:
            requests.exceptions.HTTPError: If there is an HTTP error.
            requests.exceptions.ConnectionError: If there is an error connecting.
            requests.exceptions.Timeout: If there is a timeout error.
            requests.exceptions.RequestException: If there is any other request exception.
        """
        url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        headers = {
            "accept": "application/json",
            'x-apikey': VIRUSTOTAL_API_KEY
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            report = response.json()
            return report
        except requests.exceptions.HTTPError as errh:
            QMessageBox.critical(self, "Error", f"HTTP Error: {errh}")
        except requests.exceptions.ConnectionError as errc:
            QMessageBox.critical(self, "Error", f"Error Connecting: {errc}")
        except requests.exceptions.Timeout as errt:
            QMessageBox.critical(self, "Error", f"Timeout Error: {errt}")
        except requests.exceptions.RequestException as err:
            QMessageBox.critical(
                self, "Error", f"Oops! Something went wrong: {err}")

    def is_malicious(self, result):
        """
        Check if the scan result is flagged as malicious.

        Args:
            result (dict): The scan result.

        Returns:
            bool: True if the result is malicious, False otherwise.
        """
        try:
            malicious_count = result['data']['attributes']['stats']['malicious']
            return malicious_count > 0

        except KeyError:
            return False

    def scan_folder_recursive(self, folder_path):
        """
        Recursively scan all files in a folder.

        Args:
            folder_path (str): The path to the folder.
        """
        for root, dirs, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                # Emit signal to update UI
                self.appendResult.emit(f"Scanning: {file_path}")

                scan_id = self.scan_file(file_path)
                if scan_id:
                    result = self.get_report(scan_id)
                    if self.is_malicious(result):
                        self.appendResult.emit(f"{file_name} is malicious!")
                    else:
                        self.appendResult.emit(f"{file_name} is clean")

    def browse_folder(self):
        """
        Open a file dialog to select a folder.
        """
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        path = QFileDialog.getExistingDirectory(
            self, "Select Folder", "", options=options)
        if path:
            self.selected_path = path
            self.reset_current_file_label()
            self.append_result(f"Selected Folder: {path}")

    def scan_folder(self):
        """
        Scan the selected folder.
        """
        if os.path.exists(self.selected_path):
            if os.path.isdir(self.selected_path):
                threading.Thread(target=self.scan_folder_recursive,
                                 args=(self.selected_path,)).start()
            else:
                pass
        else:
            QMessageBox.warning(
                self, "Warning", "Please select a valid folder.")

    def select_files(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select Files", "", "All Files (*);;", options=options)
        if files:
            self.selected_files = files
            self.scan_files()
    def scan_files(self):
        for file_path in self.selected_files:
            self.set_current_file_label(file_path)
            scan_id = self.scan_file(file_path)
            if scan_id:
                result = self.get_report(scan_id)
                if self.is_malicious(result):
                    self.appendResult.emit(f"{file_path} is malicious!") 
                else:
                    self.appendResult.emit(f"{file_path} is clean")
        self.reset_current_file_label()

if __name__ == '__main__':
    app = QApplication([])
    ex = VirusTotalScanner()
    ex.show()
    app.exec_() 
