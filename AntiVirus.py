import os
import requests 
import threading
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QTextEdit, QLabel, QMessageBox,QHBoxLayout
from PyQt5.QtCore import pyqtSignal, pyqtSlot
from dotenv import load_dotenv


# Load environment variables
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

class VirusTotalScanner(QWidget):

    appendResult = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.selected_path = ""
        self.initUI()
        
     

    def initUI(self):
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

        self.browse_button = QPushButton("Browse Folder", self)
        self.browse_button.clicked.connect(self.browse_folder)
        button_layout.addWidget(self.browse_button)

        self.scan_button = QPushButton("Scan Now", self)
        self.scan_button.clicked.connect(self.scan_folder)
        button_layout.addWidget(self.scan_button)

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
        if "clean" in result:
            colored_result = f'<font color="green">{result}</font>'
        elif "malicious" in result:
            colored_result = f'<font color="red">{result}</font>'
        else:
            colored_result = result

        self.result_text.append(colored_result)

        
    
    def clear_results(self):
        self.result_text.clear()
    
    
    def set_current_file_label(self, file_path):
        self.file_label.setText(f"Scanning: {file_path}") 
        QApplication.processEvents()
    
    
    def reset_current_file_label(self):
         self.file_label.setText("Scanning: None")
         
     
    
    def scan_file(self, file_path):
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
            QMessageBox.critical(self, "Error", f"Oops! Something went wrong: {err}")

    def get_report(self, scan_id):
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
            QMessageBox.critical(self, "Error", f"Oops! Something went wrong: {err}")

    def is_malicious(self, result):
        try:
            malicious_count = result['data']['attributes']['stats']['malicious']
            return malicious_count > 0

        except KeyError:
            return False

    
    def scan_folder_recursive(self, folder_path):
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
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        path = QFileDialog.getExistingDirectory(self, "Select Folder", "", options=options)
        if path:
            self.selected_path = path
            self.reset_current_file_label()
            self.append_result(f"Selected Folder: {path}")

    def scan_folder(self):
        if os.path.exists(self.selected_path):
            if os.path.isdir(self.selected_path):
                threading.Thread(target=self.scan_folder_recursive, args=(self.selected_path,)).start()
            else:
                threading.Thread(target=self.scan_file_and_display_result, args=(self.selected_path,)).start()
        else:
            QMessageBox.warning(self, "Warning", "Please select a valid folder.")
 
    def scan_file_and_display_result(self, file_path):
        self.set_current_file_label(file_path)
        scan_id = self.scan_file(file_path)
        self.reset_current_file_label()
        if scan_id:
            result = self.get_report(scan_id)
            if self.is_malicious(result):
                self.append_result(f"{file_path} is flagged as malicious!")
            else:
                self.append_result(f"{file_path} is clean.")
                    
if __name__ == '__main__':
    app = QApplication([])
    ex = VirusTotalScanner()
    ex.show()
    app.exec_()