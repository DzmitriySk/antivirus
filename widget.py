import hashlib
import os
from PySide6.QtWidgets import QApplication, QWidget, QPushButton, QFileDialog, QVBoxLayout, QLabel, QScrollArea
from smb.SMBConnection import SMBConnection

from fref import get_local_ip, get_gateway, get_mac_and_ips
from ui_form import Ui_Widget
import sys
import requests
import socket
import os
import subprocess
import nmap
import socket
import subprocess
import re
current_dir = os.path.dirname(__file__)

SHA256_HASHES_pack1 = (current_dir + '\\hard_signatures\\SHA256-Hashes_pack1.txt')
SHA256_HASHES_pack2 = (current_dir + '\\hard_signatures\\SHA256-Hashes_pack2.txt')
SHA256_HASHES_pack3 = (current_dir + '\\hard_signatures\\SHA256-Hashes_pack3.txt')


class Widget(QWidget):
    def __init__(self, api_key, parent = None):
        self.api_key = api_key
        super().__init__(parent)
        self.ui = Ui_Widget()
        self.ui.setupUi(self)

        # Connect the button's clicked signal to a custom slot
        self.ui.pushButton.clicked.connect(self.open_folder)
        self.ui.pushButton1.clicked.connect(self.open_folder)
        self.ui.pushButton2.clicked.connect(self.open_folder_api)
        self.ui.pushButton3.clicked.connect(self.scan)

    def scan(self):
        local_ip = get_local_ip()
        gateway = get_gateway()
        devices = get_mac_and_ips(local_ip, gateway)

        self.ui.verticalLayout.addWidget(QLabel(f"Local IP: {local_ip}"))
        self.ui.verticalLayout.addWidget(QLabel(f"Gateway: {gateway}"))
        self.ui.verticalLayout.addWidget(QLabel("Devices in network:"))
        for device in devices:
            self.ui.verticalLayout.addWidget(QLabel(f"IP: {device[0]}, MAC: {device[1]}"))

    def list_shared_resources(self, server_name, server_ip, username, password):
        conn = SMBConnection(username, password, '', server_name, use_ntlm_v2=True)
        if not conn.connect(server_ip, 139):
            print("Не удалось подключиться к серверу")
            return []  # Возвращаем пустой список, если подключение не удалось
        else:
            shared_files_list = []
            shares = conn.listShares()
            for share in shares:
                if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL']:
                    shared_files = conn.listPath(share.name, '/')
                    for shared_file in shared_files:
                        shared_files_list.append(
                            (share.name,
                             shared_file.filename))
            return shared_files_list
    @staticmethod
    def get_file_hash(file):
        with open(file, "rb") as f:
            bytes = f.read()
            return hashlib.sha256(bytes).hexdigest()

    def local_scan(self, file):
        results = []  # Создаем список для результатов
        try:
            # Отображаем имя файла
            file_label = QLabel(f"Сканирование файла: {file}")
            file_label.setStyleSheet("color: green")  # Устанавливаем цвет текста на зеленый
            self.ui.verticalLayout.addWidget(file_label)

            # Открываем файл и получаем хэш
            readable_hash = self.get_file_hash(file)

            # Отображаем хэш
            file_hash_label = QLabel("Хэш файла:  " + readable_hash)
            print(readable_hash)
            file_hash_label.setStyleSheet("color: green")  # Устанавливаем цвет текста на зеленый
            self.ui.verticalLayout.addWidget(file_hash_label)
            results.append("Хэш файла:  " + readable_hash)  # Добавляем хэш файла в список результатов

            # Проверяем, соответствует ли хэш какому-либо хэшу в списке хэшей вирусов
            virus_found = self.check_hash_in_list(readable_hash, SHA256_HASHES_pack1)

            if virus_found:
                virus_label = QLabel("Обнаружен вирус!")
                virus_label.setStyleSheet("color: red")  # Устанавливаем цвет текста на красный
                self.ui.verticalLayout.addWidget(virus_label)
                print("Обнаружен вирус!")
                delete_button = QPushButton("Удалить")
                delete_button.clicked.connect(lambda: self.delete_file(file))
                self.ui.verticalLayout.addWidget(delete_button)

            else:
                not_virus_label = QLabel("Вирусов не обнаружено")
                not_virus_label.setStyleSheet("color: green")  # Устанавливаем цвет текста на зеленый
                self.ui.verticalLayout.addWidget(not_virus_label)
                print("Вирусов не обнаружено!")
                delete_button = QPushButton("Удалить")
                delete_button.clicked.connect(lambda: self.delete_file(file))
                self.ui.verticalLayout.addWidget(delete_button)

        except PermissionError as e:
            exception_system_label = QLabel(f"Ошибка при сканировании системного файла {file}: {e}")
            exception_system_label.setStyleSheet("color: red")  # Устанавливаем цвет текста на красный
            self.ui.verticalLayout.addWidget(exception_system_label)
            pass  # Игнорируем ошибки доступа

        except Exception as e:
            exception_label = QLabel(f"Ошибка при сканировании файла {file}: {e}")
            exception_label.setStyleSheet("color: red")  # Устанавливаем цвет текста на красный
            self.ui.verticalLayout.addWidget(exception_label)
            print(f"Ошибка при сканировании файла {file}: {e}")

        return results  # Возвращаем список результатов

    def api_scan(self, file):
        results = []  # Создаем список для результатов
        try:
            # Проверяем, существует ли файл
            if not os.path.exists(file):
                print(f"Файл {file} не существует!!")
                return results

            # Открываем файл и получаем хэш
            readable_hash = self.get_file_hash(file)

            # Здесь мы добавляем проверку через VirusTotal
            params = {'apikey': self.api_key, 'resource': readable_hash}
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            json_response = response.json()
            if json_response['response_code']:
                positives = json_response['positives']
                if positives:
                    virus_label = QLabel(f"Обнаружен вирус! VirusTotal нашел {positives} совпадений.")
                    virus_label.setStyleSheet("color: red")  # Устанавливаем цвет текста на красный
                    self.ui.verticalLayout.addWidget(virus_label)
                    print(f"Обнаружен вирус! VirusTotal нашел {positives} совпадений.")
                else:
                    not_virus_label = QLabel("Вирусов не обнаружено")
                    not_virus_label.setStyleSheet("color: green")  # Устанавливаем цвет текста на зеленый
                    self.ui.verticalLayout.addWidget(not_virus_label)
                    print("Вирусов не обнаружено!")
        except PermissionError as e:
            exception_system_label = QLabel(f"Ошибка при сканировании системного файла {file}: {e}")
            exception_system_label.setStyleSheet("color: red")  # Устанавливаем цвет текста на красный
            self.ui.verticalLayout.addWidget(exception_system_label)
            pass  # Игнорируем ошибки доступа

        except Exception as e:
            exception_label = QLabel(f"Ошибка при сканировании файла {file}: {e}")
            exception_label.setStyleSheet("color: red")  # Устанавливаем цвет текста на красный
            self.ui.verticalLayout.addWidget(exception_label)
            print(f"Ошибка при сканировании файла {file}: {e}")

        return results  # Возвращаем список результатов



    @staticmethod
    def check_hash_in_list(hash_to_check, hash_list_file):
        with open(hash_list_file, 'r') as f:
            lines = [line.rstrip() for line in f]
            for line in lines:
                if hash_to_check == line.split(";")[0]:
                    return True  # Вирус обнаружен
        return False  # Вирус не обнаружен

    def open_folder(self):
        # Open a file dialog to select a folder
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder", "", QFileDialog.ShowDirsOnly)

        # Clear the scroll area
        self.clear_scroll_area()

        # Display the selected folder path
        folder_label = QLabel(f"Selected folder: {folder_path}")
        self.ui.verticalLayout.addWidget(folder_label)

        # Check if the selected folder is a local path or an SMB path
        if folder_path.startswith("\\\\"):
            # It's an SMB path, so scan the shared files
            shared_files_list = self.list_shared_resources('DESKTOP-LJHBNA4', '192.168.100.23', 'dimasiks', '1234')
            for share_name, file_name in shared_files_list:
                file_path = f"\\\\{share_name}\\{file_name}"
                self.local_scan(file_path)  # Pass the SMB file path to the scan method
                file_label = QLabel(f"SMB File: {share_name}/{file_name}")
                self.ui.verticalLayout.addWidget(file_label)
        else:
            # It's a local path, so proceed with local file scanning
            # Get the list of files in the selected folder
            try:
                file_list = os.listdir(folder_path)
            except PermissionError as e:
                error_label = QLabel(f"Permission denied: {folder_path}")
                self.ui.verticalLayout.addWidget(error_label)
                print(f"Permission denied: {folder_path}")
                return

            for filename in file_list:
                filepath = os.path.join(folder_path, filename)
                if os.path.isfile(filepath):
                    try:
                        self.local_scan(filepath)  # Pass the local file path to the scan method
                        file_label = QLabel(filename)
                        self.ui.verticalLayout.addWidget(file_label)
                    except Exception as e:
                        error_label = QLabel(f"Error processing file {filename}: {e}")
                        self.ui.verticalLayout.addWidget(error_label)
                        print(f"Error processing file {filename}: {e}")

    def open_folder_api(self):
        # Open a file dialog to select a folder
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder", "", QFileDialog.ShowDirsOnly)

        # Clear the scroll area
        self.clear_scroll_area()

        # Display the selected folder path
        folder_label = QLabel(f"Selected folder: {folder_path}")
        self.ui.verticalLayout.addWidget(folder_label)

        # Check if the selected folder is a local path or an SMB path
        if folder_path.startswith("\\\\"):
            # It's an SMB path, so scan the shared files
            shared_files_list = self.list_shared_resources('DESKTOP-LJHBNA4', '192.168.100.23', 'dimasiks', '1234')
            for share_name, file_name in shared_files_list:
                file_path = f"\\\\{share_name}\\{file_name}"
                self.api_scan(file_path)  # Pass the SMB file path to the scan method
                file_label = QLabel(f"SMB File: {share_name}/{file_name}")
                self.ui.verticalLayout.addWidget(file_label)
        else:
            # It's a local path, so proceed with local file scanning
            # Get the list of files in the selected folder
            try:
                file_list = os.listdir(folder_path)
            except PermissionError as e:
                error_label = QLabel(f"Permission denied: {folder_path}")
                self.ui.verticalLayout.addWidget(error_label)
                print(f"Permission denied: {folder_path}")
                return

            for filename in file_list:
                filepath = os.path.join(folder_path, filename)
                if os.path.isfile(filepath):
                    try:
                        self.api_scan(filepath)  # Pass the local file path to the scan method
                        file_label = QLabel(filename)
                        self.ui.verticalLayout.addWidget(file_label)
                    except Exception as e:
                        error_label = QLabel(f"Error processing file {filename}: {e}")
                        self.ui.verticalLayout.addWidget(error_label)
                        print(f"Error processing file {filename}: {e}")

    def scan_network():
        # Получение локального IP-адреса
        local_ip = socket.gethostbyname(socket.gethostname())
        print(f"Локальный IP-адрес: {local_ip}")

        # Получение шлюза
        gateway = os.popen("ipconfig | findstr /i \"Default Gateway\"").read().split(":")[-1].strip()
        print(f"Шлюз: {gateway}")

        # Сканирование устройств в сети
        try:
            output = subprocess.check_output(["arp", "-a"]).decode("utf-8")
            lines = output.split("\n")
            for line in lines:
                if "Interface" in line or "Internet Address" in line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip_address = parts[0]
                    mac_address = parts[1]
                    print(f"Устройство: IP = {ip_address}, MAC = {mac_address}")
        except subprocess.CalledProcessError:
            print("Не удалось выполнить сканирование сети.")

    def clear_scroll_area(self):
        # Clear the scroll area
        for i in reversed(range(self.ui.verticalLayout.count())):
            widget = self.ui.verticalLayout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()
    def delete_file(self, file):
        try:
            os.remove(file)
            print(f"Файл {file} успешно удален.")
        except Exception as e:
            print(f"Ошибка при удалении файла {file}: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    widget = Widget('910edebee81fc024938f8f80f4831ab9d229b062707d895ae71697392755c6e8')
    widget.show()
    sys.exit(app.exec())
