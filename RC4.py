import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog, QLineEdit, QHBoxLayout, QTextEdit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class FileEncryptionApp(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setGeometry(300, 300, 600, 600)
        self.setWindowTitle('Prosty Program PyQt5 - Szyfrowanie pliku')

        self.file_path = None
        self.key_input = QLineEdit(self)
        self.result_text_edit = QTextEdit(self)
        self.result_text_edit.setReadOnly(True)

        # Przycisk do wybierania pliku
        btn_select_file = QPushButton('Załącz plik', self)
        btn_select_file.clicked.connect(self.select_file)

        # Przycisk do szyfrowania pliku
        btn_encrypt = QPushButton('Szyfruj plik', self)
        btn_encrypt.clicked.connect(self.encrypt_file)

        # Przycisk do deszyfrowania pliku
        btn_decrypt = QPushButton('Deszyfruj plik', self)
        btn_decrypt.clicked.connect(self.decrypt_file)

        # Przyciski do otwierania plików
        btn_display_attached_file = QPushButton('Wyświetl plik załączony', self)
        btn_display_attached_file.clicked.connect(self.display_attached_file)

        btn_display_encrypted_file = QPushButton('Wyświetl zaszyfrowany plik', self)
        btn_display_encrypted_file.clicked.connect(self.display_encrypted_file)

        btn_display_decrypted_file = QPushButton('Wyświetl odszyfrowany plik', self)
        btn_display_decrypted_file.clicked.connect(self.display_decrypted_file)

        # Układ pionowy
        layout = QVBoxLayout()
        layout.addWidget(btn_select_file)
        layout.addWidget(self.key_input)
        layout.addWidget(btn_encrypt)
        layout.addWidget(btn_decrypt)

        # Układ poziomy dla trzech przycisków otwierania plików
        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(btn_display_attached_file)
        buttons_layout.addWidget(btn_display_encrypted_file)
        buttons_layout.addWidget(btn_display_decrypted_file)
        layout.addLayout(buttons_layout)

        layout.addWidget(self.result_text_edit)

        self.setLayout(layout)

    def select_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_dialog = QFileDialog()
        file_dialog.setOptions(options)
        file_dialog.fileSelected.connect(self.set_file_path)
        file_dialog.exec_()

    def set_file_path(self, file_path):
        self.file_path = file_path

    def encrypt_file(self):
        try:
            if self.file_path and self.file_path.lower().endswith(('.txt', '.hex')):
                key = self.key_input.text()
                try:
                    byte_key = bytes.fromhex(key)
                    with open(self.file_path, 'rb') as file:
                        plaintext_data = file.read()

                    encrypted_data = self.rc4_encrypt(byte_key, plaintext_data)

                    # Zapisz zaszyfrowane dane do pliku binarnego
                    with open("encrypted_file.hex", 'wb') as file:
                        file.write(encrypted_data)

                    print("Plik został pomyślnie zaszyfrowany!")
                except Exception as e:
                    print(f"Wartość nie jest w formacie HEX {e}")
            else:
                print("Nie wybrano pliku do zaszyfrowania lub plik nie ma rozszerzenia .txt.")
        except Exception as e:
            print(f"Wystąpił błąd podczas szyfrowania: {e}")

    def decrypt_file(self):
        try:
            if self.file_path and self.file_path.lower().endswith(('.hex', '.txt')):

                key = self.key_input.text()
                try:
                    byte_key = bytes.fromhex(key)
                    with open(self.file_path, 'rb') as file:
                        encrypted_data = file.read()

                    decrypted_data = self.rc4_decrypt(byte_key, encrypted_data)

                    # Zapisz zdeszyfrowane dane do pliku binarnego
                    with open("decrypted_file.txt", 'wb') as file:
                        file.write(decrypted_data)

                    print("Plik został pomyślnie deszyfrowany!")
                except Exception as E:
                    print(f"Wartość nie jest w formacie HEX {E}")
            else:
                print("Nie wybrano pliku do deszyfrowania lub plik nie ma rozszerzenia .hex.")
        except Exception as e:
            print(f"Wystąpił błąd podczas deszyfrowania: {e}")

    def display_attached_file(self):
        if self.file_path:
            try:
                with open(self.file_path, 'rb') as file:
                    file_content = file.read()

                    # Spróbuj odczytać jako 'utf-8'
                    try:
                        decoded_text = file_content.decode('utf-8')
                    except UnicodeDecodeError:
                        decoded_text = None

                    # Jeśli nie udało się odczytać jako 'utf-8', próbuj jako 'latin-1'
                    if decoded_text is None:
                        try:
                            decoded_text = file_content.decode('latin-1')
                        except UnicodeDecodeError:
                            decoded_text = None

                    if decoded_text is not None:
                        self.result_text_edit.setPlainText(decoded_text)
                        print(f"Plik {self.file_path} został otwarty.")
                    else:
                        print(f"Nie udało się zdekodować danych z pliku {self.file_path}.")
            except Exception as e:
                print(f"Błąd podczas otwierania pliku: {e}")
        else:
            print("Nie wybrano jeszcze pliku do wyświetlenia.")

    def display_encrypted_file(self):
        self.open_binary_file("encrypted_file.hex")

    def display_decrypted_file(self):
        self.open_file("decrypted_file.txt")

    def open_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                file_content = file.read()
                self.result_text_edit.setPlainText(file_content)
        except Exception as e:
            print(f"Błąd podczas otwierania pliku: {e}")

    def open_binary_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                file_content = file.read()
                self.result_text_edit.setPlainText(file_content.decode('latin-1'))
        except Exception as e:
            print(f"Błąd podczas otwierania pliku: {e}")

    def rc4_decrypt(self, key, ciphertext):
        cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    def rc4_encrypt(self, key, plaintext):
        cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

if __name__ == '__main__':
    app = QApplication(sys.argv)
    file_encryption_app = FileEncryptionApp()
    file_encryption_app.show()
    sys.exit(app.exec_())
