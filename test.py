import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog, QLineEdit, QHBoxLayout, \
    QTextEdit, QLabel
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image


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

        # Przycisk do ukrywania pliku w obrazie
        btn_hide_in_image = QPushButton('Ukryj w obrazie', self)
        btn_hide_in_image.clicked.connect(self.hide_file_in_image)

        # Przycisk do wyodrębniania pliku z obrazu
        btn_extract_from_image = QPushButton('Wyodrębnij z obrazu', self)
        btn_extract_from_image.clicked.connect(self.extract_file_from_image)

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

        # Układ poziomy dla przycisków ukrywania i wyodrębniania w obrazie
        image_buttons_layout = QHBoxLayout()
        image_buttons_layout.addWidget(btn_hide_in_image)
        image_buttons_layout.addWidget(btn_extract_from_image)
        layout.addLayout(image_buttons_layout)

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


    def hide_file_in_image(self):
        file_path = self.file_path
        if not file_path:
            print("Nie wybrano pliku do ukrycia.")
            return

        try:
            steganography_app = SteganographyApp(file_path=file_path)
            if steganography_app.exec_() == SteganographyApp.Accepted:
                print("Dane zostały pomyślnie ukryte w obrazie.")
        except Exception as e:
            print(f"Wystąpił błąd: {e}")


    def extract_file_from_image(self):
        try:
            steganography_app = SteganographyApp(extract_mode=True)
            if steganography_app.exec_() == SteganographyApp.Accepted:
                print("Dane zostały pomyślnie wyodrębnione z obrazu.")
        except Exception as e:
            print(f"Wystąpił błąd: {e}")


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


class SteganographyApp(QWidget):
    def __init__(self, file_path=None, extract_mode=False):
        super().__init__()

        self.file_path = file_path
        self.extract_mode = extract_mode
        self.hidden_file_path = None
        self.cover_image_path = None

        self.initUI()

    def initUI(self):
        self.setGeometry(300, 300, 600, 400)
        self.setWindowTitle('Steganography App')

        self.file_path_label = QLabel('Plik:', self)
        self.image_path_label = QLabel('Obraz:', self)
        self.file_path_text = QTextEdit(self)
        self.image_path_text = QTextEdit(self)
        self.file_path_text.setReadOnly(True)
        self.image_path_text.setReadOnly(True)

        btn_load_file = QPushButton('Załaduj Plik', self)
        btn_load_file.clicked.connect(self.load_file)

        btn_load_image = QPushButton('Załaduj Obraz', self)
        btn_load_image.clicked.connect(self.load_image)

        btn_load_hidden_file = QPushButton('Załaduj Plik Ukrywany', self)
        btn_load_hidden_file.clicked.connect(self.load_hidden_file)

        btn_load_cover_image = QPushButton('Załaduj Obraz Ukrywający', self)
        btn_load_cover_image.clicked.connect(self.load_cover_image)

        btn_hide = QPushButton('Ukryj', self)
        btn_hide.clicked.connect(self.hide_data)

        btn_extract = QPushButton('Wyodrębnij', self)
        btn_extract.clicked.connect(self.extract_data)

        layout = QVBoxLayout()
        layout.addWidget(btn_load_file)
        layout.addWidget(self.file_path_label)
        layout.addWidget(self.file_path_text)
        layout.addWidget(btn_load_image)
        layout.addWidget(self.image_path_label)
        layout.addWidget(self.image_path_text)

        if not self.extract_mode:
            layout.addWidget(btn_load_hidden_file)
            layout.addWidget(btn_load_cover_image)
            layout.addWidget(btn_hide)

        layout.addWidget(btn_extract)

        self.setLayout(layout)


    def load_hidden_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Załaduj Plik Ukrywany", "",
                                                   "Wszystkie pliki (*);;Pliki tekstowe (*.txt);;Pliki binarne (*.bin)")
        if file_path:
            self.hidden_file_path = file_path
            self.file_path_text.setPlainText(file_path)

    def load_cover_image(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        image_path, _ = QFileDialog.getOpenFileName(self, "Załaduj Obraz Ukrywający", "",
                                                    "Pliki obrazów (*.png *.jpg *.bmp)")
        if image_path:
            self.cover_image_path = image_path
            self.image_path_text.setPlainText(image_path)

    def load_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Załaduj Plik", "",
                                                   "Wszystkie pliki (*);;Pliki tekstowe (*.txt);;Pliki binarne (*.bin)")
        if file_path:
            self.file_path_text.setPlainText(file_path)

    def load_image(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Załaduj Plik", "",
                                                   "Wszystkie pliki (*);;Pliki tekstowe (*.txt);;Pliki binarne (*.bin)")
        if file_path:
            self.file_path_text.setPlainText(file_path)

    def load_image(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        image_path, _ = QFileDialog.getOpenFileName(self, "Załaduj Obraz", "", "Pliki obrazów (*.png *.jpg *.bmp)")
        if image_path:
            self.image_path_text.setPlainText(image_path)

    def load_hidden_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Załaduj Plik Ukrywany", "",
                                                   "Wszystkie pliki (*);;Pliki tekstowe (*.txt);;Pliki binarne (*.bin)")
        if file_path:
            self.hidden_file_path = file_path
            self.file_path_text.setPlainText(file_path)

    def load_cover_image(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        image_path, _ = QFileDialog.getOpenFileName(self, "Załaduj Obraz Ukrywający", "",
                                                    "Pliki obrazów (*.png *.jpg *.bmp)")
        if image_path:
            self.cover_image_path = image_path
            self.image_path_text.setPlainText(image_path)

    def load_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Załaduj Plik", "",
                                                   "Wszystkie pliki (*);;Pliki tekstowe (*.txt);;Pliki binarne (*.bin)")
        if file_path:
            self.file_path_text.setPlainText(file_path)

    def hide_data(self):
        if not self.hidden_file_path or not self.cover_image_path:
            print("Załaduj plik ukrywany i obraz ukrywający przed ukryciem danych.")
            return

        try:
            # Wczytaj obraz
            img = Image.open(self.cover_image_path)

            # Wczytaj dane do ukrycia
            with open(self.hidden_file_path, 'rb') as file:
                data = file.read()

            # Konwertuj dane na listę bitów
            data_bits = [int(bit) for byte in data for bit in f"{byte:08b}"]

            # Ukryj dane w obrazie
            pixels = list(img.getdata())

            # Sprawdź, czy obraz ma wystarczającą ilość pikseli do ukrycia danych
            if len(pixels) < len(data_bits):
                print("Błąd: Obraz ma zbyt mało pikseli do ukrycia danych.")
                return

            for i in range(len(data_bits)):
                # Zmień najmniej znaczący bit w kanale czerwonym każdego piksela
                pixels[i] = (pixels[i][0] & 0b11111110) | data_bits[i]

            # Zapisz zmodyfikowany obraz
            img.putdata(pixels)
            img.save("output_image.png")

            print("Dane zostały pomyślnie ukryte w obrazie.")
        except Exception as e:
            print(f"Wystąpił błąd: {e}")

    def extract_data(self):
        image_path = self.image_path_text.toPlainText()

        if not image_path:
            return

        try:
            # Wczytaj obraz
            img = Image.open(image_path)

            # Wyodrębnij ukryte dane
            extracted_data_bits = [pixel[0] & 0b00000001 for pixel in img.getdata()]

            # Konwertuj bity na bajty
            extracted_bytes = bytes(
                [int("".join(map(str, extracted_data_bits[i:i + 8])), 2) for i in range(0, len(extracted_data_bits), 8)]
            )

            # Zapisz wyodrębnione dane do pliku
            with open("extracted_data.bin", 'wb') as file:
                file.write(extracted_bytes)

            print("Dane zostały pomyślnie wyodrębnione z obrazu.")
        except Exception as e:
            print(f"Wystąpił błąd: {e}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    file_encryption_app = FileEncryptionApp()
    file_encryption_app.show()
    sys.exit(app.exec_())

