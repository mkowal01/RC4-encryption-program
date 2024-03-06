import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QTextEdit
from PIL import Image

class SteganographyApp(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setGeometry(300, 300, 400, 200)
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
        layout.addWidget(btn_hide)
        layout.addWidget(btn_extract)

        self.setLayout(layout)

    def load_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Załaduj Plik", "", "Wszystkie pliki (*);;Pliki tekstowe (*.txt);;Pliki binarne (*.bin)")
        if file_path:
            self.file_path_text.setPlainText(file_path)

    def load_image(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        image_path, _ = QFileDialog.getOpenFileName(self, "Załaduj Obraz", "", "Pliki obrazów (*.png *.jpg *.bmp)")
        if image_path:
            self.image_path_text.setPlainText(image_path)

    def hide_data(self):
        file_path = self.file_path_text.toPlainText()
        image_path = self.image_path_text.toPlainText()

        if not file_path or not image_path:
            return

        try:
            # Wczytaj obraz
            img = Image.open(image_path)

            # Wczytaj dane do ukrycia
            with open(file_path, 'rb') as file:
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
                [int("".join(map(str, extracted_data_bits[i:i+8])), 2) for i in range(0, len(extracted_data_bits), 8)]
            )

            # Zapisz wyodrębnione dane do pliku
            with open("extracted_data.bin", 'wb') as file:
                file.write(extracted_bytes)

            print("Dane zostały pomyślnie wyodrębnione z obrazu.")
        except Exception as e:
            print(f"Wystąpił błąd: {e}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    steganography_app = SteganographyApp()
    steganography_app.show()
    sys.exit(app.exec_())
