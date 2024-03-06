import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QComboBox, QLineEdit, QVBoxLayout

class KeyGeneratorApp(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Key Generator')
        self.setGeometry(300, 300, 300, 200)

        self.key_size_label = QLabel('Wybierz rozmiar klucza:')
        self.key_size_combobox = QComboBox(self)
        self.key_size_combobox.addItem('40 bitowy klucz')
        self.key_size_combobox.addItem('56 bitowy klucz')
        self.key_size_combobox.addItem('64 bitowy klucz')
        self.key_size_combobox.addItem('80 bitowy klucz')
        self.key_size_combobox.addItem('128 bitowy klucz')
        self.key_size_combobox.addItem('192 bitowy klucz')
        self.key_size_combobox.addItem('256 bitowy klucz')

        self.key_entry_label = QLabel('Wprowadź klucz:')
        self.key_entry_field = QLineEdit(self)

        self.generate_button = QLabel('Generuj klucz')

        vbox = QVBoxLayout()
        vbox.addWidget(self.key_size_label)
        vbox.addWidget(self.key_size_combobox)
        vbox.addWidget(self.key_entry_label)
        vbox.addWidget(self.key_entry_field)
        vbox.addWidget(self.generate_button)

        self.setLayout(vbox)

        self.key_size_combobox.currentIndexChanged.connect(self.update_key_entry_field)
        self.key_entry_field.textChanged.connect(self.format_key)

    def update_key_entry_field(self):
        key_size = self.key_size_combobox.currentText().split()[0]
        max_length = int(key_size) * 2  # Each HEX character is 2 characters
        self.key_entry_field.setMaxLength(max_length)

    def format_key(self):
        cursor_position = self.key_entry_field.cursorPosition()
        current_text = self.key_entry_field.text()
        formatted_text = ' '.join(current_text[i:i+2] for i in range(0, len(current_text), 2))
        self.key_entry_field.setText(formatted_text)
        self.key_entry_field.setCursorPosition(cursor_position)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = KeyGeneratorApp()
    ex.show()
    sys.exit(app.exec_())
