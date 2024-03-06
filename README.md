# RC4-encryption-program
RC4 encryption, decryption and image hiding program

Dokumentacja kodu 
Program komputerowy szyfrujący i deszyfrujący dowolne wiadomości
(pliki binarne dowolnej długości) za pomocą szyfru RC4 i ukrywający
kryptogram w pliku graficznym
Wprowadzenie
Program ten umożliwia użytkownikowi szyfrowanie i deszyfrowanie plików tekstowych oraz 
binarnych, a także ukrywanie i wyodrębnianie plików binarnych w obrazach przy użyciu steganografii.
Został napisany w języku Python, a bibliotekami wykorzystanymi w nim oprócz standardowych 
modułów są: PyQt5, Cryptography, PIL (Python Imaging Library). 
Opis interfejsu
Załącz plik – wybranie pliku z dysku komputera
Pole tekstowe – wpisanie n-bitowego klucza
Szyfruj plik – uruchomienie algorytmu szyfrującego pliki tekstowe/binarne
Deszyfruj plik – uruchomienie algorytmu deszyfrującego pliki tekstowe/binarne
Wyświetl plik załączony – podgląd zawartości określonego pliku
Wyświetl plik zaszyfrowany - wyświetlenie treści pliku zaszyfrowanego
Wyświetl plik odszyfrowany – wyświetlenie treści pliku odszyfrowanego
Załącz plik binarny – załączanie plików binarnych z rozszerzeniem .bin, .hex
Załącz plik graficzny - Załączanie plików graficznych z rozszerzeniami .jpg, .png 
Ukryj plik - ukrywanie pliku w obrazie, gdzie po ukryciu zapisuje plik do formatu .png 
Wyodrębnij plik z obrazu - wyodrębnianie pliku zaszyfrowanego bitowego z obrazu 
PyQt5
Jest to biblioteka odpowiedzialna za tworzenie interfejsów graficznych w języku Python, oparta na 
Qt. W programie używamy jej do stworzenia interfejsu użytkownika z przyciskami i polami 
tekstowymi opisanymi w poprzednim podpunkcie.
Metody odpowiedzialne za komponenty interfejsu:
- QApplication - mechanizm obsługi zdarzeń dla całej aplikacji.
- QWidget - bazowa klasa dla wszystkich elementów interfejsu użytkownika.
- QPushButton - przyciski do interakcji użytkownika.
- QVBoxLayout, QHBoxLayout - układy interfejsu do rozmieszczania elementów w pionie i poziomie.
- QfileDialog - okno dialogowe do wybierania plików.
Cryptography
Biblioteka cryptography służy do implementacji algorytmów kryptograficznych. Dzięki niej 
korzystamy z zaimplementowanych, gotowych rozwiązań, które konfigurujemy pod potrzeby naszego
programu. W naszym przypadku używamy jej do implementacji szyfrowania i deszyfrowania plików 
przy użyciu algorytmu RC4.
Metody kryptograficzne
- rc4_encrypt(key, plaintext) - Szyfruje dane przy użyciu algorytmu RC4.
- rc4_decrypt(key, ciphertext) - Deszyfruje dane przy użyciu algorytmu RC4.
PIL - Python Imaging Library
Biblioteka PIL pozwala na manipulację obrazami. W programie używamy jej do operacji 
steganograficznych - ukrywania i wyodrębniania danych w obrazach.
Metody steganograficzne
- action_hide_file() - ukrywa plik binarny w obrazie.
- action_unhide_file() - wyodrębnia ukryty plik binarny z obrazu.
Funkcje programu
1. Wybieranie pliku:
 - select_file() - otwiera okno dialogowe umożliwiające wybór pliku.
2. Szyfrowanie i Deszyfrowanie pliku:
 - encrypt_file() - szyfruje plik przy użyciu algorytmu RC4 i zapisuje zaszyfrowane dane do nowego 
pliku.
 - decrypt_file() - deszyfruje plik przy użyciu algorytmu RC4 i zapisuje zdeszyfrowane dane do 
nowego pliku.
3. Otwieranie plików:
 - display_attached_file() - wyświetla zawartość wybranego pliku tekstowego.
 - display_encrypted_file() - wyświetla zawartość zaszyfrowanego pliku.
 - display_decrypted_file() - wyświetla zawartość odszyfrowanego pliku.
4. Steganografia:
 - load_file_binary() - ładuje plik binarny do ukrycia.
 - load_cover_image() - ładuje obraz, w którym będą ukrywane dane.
 - action_hide_file() - ukrywa plik binarny w obrazie.
 - action_unhide_file() - wyodrębnia ukryty plik binarny z obrazu.
5. Obsługa Błędów:
 Program został zoptymalizowany pod kątem obsługi błędów, a komunikaty są wyświetlane w 
konsoli. Błędy które mogą występować w programie tyczą się głównie:
a) Błędy szyfrowania i deszyfrowania:
- w przypadku podania nieprawidłowego klucza (klucz nie w formacie HEX) podczas szyfrowania lub 
deszyfrowania
- gdy plik do zaszyfrowania nie istnieje lub nie ma odpowiedniego rozszerzenia
- gdy plik do deszyfrowania nie istnieje lub nie ma odpowiedniego rozszerzenia
 b) Błędy otwierania plików:
- Problem podczas otwierania pliku (np. plik uszkodzony)
- Niepowodzenie dekodowania pliku tekstowego (np. plik nie jest w kodowaniu 'utf-8' ani 'latin-1')
c) Błędy steganografii
 - Brak wystarczającej ilości pikseli do ukrycia danych, program poinformuje o tym błędzie i nie 
przeprowadzi operacji steganograficznej.
d) Błędy Ogólne:
- W przypadku innych nieprzewidzianych błędów, program wyświetli komunikat o błędzie z 
odpowiednim opisem.
Klucze:
Minimalne: 40 bitowe
Maksymalne: 256 bitowe
Klucz może mieć długość tylko i wyłącznie z podanego przedziału czyli 40, 56, 64, 80, 128, 192, 256 
bitów długości. 
 40 bitowy klucz = 5 bajtów = 10 znaków (HEX)
 56 bitowy klucz = 7 bajtów = 14 znaków (HEX)
 64 bitowy klucz = 8 bajtów = 16 znaków (HEX)
 80 bitowy klucz = 10 bajtów = 20 znaków (HEX)
 128 bitowy klucz = 16 bajtów = 32 znaki (HEX)
 192 bitowy klucz = 24 bajty = 48 znaków (HEX)
 256 bitowy klucz = 32 bajty = 64 znaki (HEX)
Podsumowanie:
Program integruje różne funkcje związane z kryptografią i steganografią, dostarczając prosty interfejs
użytkownika do obsługi tych operacji. Kod źródłowy składa się z funkcji które zawierają algorytmy
szyfrujące oraz ukrywające informacje w plikach graficznych oraz tzw. button-boxy podpięte pod te
funkcje, widoczne w interfejsie graficznym. Ogół programu skupia się na prostym do zrozumienia
interfejsie graficznym, tak aby nie komplikować korzystania z niego. W przypadku błędów, program
wyświetla stosowne komunikaty, a w przypadku powodzenia, informuje użytkownika o wykonanych
operacjach.
