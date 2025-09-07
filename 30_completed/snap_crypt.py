#from PyInstaller.utils.hooks import collect_submodules
#hiddenimports = collect_submodules('pyautogui')
#pyinstaller --name snap_crypt_Q --onefile --noupx --noconsole --icon=.\30_completed\snap_crypt_icon.ico --hidden-import=pyscreeze --hidden-import=pillow --hidden-import=numpy --exclude-module=pwd --exclude-module=grp --exclude-module=fcntl --exclude-module=termios --exclude-module=PyQt5 snap_crypt.py

pyQT = True
MENU_RUN = False
Multi_Display = True

import sys
import PyInstaller.__main__
if "--build" in sys.argv:
#python snap_crypt.py --build
    PyInstaller.__main__.run([
        __file__,  # 현재 실행 중인 파일
        '--name', 'snap_crypt_Q_mu', '--noconsole',
#        '--name=snap_crypt_alt_single', 
#        '--name=snap_crypt_menu_single', 
        '--onefile', '--noupx', '--icon=.\\30_completed\\snap_crypt_icon.ico',
        '--hidden-import=pyscreeze', '--hidden-import=pillow', '--hidden-import=numpy',
        '--exclude-module=pwd', '--exclude-module=grp', '--exclude-module=fcntl', '--exclude-module=termios', '--exclude-module=PyQt5'
    ])
    sys.exit()

from pynput import keyboard   #pip install pynput pywin32 pyMeow
from cryptography.hazmat.primitives import hashes    #pip install cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QInputDialog, QListWidget, QListWidgetItem #pip install pyQT6
from PyQt6.QtGui import QColor
from PyQt6.QtCore import Qt
from screeninfo import get_monitors
from PIL import Image

from datetime import datetime

import pyautogui as p  #pip install pyautogui, pip install pyscreenshot, pip install pyscreeze pillow
import time
import os
import sys
import io
import base64
import json
import glob
import threading
import pwinput #pip install pwinput
import mss
import mss.tools
import ctypes

delimeter = f'{"-" * 55}'
class Capture_Encrypt_Decrypt():
    def __init__(self):
        self.display_number=0
        self.display = {"left": 0, "top": 0, "width": 0, "height": 0}
        monitors = get_monitors()
        monitor = monitors[self.display_number]
        self.display["left"] = monitor.x
        self.display["top"] = monitor.y
        self.display["width"] = monitor.width
        self.display["height"] = monitor.height
        self.control_key_pressed_dic = {"shift_key": False, "alt_key": False, "ctrl_key": False}
        self.alt_key_pressed_dic = {'c': False, 'd': False, 's': False, 'q': False}
        self.capture_file = None
        self.jason_file = None
        self.key = None
        self.salt = None
        self.cipher = None
        self.wait_timer_sec = 60
        self.total_timeout_sec = self.wait_timer_sec * 20
        self.semaphore_timeout_flag = False
        self.dest_dir = os.path.join(os.getcwd(), 'snapshots')
        self.log_file = os.path.join(self.dest_dir, 'snap_crypt_log.txt')
        if not os.path.exists(self.dest_dir):
            os.makedirs(self.dest_dir)
        self.get_key_from_user()
        self.previous_time = time.time()
        self.timer_event_set()
        self.log_log(f'--- Program Start')

    def timer_event_set(self):
        self.timer_event = threading.Event()
        self.exit_thread = threading.Thread(target=self.wait_and_exit)
        self.exit_thread.daemon = True  # 프로그램 종료 시 스레드도 종료되도록 설정
        self.exit_thread.start()  # 스레드 시작

    def wait_and_exit(self):
        while True:
            self.timer_event.wait(self.wait_timer_sec)
            if time.time() - self.previous_time > self.total_timeout_sec:
                self.semaphore_timeout_flag = True
                self.timer_event.clear()

    def get_key_from_user(self):
        unuseful_key_value = True
        if pyQT:
            while unuseful_key_value:
                self.key, ok = QInputDialog.getText(mywindow, "키 입력", "키를 입력하세요.", QLineEdit.EchoMode.Password)
                self.key = self.key.encode()
                if ok and self.key:
                    break
        else:
            while unuseful_key_value:
                self.key = pwinput.pwinput("Enter Secret key: ", mask="*").encode()
                if self.key:
                    break

    def make_key_ciper(self, salt): # PBKDF2HMAC을 사용하여 입력 키에서 32바이트 길이의 키 도출
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt = salt, iterations=1000)
        key = base64.urlsafe_b64encode(kdf.derive(self.key))  # 키 도출 및 base64 인코딩
        self.cipher = Fernet(key)

    def check_directory(self):
        if not os.path.exists(self.dest_dir):
            os.makedirs(self.dest_dir)

    def decrypt_file(self, encrypted_jason_file) -> bool:
        try:
            salt_from_jason = base64.b64decode(encrypted_jason_file["salt"].encode())  # base64로 인코딩된 salt 복원
            encrypted_data_from_jason = base64.b64decode(encrypted_jason_file["Encrypted Image"].encode())  # 암호화된 메시지 복원
            self.make_key_ciper(salt_from_jason)
            decrypted_file_data = self.cipher.decrypt(encrypted_data_from_jason)
            self.check_directory()
            with open(f'{self.capture_file}', "wb") as file:
                file.write(decrypted_file_data)
            return True
        except Exception as e:
            return False

    def decrypt_all_files(self):
        file_names = glob.glob(os.path.join(self.dest_dir, "*.json"))  
        for i in range(len(file_names)):
            self.jason_file = file_names[i]
            self.capture_file = self.jason_file.replace(".json", "_dec.png")
            self.check_directory()
            with open(self.jason_file, "r") as f:
                encrypted_data_from_jason = json.load(f)
            if self.decrypt_file(encrypted_data_from_jason):
                self.log_log(f"{delimeter}\n!!! Decryption success\n    * {self.jason_file}\n      -> {self.capture_file}\n{delimeter}", True)
            else:
                self.log_log(f"{delimeter}\n!!! Invalid key\n    * {self.jason_file}\n{delimeter}", True)

    def encrypt_data(self, data_bytes: bytes = None, data_from_file: str = None) -> bytes:
        self.salt = os.urandom(16)  # # salt를 생성 (매번 새로 생성해야 함)
        self.make_key_ciper(self.salt)
        self.check_directory()
        if data_from_file:
            with open(data_from_file, "rb") as f:
                data_bytes = f.read()
        encrypted_data = self.cipher.encrypt(data_bytes)
        return encrypted_data

    def menu_display(self) -> None:
#        command = "cls" if sys.platform.startswith("win") else "clear"
#        os.system(command)
        if MENU_RUN:
            print(f"\n\n{delimeter}\n- {self.total_timeout_sec/60:.0f}분 동안 스크린 캡처나 복호화가 없으면 자동 종료")
            print(f"- 'c' : 스크린 캡처후 암호 저장")
            print(f"- 'd' : 저장된 캡처 화일중 키가 일치하는 화일 복호")
            print(f"- 'k' : 암복호 키 변경")
            if Multi_Display:
                print(f"- 's' : 캡처 디스플레이 변경(현재 디스플레이 = {self.display_number + 1})")
            print(f"- 'q' : 종료\n{delimeter}")
            return(input("원하시는 서비스를 입력하세요 : "))
        else:
            print(f"\n\n{delimeter}\n* {self.total_timeout_sec/60:.0f}분 동안 스크린 캡처나 복호화가 없으면 자동 종료")
            print(f"* 'alt-c' : 스크린 캡처후 암호 저장")
            print(f"* 'alt-d' : 저장된 암호 화일중 키가 일치하는 화일 복호")
            if Multi_Display:
                print(f"* 'alt-s' : 캡처 tmzmfls 변경(현재 디스플레이 = {self.display_number + 1})")
            print(f"* 'alt-q' : 종료\n{delimeter}")
            return ""

    def change_display(self):
        monitors = get_monitors()
        old_display_number = self.display_number 
        self.display_number = ((self.display_number + 1) % len(monitors))
        monitor = monitors[self.display_number]
        self.display["left"] = monitor.x
        self.display["top"] = monitor.y
        self.display["width"] = monitor.width
        self.display["height"] = monitor.height
        self.log_log(f"{delimeter}\n!!! Change Capturing Display \n    * Display {old_display_number + 1} -> Display {self.display_number + 1}\n{delimeter}")
        return old_display_number

    def get_display_info(self):
        monitors = get_monitors()
        for m in monitors:
            width, height = m.width, m.height
            hdc = ctypes.windll.user32.GetDC(0)
            dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)  # LOGPIXELSX
            scale = dpi / 96 * 100  # 기본 DPI(96) 기준 배율 계산
            ctypes.windll.user32.ReleaseDC(0, hdc)
            self.log_log(f"{delimeter}\n디스플레이 해상도: {width} x {height} / DPI 배율: {scale:.0f}%\n{delimeter}")

    def get_dpi_scale(self):
        hdc = ctypes.windll.user32.GetDC(0)
        dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)  # 88은 HORZSIZE
        ctypes.windll.user32.ReleaseDC(0, hdc)
        return dpi / 96  # 96 DPI는 기본 DPI

    def capture_display(self):
#       p.screenshot(self.capture_file)  # 전체 화면 Capture & 파일로 저장
#       os.remove(self.capture_file)
#        screen_shot_image = p.screenshot() # 전체 화면 Capture
#        screen_shot_image = ImageGrab.grab(bbox=(self.display["left"], self.display["top"], self.display["left"] + self.display["width"], self.display["top"] + self.display["height"]))
#        with io.BytesIO() as image_bytes_array:
#            screen_shot_image.save(image_bytes_array, format='PNG')
#            return image_bytes_array.getvalue()
#        image_bytes_array = io.BytesIO()   #memory 에서 open
#        screen_shot_image.save(image_bytes_array, format='png')
#        image_bytes_array.seek(0)
#        image_data = image_bytes_array.read()
#        return image_data
#        self.display["left"], self.display["top"], self.display["left"] + self.display["width"], self.display["top"] + self.display["height"]

        monitor = {"left": self.display["left"], "top": self.display["top"], "width": self.display["left"] + self.display["width"], "height": self.display["top"] + self.display["height"]}

        self.get_display_info()
        ctypes.windll.user32.SetProcessDPIAware() # DPI awareness 설정

        dpi_scale = self.get_dpi_scale() # DPI 배율 계산
        with mss.mss() as sct:
            screenshot = sct.grab(sct.monitors[self.display_number + 1])  #0 = 전체 모니터
        screen_shot_image = Image.frombytes("RGB", screenshot.size, screenshot.rgb) #RGB 데이터를 PIL 이미지로 변환
        new_size = (int(screen_shot_image.width / dpi_scale), int(screen_shot_image.height / dpi_scale)) # DPI 배율에 맞춰 이미지 크기 조정 (배율에 맞게 리사이즈)
        screen_shot_image = screen_shot_image.resize(new_size, Image.LANCZOS)
#        screen_shot_image.show() # 이미지 보여주기
        with io.BytesIO() as image_bytes_array: # 메모리에서 PNG로 저장
            screen_shot_image.save(image_bytes_array, format="PNG")
            return image_bytes_array.getvalue()  # PNG 바이트 데이터 반환
       
    def save_encrypted_data_2_file(self, salt: bytes, encrypted_data: bytes, file_name: str):
        data_to_store_4_jason = {
            "salt": base64.b64encode(salt).decode(),  # salt를 base64로 인코딩하여 저장
            "Encrypted Image": base64.b64encode(encrypted_data).decode()  # 암호화된 메시지를 Base64로 인코딩하여 저장
        }
        self.check_directory()
        with open(f'{file_name}', "w") as f:
            json.dump(data_to_store_4_jason, f)

    def log_log(self, message: str, display_on = False) -> None:
        log_message = f'{datetime.now().strftime("%Y%m%d_%H%M%S")} : {message}'
        self.check_directory()
        with open(self.log_file, "a", encoding="utf-8", buffering = 1) as f:
            f.write(f'{log_message}\n')
        if pyQT:
            mywindow.append_text(f'{message}')
        else:
            if display_on:
                print(f'{message}')

    def is_admin(self) -> int:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux, Mac
            return os.geteuid() == 0

    def check_semaphore_timeout_flag(self) -> None:
        if self.semaphore_timeout_flag:
            self.log_log(f"--- Program Exit by Timer", True)
            sys.exit(-1)

    def on_release(self, key):
        if hasattr(key, 'char'): 
            key_char = key.char.lower()
            if key_char in self.alt_key_pressed_dic:
                self.alt_key_pressed_dic[key_char] = False
        elif key == keyboard.Key.alt_l or key == keyboard.Key.alt_r:
            self.control_key_pressed_dic["alt_key"] = False
        elif key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
            self.control_key_pressed_dic["ctrl_key"] = False
        elif key == keyboard.Key.shift_l or key == keyboard.Key.shift_r:
            self.control_key_pressed_dic["shift_key"] = False

    def on_press(self, key):
        self.check_semaphore_timeout_flag()
        try:
            if (not self.control_key_pressed_dic["alt_key"]):
                if key in {keyboard.Key.alt_l, keyboard.Key.alt_r}:
                    self.control_key_pressed_dic["alt_key"] = True
            if hasattr(key, 'char'):
                key_char_lower = key.char.lower()
                if self.control_key_pressed_dic.get("alt_key", False) and key_char_lower in self.alt_key_pressed_dic:
                    if(key_char_lower == 'q'):  #종료
                        self.log_log(f"--- Program Exit by alt_q")
                        sys.exit(0)
                    if key_char_lower in self.alt_key_pressed_dic and not self.alt_key_pressed_dic.get(key_char_lower, False):
                        self.alt_key_pressed_dic[key_char_lower] = True  #한 번만 동작하도록 key_pressed 설정
                        self.previous_time = time.time()
                        if key_char_lower == 'c': 
                            capture_and_encrypt(self)
                        elif key_char_lower == 'd':
                            self.decrypt_all_files()
                        elif key_char_lower == 's' and Multi_Display:
                            self.change_display()
                    self.menu_display()

        except AttributeError:
            self.log_log(f"Special Key: {key}")

def capture_and_encrypt(Capture_Encrypt_Decrypt_Class):
    file_time = datetime.now().strftime(r"%Y%m%d_%H%M%S")
    Capture_Encrypt_Decrypt_Class.capture_file = os.path.join(Capture_Encrypt_Decrypt_Class.dest_dir, f"{file_time}.png")
    Capture_Encrypt_Decrypt_Class.jason_file = os.path.join(Capture_Encrypt_Decrypt_Class.dest_dir, f"{file_time}.json")
    image_data = Capture_Encrypt_Decrypt_Class.capture_display()
    encrypted_data = Capture_Encrypt_Decrypt_Class.encrypt_data(image_data, None)
    Capture_Encrypt_Decrypt_Class.save_encrypted_data_2_file(Capture_Encrypt_Decrypt_Class.salt, encrypted_data, Capture_Encrypt_Decrypt_Instance.jason_file)
    Capture_Encrypt_Decrypt_Class.log_log(f"{delimeter}\n!!! Screen capture & Encryption success\n    * {Capture_Encrypt_Decrypt_Instance.jason_file}\n{delimeter}", True)

if pyQT:
    class MyWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Snap_Crypt_Q(화면 캡처 & 암복호화 App)")  # 창 제목 설정
            self.setGeometry(100, 100, 600, 400)  # 화면 크기 (1800 x 400)
            central_widget = QWidget(self)  # 중앙 위젯 생성
            self.setCentralWidget(central_widget)
            main_layout = QVBoxLayout()  # 전체 수직 레이아웃

            #버튼을 위한 가로 레이아웃
            button_layout = QHBoxLayout()

            self.Button_Info = [["키 변경(&K)", self.but_1], ["화면 캡처 -> 암호(&C)", self.but_2], ["암호 화면 복호(&D)", self.but_3]]
            if Multi_Display:
                self.Button_Info = [["키 변경(&K)", self.but_1], ["화면 캡처 -> 암호(&C)", self.but_2], ["암호 화면 복호(&D)", self.but_3], ["현재 캡처 화면(1)(&S)", self.but_4]]
            self.button = [] 
            for i in range(len(self.Button_Info)):
                self.button.append(QPushButton(self.Button_Info[i][0], self)) # 버튼 생성
                self.button[i].setFixedHeight(30)  # 버튼 높이
                self.button[i].setStyleSheet("font-size: 12px;")  # 버튼 스타일
                self.button[i].clicked.connect(self.Button_Info[i][1]) # 버튼 실행 함수 연결
                button_layout.addWidget(self.button[i]) #layout에 배치

            main_layout.addLayout(button_layout)  # 버튼 레이아웃 추가

            #출력 QListEdit
            self.list_widget = QListWidget(self)
            self.list_widget.setStyleSheet("font-size: 12px;")
            main_layout.addWidget(self.list_widget)

            central_widget.setLayout(main_layout)  # 레이아웃 적용

        def but_1(self):
            Capture_Encrypt_Decrypt_Instance.get_key_from_user()
            Capture_Encrypt_Decrypt_Instance.log_log(f"{delimeter}\n!!! Key Change\n{delimeter}")
        def but_2(self):
            capture_and_encrypt(Capture_Encrypt_Decrypt_Instance)
        def but_3(self):
            Capture_Encrypt_Decrypt_Instance.decrypt_all_files()
        def but_4(self):
            Capture_Encrypt_Decrypt_Instance.change_display()
            self.button[len(self.Button_Info)-1].setText(f"현재 캡처 화면({Capture_Encrypt_Decrypt_Instance.display_number + 1})(&S)")

        def append_text(self, message):
            item = QListWidgetItem(message)
            if self.list_widget.count() % 2 == 0:
                item.setBackground(QColor("#f0f0f0"))  # 연한 회색
            else:
                item.setBackground(QColor("#d0e8ff"))  # 연한 파란색
            
            self.list_widget.addItem(message)
            self.list_widget.scrollToBottom()

    app = QApplication(sys.argv)
    mywindow = MyWindow()  # MyWindow 객체 생성
    mywindow.show()
    Capture_Encrypt_Decrypt_Instance = Capture_Encrypt_Decrypt()
    sys.exit(app.exec())

else:
    Capture_Encrypt_Decrypt_Instance = Capture_Encrypt_Decrypt()

    if MENU_RUN:
        while True:
            imenu = Capture_Encrypt_Decrypt_Instance.menu_display().lower()
            Capture_Encrypt_Decrypt_Instance.check_semaphore_timeout_flag()
            Capture_Encrypt_Decrypt_Instance.previous_time = time.time()
            if imenu == "c":
                capture_and_encrypt(Capture_Encrypt_Decrypt_Instance)
            elif imenu == "d":
                Capture_Encrypt_Decrypt_Instance.decrypt_all_files()
            elif imenu == "k":
                Capture_Encrypt_Decrypt_Instance.get_key_from_user()
            elif imenu == "s" and Multi_Display:
                Capture_Encrypt_Decrypt_Instance.change_display()
            elif imenu == "q":
                Capture_Encrypt_Decrypt_Instance.log_log(f"--- Program Exit by User")
                break
    else:
        Capture_Encrypt_Decrypt_Instance.menu_display()
        Capture_Encrypt_Decrypt_Instance.timer_event_set()
        with keyboard.Listener(on_press=Capture_Encrypt_Decrypt_Instance.on_press, on_release=Capture_Encrypt_Decrypt_Instance.on_release) as listener:
            listener.join()
