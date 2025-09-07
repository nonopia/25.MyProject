#from PyInstaller.utils.hooks import collect_submodules
#hiddenimports = collect_submodules('pyautogui')
#pyinstaller --name snap_crypt_Q --onefile --noupx --noconsole --icon=.\30_completed\snap_crypt_icon.ico --hidden-import=pyscreeze --hidden-import=pillow --hidden-import=numpy --exclude-module=pwd --exclude-module=grp --exclude-module=fcntl --exclude-module=termios --exclude-module=PyQt5 snap_crypt.py

from pathlib import Path
from pynput import keyboard   #pip install pynput pywin32 pyMeow
from cryptography.hazmat.primitives import hashes    #pip install cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QInputDialog, QListWidget, QListWidgetItem, QFileDialog, QLabel, QStyledItemDelegate, QProgressBar, QCheckBox, QMessageBox, QGroupBox, QRadioButton, QListWidget, QButtonGroup, QDialog  #pip install pyQT6
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QEvent, QRegularExpression
from PyQt6.QtGui import QColor, QPen, QRegularExpressionValidator, QIntValidator

from PIL import Image
from datetime import datetime
from ctypes import wintypes

import pyautogui as p  #pip install pyautogui, pip install pyscreenshot, pip install pyscreeze pillow
import sys
import time
import os, io
import copy
import platform
import base64
import json
import glob
import threading
import pwinput #pip install pwinput
import mss
import ctypes
import pygetwindow as gw
 
import PyInstaller.__main__ #python snap_crypt.py --build
separator = ';' if os.name == 'nt' else ':' #Windows ';' / Linux ':' 
script_path = os.path.abspath(__file__) #상대 경로일 경우 보정
script_name = os.path.splitext(os.path.basename(sys.argv[0]))[0] #상대 경로일 경우 보정
if "--build" in sys.argv:
    PyInstaller.__main__.run([ 
        script_path,                 #__file__,  # 현재 실행 중인 파일
        f'--name={script_name}',    #f'--name={sys.argv[0].rsplit(".", 1)[0]}',
        '--onefile', 
        '--noupx', 
        '--noconsole',
        f'--icon={os.path.join(".", "30_completed", "snap_crypt_icon.ico")}',
#        f'--add-data={os.path.join(".", "_access_info.json")}{separator}.', # ./1.json이 실행시에는 _MEI/1.json에 위치
#        f'--add-data={os.path.join(".", "data", "remote_info.json")}{separator}config', #./data/1.json이 실행시에는 _MEI/config/1.json에 위치
        '--hidden-import=pyscreeze', '--hidden-import=pillow', '--hidden-import=numpy',
        '--exclude-module=pwd', '--exclude-module=grp', '--exclude-module=fcntl', '--exclude-module=termios', '--exclude-module=PyQt5'
    ])
    sys.exit(0)

pyQT = True
THREAD_PROGRESS_BAR = False
if pyQT is False:
    THREAD_PROGRESS_BAR = False
MENU_RUN = True
TIME_LIMIT = True

class CLASS_ProgressBar(QThread):
    progress_changed_func = pyqtSignal(int)  # 진행 상태를 업데이트하는 시그널
    progress_finished_func = pyqtSignal()  # 작업이 완료되었을 때
    log_message_func = pyqtSignal(bool, str, bool)  # 로그 메시지를 위한 시그널

    def __init__(self, file_names, parent_window):
        super().__init__()
        self.file_names = file_names  # 암호화할 파일 목록
        self.parent_window = parent_window  # UI를 제어하기 위해 QMainWindow를 받아옴

    def run(self):
        self.parent_window.checkbox_file_or_dir.setChecked(True)
        self.parent_window.layout_QObject_setEnabled(self.parent_window.file_dir_layout, False)
        self.parent_window.layout_QObject_setEnabled(self.parent_window.button_layout, False)
        self.parent_window.layout_QObject_setEnabled(self.parent_window.label_checkbox_layout, False)

        if THREAD_PROGRESS_BAR == True:
            j = 0
            for i, file_name in enumerate(self.file_names):
                QApplication.processEvents()  #실행하는동안 Widget Event 버림
                if pyQT and self.parent_window.checkbox_file_or_dir.isChecked():
                    progress = int(((i + 1) / len(cls_Capture_Encrypt_Decrypt.cls_progress_bar.file_names)) * 100)
                    cls_Capture_Encrypt_Decrypt.cls_progress_bar.progress_changed_func.emit(progress)  # 진행 상태 업데이트 연결
                if not ".json" in file_name:
                    continue 
                cls_Capture_Encrypt_Decrypt.json_file = file_name
                cls_Capture_Encrypt_Decrypt.image_file = cls_Capture_Encrypt_Decrypt.json_file.replace(".json", "_dec.png")
                cls_common.check_directory_exist(cls_common.dest_dir)
                try:
                    with open(cls_Capture_Encrypt_Decrypt.json_file, "r") as f:
                        encrypted_data_from_json = json.load(f)
                except Exception as e:
                    cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 암호 파일 포맷 부적절\n    * {cls_Capture_Encrypt_Decrypt.json_file}\n{cls_common.delimeter}", Console_On = True)
                    cls_common.log_log(list_log_append=pyQT, message=f"{cls_common.delimeter}\n!!! 총 {j}개 암호 파일 해제 완료\n{cls_common.delimeter}")
                    if pyQT and self.parent_window.checkbox_file_or_dir.isChecked():
                            cls_Capture_Encrypt_Decrypt.cls_progress_bar.progress_finished_func.emit()  # 작업 완료 시 신호 발생
                    return False
                if cls_Capture_Encrypt_Decrypt.decrypt_file(encrypted_data_from_json):
                    cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 암호 파일 해제 성공\n    * {cls_Capture_Encrypt_Decrypt.json_file}\n      -> {cls_Capture_Encrypt_Decrypt.image_file}\n{cls_common.delimeter}", Console_On = True)
                    j += 1
                else:
                    cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 암호 파일 해제 실패 : 암호키와 다른 키로 해제 시도\n    * {cls_Capture_Encrypt_Decrypt.json_file}\n{cls_common.delimeter}", Console_On = True)
            cls_common.log_log(list_log_append=pyQT, message=f"{cls_common.delimeter}\n!!! 총 {j}개 암호 파일 해제 완료\n{cls_common.delimeter}")
            if pyQT and (not self.parent_window.checkbox_file_or_dir.isChecked()):
                cls_MyWindow.progress_finished_func_1()
            else:
                cls_Capture_Encrypt_Decrypt.cls_progress_bar.progress_finished_func.emit()  #Thread

#        self.parent_window.layout_QObject_setEnabled(self.parent_window.file_dir_layout, False)
#        self.parent_window.layout_QObject_setEnabled(self.parent_window.button_layout, False)
#        total_files = len(self.file_names)
#        for idx, file in enumerate(self.file_names):
#            time.sleep(0.5)  # 암호화 작업을 시뮬레이션 (실제 암호화 로직을 넣으시면 됩니다)
#            progress = int(((idx + 1) / total_files) * 100)
#            self.progress_changed_func.emit(progress)  # 진행 상태를 업데이트
#        self.progress_finished_func.emit()  # 작업 완료 시 신호 발생

class CLASS_common():
    def __init__(self):
        self.delimeter = f'{"-" * 55}'
        self.user_node = platform.node()
        self.file_stamp_time = None
        self.subdirectory_name = 'snapshots'
        self.log_file_name = '00000000-snap_crypt_log.txt'
        self.current_directory = Path(os.path.join(os.getcwd(), self.subdirectory_name))
        self.dest_dir = Path(os.path.join(os.getcwd(), self.subdirectory_name))
        self.log_file = Path(os.path.join(self.dest_dir, self.log_file_name))
        self.check_directory_exist(self.dest_dir)
        self.monitor_number = 0
        self.display = {"name": "", "left": 0, "top": 0, "width": 0, "height": 0, "scale": 0}
#        self.monitors = self.get_monitor_info()
        self.previous_time = time.time()
        self.wait_timer_sec = 60
        self.total_timeout_sec = self.wait_timer_sec * 15
        self.semaphore_timeout_flag = False
        self.control_key_pressed_dic = {"shift_key": False, "alt_key": False, "ctrl_key": False}
        self.alt_key_pressed_dic = {'c': False, 'd': False, 's': False, 'q': False}
        self.timer_event_set()

    def get_monitor_info(self):
        with mss.mss() as sct:
            self.log_log(list_log_append=pyQT, message=f'{self.delimeter}\n--- 모니터 크기 = {sct.monitors}\n{self.delimeter}', Console_On=True)
            return sct.monitors

    def capture_monitor(self, monitor_info = {}) -> bytes:
#        windows = gw.getAllTitles()
##        visible_windows = []
#        for window_title in windows:
#            window = gw.getWindowsWithTitle(window_title)[0]  # 윈도우 객체 가져오기
#            # 제목이 비어 있거나 크기가 너무 작은 윈도우는 제외
#            if window.title and window.width > 1 and window.height > 1 and window.visible and not window.isMinimized:
#                visible_windows.append(window)

        with mss.mss() as sct:
#            monitor = {"top": top, "left": left, "width": right - left, "height": bottom - top}
            screenshot = sct.grab(monitor_info)
        screen_shot_image = Image.frombytes("RGB", screenshot.size, screenshot.rgb)
#        screen_shot_image.show()
        with io.BytesIO() as image_bytes_array: # 메모리에서 PNG로 저장
            screen_shot_image.save(image_bytes_array, format="PNG")
            return image_bytes_array.getvalue()  # PNG 바이트 데이터 반환

    class MONITORINFOEX(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("rcMonitor", wintypes.RECT),
            ("rcWork", wintypes.RECT),
            ("dwFlags", wintypes.DWORD),
            ("szDevice", wintypes.WCHAR * 32),
        ]

    class Monitor():
        """ 개별 모니터 정보를 저장하는 클래스 """
        def __init__(self, name, x, y, width, height, scale):
            self.name = name
            self.x = x
            self.y = y
            self.width = width
            self.height = height
            self.scale = scale

        def __repr__(self):
            return f"Monitor(name={self.name}, x={self.x}, y={self.y}, width={self.width}, height={self.height}, scale={self.scale}, index={self.index})"

    def get_monitor_info2(self):
        user32 = ctypes.windll.user32
        shcore = ctypes.windll.shcore
        shcore.SetProcessDpiAwareness(2)  # DPI 인식 설정
        monitor_infos = []
        
        def callback(hMonitor, hdcMonitor, lprcMonitor, dwData):
            info = self.MONITORINFOEX()
            info.cbSize = ctypes.sizeof(self.MONITORINFOEX)
            if user32.GetMonitorInfoW(hMonitor, ctypes.byref(info)):
                scale_factor = ctypes.c_uint()
                if shcore.GetScaleFactorForMonitor(hMonitor, ctypes.byref(scale_factor)) == 0:
                    scale = scale_factor.value / 100  # ex) 150 -> 1.5
                else:
                    scale = 1.0  # 기본값 100%
                x, y = info.rcMonitor.left, info.rcMonitor.top
                width = (info.rcMonitor.right - info.rcMonitor.left) / scale
                height = (info.rcMonitor.bottom - info.rcMonitor.top) / scale
                if not monitor_infos:  # 첫 번째 모니터는 스케일 보정 없이 그대로
                    width = width
                    height = height
                else:
                    width = width / scale
                    height = height / scale
                monitor_infos.append(self.Monitor(name = info.szDevice, x = int(x), y = int(y), width = int(width), height = int(height), scale = scale_factor.value))
            return True

        MONITOR_ENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HMONITOR, wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.LPARAM)
        user32.EnumDisplayMonitors(0, 0, MONITOR_ENUMPROC(callback), 0)
        return monitor_infos

    def capture_monitor2(self, monitor_info = "") -> bytes:
#       p.screenshot(self.image_file)  # 전체 화면 Capture & 파일로 저장
#       os.remove(self.image_file)
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

        with mss.mss() as sct:
            monitor = {
                "top": monitor_info.y,
                "left": monitor_info.x,
                "width": monitor_info.width,
                "height": monitor_info.height
            }
            screenshot = sct.grab(monitor)
        screen_shot_image = Image.frombytes("RGB", screenshot.size, screenshot.rgb)
        screen_shot_image.show()
        with io.BytesIO() as image_bytes_array: # 메모리에서 PNG로 저장
            screen_shot_image.save(image_bytes_array, format="PNG")
            return image_bytes_array.getvalue()  # PNG 바이트 데이터 반환

    def get_dpi_scale(self) -> float:
        hdc = ctypes.windll.user32.GetDC(0)
        dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)  # 88은 HORZSIZE
        ctypes.windll.user32.ReleaseDC(0, hdc)
        return dpi / 96  # 96 DPI는 기본 DPI

    def is_admin(self) -> int:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux, Mac
            return os.geteuid() == 0

    def timer_event_set(self) -> None:
        self.timer_event = threading.Event()
        self.exit_thread = threading.Thread(target=self.wait_and_exit)
        self.exit_thread.daemon = True  # 프로그램 종료 시 스레드도 종료되도록 설정
        self.exit_thread.start()  #백그라운드 스레드 메소드

    def wait_and_exit(self) -> None:
        while True:
            self.timer_event.wait(self.wait_timer_sec)
            if time.time() - self.previous_time > self.total_timeout_sec:
                self.semaphore_timeout_flag = True
                self.timer_event.clear()

    def check_timeout_semaphore_exit(self) -> None:
        if TIME_LIMIT:
            if self.semaphore_timeout_flag:
                self.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n--- 타이머{self.total_timeout_sec/60:.0f}(분)에 의해 프로그램 종료\n{cls_common.delimeter}", Console_On = True)
                sys.exit()

    def check_directory_exist(self, directory):
        if not os.path.exists(directory):
            os.makedirs(directory)

    def log_log(self, list_log_append:bool = False , message: str = "",  Console_On: bool = False) -> None:
        log_message = f'>>>> {datetime.now().strftime("%Y%m%d_%H%M%S")} : \n{message}'
        self.check_directory_exist(self.dest_dir)
        with open(self.log_file, "a", encoding="utf-8", buffering = 1) as f:
            f.write(f'{log_message}\n')
        if list_log_append:
            cls_MyWindow.append_text_2_list_log(f'{message}')
        else:
            if Console_On:
                print(f'{message}')

    def change_monitor(self):
        self.monitors = self.get_monitor_info()
        old_monitor_number = self.monitor_number
        self.monitor_number = self.monitor_number + 1
        self.monitor_number = (self.monitor_number % len(self.monitors))
        self.log_log(list_log_append = pyQT, message = f"{self.delimeter}\n!!! 캡쳐 화면(0번은 모든 스크린을 합친 화면) \n    * 스크린 {old_monitor_number} -> 스크린 {self.monitor_number}\n{self.delimeter}", Console_On=True)
        return old_monitor_number

    def menu_display(self) -> None:
#        command = "cls" if sys.platform.startswith("win") else "clear"
#        os.system(command)
        if MENU_RUN:
            print(f"\n\n{self.delimeter}\n- {self.total_timeout_sec/60:.0f}분 동안 스크린 캡처나 암호 파일 해제가 없으면 자동 종료")
            print(f"- 's' : 캡처 화면(현재 화면 = {self.monitor_number})")
            print(f"- 'k' : 키 입력/변경")
            print(f"- 'c' : 화면 캡처후 암호")
            print(f"- 'd' : 암호 파일 해제")
            print(f"- 'q' : 종료\n{self.delimeter}")
            input_key = input("원하시는 서비스를 입력하세요 : ")
            print("")
            return input_key
        else:
            print(f"\n\n{self.delimeter}\n* {self.total_timeout_sec/60:.0f}분 동안 스크린 캡처나 암호 파일 해제가 없으면 자동 종료")
            print(f"* 'alt-s' : 캡처 화면(현재 화면 = {self.monitor_number})")
            print(f"* 'alt-c' : 화면 캡처후 암호")
            print(f"* 'alt-d' : 암호 파일 해제")
            print(f"* 'alt-q' : 종료\n{self.delimeter}")
            return ""

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
        self.check_timeout_semaphore_exit()
        try:
            if (not self.control_key_pressed_dic["alt_key"]):
                if key in {keyboard.Key.alt_l, keyboard.Key.alt_r}:
                    self.control_key_pressed_dic["alt_key"] = True
            if hasattr(key, 'char'):
                key_char_lower = key.char.lower()
                if self.control_key_pressed_dic.get("alt_key", False) and key_char_lower in self.alt_key_pressed_dic:
                    if(key_char_lower == 'q'):  #종료
                        self.log_log(list_log_append = pyQT, message = f"{self.delimeter}\n--- Program Exit by alt_q\n{self.delimeter}", Console_On = True)
                        sys.exit(0)
                    if key_char_lower in self.alt_key_pressed_dic and not self.alt_key_pressed_dic.get(key_char_lower, False):
                        self.alt_key_pressed_dic[key_char_lower] = True  #한 번만 동작하도록 key_pressed 설정
#                        self.previous_time = time.time()
                        if key_char_lower == 'c': 
                            cls_Capture_Encrypt_Decrypt.capture_and_encrypt()
                        elif key_char_lower == 'd':
                            cls_Capture_Encrypt_Decrypt.decrypt_all_files()
                        elif key_char_lower == 's':
                            self.change_monitor()
                    self.menu_display()

        except AttributeError:
            self.log_log(list_log_append = pyQT, message = f"{self.delimeter}\n!!! Special Key Input: {key}( in (on_press)\n{self.delimeter}", Console_On = True)

class CLASS_Capture_Encrypt_Decrypt():
    def __init__(self):
        self.image_file = None
        self.json_file = None
        self.key = None
        self.salt = None
        self.cipher = None
        if THREAD_PROGRESS_BAR:
            cls_common.log_log(list_log_append = pyQT, message = f'{cls_common.delimeter}\n--- Program(Thread Progress) Start on {cls_common.user_node}\n{cls_common.delimeter}')
        else:
            cls_common.log_log(list_log_append = pyQT, message = f'{cls_common.delimeter}\n--- Program Start on {cls_common.user_node}\n{cls_common.delimeter}')

    def get_key_from_user(self) -> bool:
        unuseful_key_value = True
        old_key = self.key
        ok = True
        while unuseful_key_value:
            if pyQT:
                if self.key is None:
                    self.key, ok = QInputDialog.getText(cls_MyWindow, "키 입력", "초기 키를 입력하세요.", QLineEdit.EchoMode.Password)
                else:
                    self.key, ok = QInputDialog.getText(cls_MyWindow, "키 입력", "변경할 키를 입력하세요.", QLineEdit.EchoMode.Password)
            else:
                self.key = pwinput.pwinput("키를 입력하세요 : ", mask="*")
            self.key = self.key.encode()
            if ok == True and self.key:
                return True
            if ok == False:
                self.key = old_key
                return False

    def make_key_ciper(self, salt, key, user_node, file_stamp_time): # PBKDF2HMAC을 사용하여 입력 키에서 32바이트 길이의 키 도출
        combined_input = key + user_node.encode("ascii") + file_stamp_time.encode("ascii")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt = salt, iterations=1000)
        key = base64.urlsafe_b64encode(kdf.derive(combined_input))  # 키 도출 및 base64 인코딩
        self.cipher = Fernet(key)

    def decrypt_file(self, encrypted_json_file) -> bool:
        try:
            salt_from_json = base64.b64decode(encrypted_json_file["salt"].encode())  # base64로 인코딩된 salt 복원
            user_node_from_json = encrypted_json_file["User_Node"]
            file_stamp_time_from_json = encrypted_json_file["Time_Stamp"]  
            encrypted_data_from_json = base64.b64decode(encrypted_json_file["Encrypted Image"].encode())  # 암호화된 메시지 복원
            self.make_key_ciper(salt_from_json, self.key, user_node_from_json, file_stamp_time_from_json)
            decrypted_file_data = self.cipher.decrypt(encrypted_data_from_json)
            cls_common.check_directory_exist(cls_common.dest_dir)
            with open(f'{self.image_file}', "wb") as file:
                file.write(decrypted_file_data)
            return True
        except Exception as e:
            cls_common.log_log(list_log_append = pyQT, message = f'{cls_common.delimeter}\n--- 암호 해제 실패 {e} - in (decrypt_file)\n{cls_common.delimeter}')

    def decrypt_all_files(self) -> bool:
        if THREAD_PROGRESS_BAR:
            self.decrypt_files_by_thread()
        else:
            self.decrypt_files_by_mainloop()

    def decrypt_files_by_thread(self) -> bool:
        if (not self.key) and (not self.get_key_from_user()):
            cls_common.log_log(list_log_append = pyQT, message = f'{cls_common.delimeter}\n--- 키 미설정 - in (decrypt_all_files)\n{cls_common.delimeter}')
            return False
        if pyQT:
            file_names = cls_MyWindow.make_file_location_from_editbox(cls_MyWindow.line_edit_search_box.text(), cls_common.dest_dir, cls_MyWindow.list_file_dir_widget)
        else:
            file_names = glob.glob(os.path.join(cls_common.dest_dir, "*.json"))
        if not file_names:
            cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 해제할 파일이 없음\n{cls_common.delimeter}", Console_On = True)
            return False        
        if pyQT and not cls_MyWindow.checkbox_file_or_dir.isChecked(): #1 File, No progree bar
            file_names = glob.glob(os.path.join(cls_common.dest_dir, cls_MyWindow.list_file_dir_widget.currentItem().text()))
            j = 0
            for i, file_name in enumerate(file_names):
                self.json_file = file_name
                self.image_file = self.json_file.replace(".json", "_dec.png")
                cls_common.check_directory_exist(cls_common.dest_dir)
                try:
                    with open(self.json_file, "r") as f:
                        encrypted_data_from_json = json.load(f)
                except Exception as e:
                    cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 암호 파일 포맷 부적절\n    * {self.json_file}\n{cls_common.delimeter}", Console_On = True)
                    cls_common.log_log(list_log_append=pyQT, message=f"{cls_common.delimeter}\n!!! 총 {j}개 암호 파일 해제 완료\n{cls_common.delimeter}")
                    return False
                if self.decrypt_file(encrypted_data_from_json):
                    cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 암호 파일 해제 성공\n    * {self.json_file}\n      -> {self.image_file}\n{cls_common.delimeter}", Console_On = True)
                    j = j + 1
                else:
                    cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 암호 파일 해제 실패 : 암호키와 다른 키로 암호 해제 시도\n    * {self.json_file}\n{cls_common.delimeter}", Console_On = True)
            cls_common.log_log(list_log_append=pyQT, message=f"{cls_common.delimeter}\n!!! 총 {j}개 암호 파일 해제 완료\n{cls_common.delimeter}")
            if pyQT and (not cls_MyWindow.checkbox_file_or_dir.isChecked()):
                cls_MyWindow.progress_finished_func_1()
            else:
                if pyQT:
                    self.cls_progress_bar.progress_finished_func.emit()  # 작업 완료 시 신호 발생
        else: #n File, progress Bar setting
            if pyQT:
                QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
                self.cls_progress_bar = CLASS_ProgressBar(file_names, cls_MyWindow)  #class
                self.cls_progress_bar.progress_changed_func.connect(cls_MyWindow.progress_changed_func_1)  # 진행 상태 업데이트 연결
                self.cls_progress_bar.progress_finished_func.connect(cls_MyWindow.progress_finished_func_1)  # 진행 종료 업데이트 연결
                self.cls_progress_bar.start()  # run Thread

    def decrypt_files_by_mainloop(self) -> bool:
        if (not self.key) and (not self.get_key_from_user()):
            cls_common.log_log(list_log_append = pyQT, message = f'{cls_common.delimeter}\n--- 키 미설정 - in (decrypt_all_files)\n{cls_common.delimeter}')
            return False
        if pyQT:
            file_names = cls_MyWindow.make_file_location_from_editbox(cls_MyWindow.line_edit_search_box.text(), cls_common.dest_dir, cls_MyWindow.list_file_dir_widget)
        else:
            file_names = glob.glob(os.path.join(cls_common.dest_dir, "*.json"))
        if not file_names:
            cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 해제할 암호 파일이 없음\n{cls_common.delimeter}", Console_On = True)
            return False
        if pyQT and not cls_MyWindow.checkbox_file_or_dir.isChecked(): #1 File, No progree bar setting
            file_names = glob.glob(os.path.join(cls_common.dest_dir, cls_MyWindow.list_file_dir_widget.currentItem().text()))
        else: #n File, progress Bar setting
            if pyQT:
                ####### 현재 Menu 모드 , Progressive 모드 구현안되어 있음, 
                #QPixmap 에러 발생 : Must construct a QGuiApplication before a QPixmap 
                QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
                self.cls_progress_bar = CLASS_ProgressBar(file_names, cls_MyWindow)  #class
                self.cls_progress_bar.progress_changed_func.connect(cls_MyWindow.progress_changed_func_1)  # 진행 상태 업데이트 연결
                self.cls_progress_bar.progress_finished_func.connect(cls_MyWindow.progress_finished_func_1)  # 진행 종료 업데이트 연결
                self.cls_progress_bar.start()  #Thread run
        j = 0
        for i, file_name in enumerate(file_names):
            QApplication.processEvents()  #실행하는동안 Widget Event 버림
            if pyQT and cls_MyWindow.checkbox_file_or_dir.isChecked():
                progress = int(((i + 1) / len(cls_Capture_Encrypt_Decrypt.cls_progress_bar.file_names)) * 100)
                cls_Capture_Encrypt_Decrypt.cls_progress_bar.progress_changed_func.emit(progress)  # 진행 상태 업데이트 연결
            if not ".json" in file_name:
                continue 
            self.json_file = file_name
            self.image_file = self.json_file.replace(".json", "_dec.png")
            cls_common.check_directory_exist(cls_common.dest_dir)
            try:
               with open(self.json_file, "r") as f:
                    encrypted_data_from_json = json.load(f)
            except Exception as e:
                cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 암호 파일 포맷 부적절\n    * {self.json_file}\n{cls_common.delimeter}", Console_On = True)
                cls_common.log_log(list_log_append=pyQT, message=f"{cls_common.delimeter}\n!!! 총 {j}개 암호 파일 해제 완료\n{cls_common.delimeter}")
                if pyQT and cls_MyWindow.checkbox_file_or_dir.isChecked():
                        self.cls_progress_bar.progress_finished_func.emit()  # 작업 완료 시 신호 발생
                return False
            if self.decrypt_file(encrypted_data_from_json):
                cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 암호 파일 해제 성공\n    * {self.json_file}\n      -> {self.image_file}\n{cls_common.delimeter}", Console_On = True)
                j += 1
            else:
                cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 암호 파일 해제 실패 : 암호키와 다른 키로 해제 시도\n    * {self.json_file}\n{cls_common.delimeter}", Console_On = True)
        cls_common.log_log(list_log_append=pyQT, message=f"{cls_common.delimeter}\n!!! 총 {j}개 암호 파일 해제 완료\n{cls_common.delimeter}")
        if pyQT and (not cls_MyWindow.checkbox_file_or_dir.isChecked()):
            cls_MyWindow.progress_finished_func_1()  # 작업 완료 시 신호 발생
        else:
            if pyQT:
                cls_MyWindow.progress_finished_func_1()

    def encrypt_data(self, data_bytes: bytes = None, data_from_file: str = None) -> bytes:
        if (not self.key) and (not self.get_key_from_user()):
            cls_common.log_log(list_log_append = pyQT, message = f'{cls_common.delimeter}\n--- 키 미설정 - in (encrypt_data)\n{cls_common.delimeter}')
            return False
        self.salt = os.urandom(16)  # # salt를 생성 (매번 새로 생성해야 함)
        self.make_key_ciper(self.salt, self.key, cls_common.user_node, cls_common.file_stamp_time)
        cls_common.check_directory_exist(cls_common.dest_dir)
        if data_from_file:
            with open(data_from_file, "rb") as f:
                data_bytes = f.read()
        encrypted_data = self.cipher.encrypt(data_bytes)
        return encrypted_data

    def save_encrypted_data_2_file(self, salt: bytes, encrypted_data: bytes, file_name: str):
        data_to_store_4_json = {
            "User_Node": cls_common.user_node,
            "Time_Stamp": cls_common.file_stamp_time,
            "salt": base64.b64encode(salt).decode(),  # salt를 base64로 인코딩하여 저장
            "Encrypted Image": base64.b64encode(encrypted_data).decode(),  # 암호화된 메시지를 Base64로 인코딩하여 저장
        }
        cls_common.check_directory_exist(cls_common.dest_dir)
        with open(f'{file_name}', "w") as f:
            json.dump(data_to_store_4_json, f)

    def find_monitor_window(self):
        if not cls_MyWindow.current_monitor_title and not cls_MyWindow.current_window_title:
#            cls_common.log_log(list_log_append = pyQT, message = f'{cls_common.delimeter}\n--- 먼저 캡처대상을 선택하여야 합니다.\n{cls_common.delimeter}')
            cls_MyWindow.but_1()
        if cls_MyWindow.current_monitor_title:
            target_title = cls_MyWindow.current_monitor_title
            monitor_rec = cls_MyWindow.monitors[int(target_title.split()[-1])]
            return_position = monitor_rec
            return return_position
        if cls_MyWindow.current_window_title:
            target_title = cls_MyWindow.current_window_title
            windows = gw.getWindowsWithTitle(target_title)
            if windows:
                for window in windows:
                    if window.title == target_title:  # 정확히 일치하는 제목만 확인
                        return_position = {
                            "left" : window.left, 
                            "top" : window.top, 
                            "width" : window.width, 
                            "height" :window.height
                        }
            else:
                cls_common.log_log(list_log_append = pyQT, message = f'{cls_common.delimeter}\n--- 캡처할 윈도우가 사라졌습니다. 다시 선택해 주세요.\n{cls_common.delimeter}')
                cls_MyWindow.current_monitor_title = ""
                cls_MyWindow.current_window_title = ""
                return False 
        return return_position
    
    def capture_and_encrypt(self) -> bool:
        cls_common.file_stamp_time = datetime.now().strftime(r"%Y%m%d_%H%M%S")
        self.image_file = os.path.join(cls_common.dest_dir, f"{cls_common.file_stamp_time}.png")
        self.json_file = os.path.join(cls_common.dest_dir, f"{cls_common.file_stamp_time}.json")
        if pyQT :
            capture_rec = self.find_monitor_window()
            if capture_rec is False:
                return False
            image_data = cls_common.capture_monitor(monitor_info = capture_rec)
        else:
            cls_common.monitors = cls_common.get_monitor_info()
            image_data = cls_common.capture_monitor(monitor_info = cls_common.monitors[cls_common.monitor_number])
        encrypted_data = self.encrypt_data(image_data, None)
        if not encrypted_data:
            return False
        self.save_encrypted_data_2_file(self.salt, encrypted_data, self.json_file)
        cls_common.log_log(list_log_append = pyQT, message =f"{cls_common.delimeter}\n!!! 화면 캡처 및 암호 성공\n    * {self.json_file}\n{cls_common.delimeter}", Console_On = True)
        return True

cls_common = CLASS_common()
if pyQT:

    class PopUpWindow(QDialog):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.parent = parent

            self.setWindowTitle("캡처 대상 선택")
            self.setGeometry(150, 150, 300, 600)

            # 전체 레이아웃 생성
            main_layout = QVBoxLayout(self)

            # 라벨 및 텍스트 박스 추가
            self.label = QLabel("캡처 대상 모니터/윈도우", self)
            self.capture_textbox = QLineEdit()
            self.capture_textbox.setPlaceholderText("캡처할 모니터/윈도우를 선택하세요")
            self.capture_textbox.setReadOnly(True)

            if parent.current_monitor_title:
                self.capture_textbox.setText(parent.current_monitor_title)
            if parent.current_window_title:
                self.capture_textbox.setText(parent.current_window_title)
            
            main_layout.addWidget(self.label)  # 먼저 Label 추가
            main_layout.addWidget(self.capture_textbox)  # 그 다음 Textbox 추가

            # 캡처 대상 모니터 그룹
            monitor_group = QGroupBox("캡처 대상 모니터 선택")
            self.list_monitor_widget = QListWidget()
            self.get_monitor_info()  # 모니터 정보를 가져와 리스트에 추가

            list_height = self.list_monitor_widget.sizeHintForRow(0) * 3  # 3줄 높이
            self.list_monitor_widget.setFixedHeight(list_height)
            self.list_monitor_widget.itemClicked.connect(self.list_monitor_widget_click)
            self.list_monitor_widget.itemDoubleClicked.connect(self.popup_close)

            monitor_layout = QVBoxLayout()  # 
            monitor_layout.addWidget(self.list_monitor_widget)
            monitor_group.setLayout(monitor_layout)  # 

            main_layout.addWidget(monitor_group)  #

            # 캡처 대상 윈도우 그룹
            window_group = QGroupBox("캡처 대상 윈도우 선택")
            self.list_windows_widget = QListWidget()
            self.get_window_info()  # 윈도우 정보를 가져와 리스트에 추가

            row_height = self.list_windows_widget.sizeHintForRow(0)
            self.list_windows_widget.setFixedHeight(row_height * 7)  # 7줄만 표시하도록 설정

            self.list_windows_widget.itemClicked.connect(self.list_windows_widget_click)
            self.list_windows_widget.itemDoubleClicked.connect(self.popup_close)

            window_layout = QVBoxLayout()
            window_layout.addWidget(self.list_windows_widget)
            window_group.setLayout(window_layout)
            window_layout.setContentsMargins(0, 0, 0, 0)

            window_group.setLayout(window_layout)
            window_group.setFixedHeight(self.list_windows_widget.sizeHint().height())  # 리스트 위젯에 맞게 높이 설정
#            window_group.setFixedHeight(row_height * 7 + 50 + 40) 
#            window_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

            group_height = row_height * 7 + 30
            window_group.setFixedHeight(group_height)
            main_layout.addWidget(window_group)  # 

#            self.setLayout(main_layout)  # 최종 레이아웃 설정
            total_height = list_height + self.list_windows_widget.sizeHintForRow(0) * 6 + 50 + 40 + 80
            self.setFixedHeight(total_height)

            # 자식 윈도우가 모달 창이 되도록 설정
            self.setWindowModality(Qt.WindowModality.ApplicationModal)
            self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)  # 창이 닫힐 때 삭제

        def popup_close(self):
            self.close()
            
        def closeEvent(self, event):
            parent_window = self.parentWidget()  # parent() 대신 parentWidget() 사용
            if parent_window:
                parent_window.setEnabled(True)  # 자식 창이 닫힐 때 부모 윈도우 활성화
                parent_window.activateWindow()  # 부모 창을 다시 최상위로 활성화
            event.accept()

        def list_monitor_widget_click(self):
            item = self.list_monitor_widget.currentItem().text()
            self.parent.current_window_title = ""
            self.parent.current_monitor_title = str(item)
            self.capture_textbox.setText(f'{self.parent.current_monitor_title}')

        def list_windows_widget_click(self):
            item = self.list_windows_widget.currentItem().text()
            self.parent.current_monitor_title = ""
            self.parent.current_window_title = item
            self.capture_textbox.setText(self.parent.current_window_title)

        def get_monitor_info(self):
            with mss.mss() as sct:
                monitors = sct.monitors  # 모니터 정보 가져오기
                monitor_names = [f"Monitor {i}" for i in range(0, len(monitors))]  # 예: 모니터 1, 모니터 2 등
                self.list_monitor_widget.addItems(monitor_names)  # 모니터 정보를 "모니터 선택" 리스트에 추가
            self.parent.monitors = copy.deepcopy(monitors)

        def get_window_info(self):
            windows = gw.getAllTitles()  # 모든 윈도우 제목 가져오기
            visible_windows = []
            for window_title in windows:
                if not window_title in ["설정","Program Manager", "Windows 입력 환경"]:
                    window = gw.getWindowsWithTitle(window_title)[0]  # 윈도우 객체 가져오기
                    if window.title and window.width > 1 and window.height > 1 and window.visible and not window.isMinimized:
                        visible_windows.append(window.title)  # 조건에 맞는 윈도우만 필터링
            self.list_windows_widget.addItems(visible_windows)  # 필터링된 윈도우 제목 리스트에 추가
            self.parent.windows = copy.deepcopy(windows)


            # 윈도우 정보 리스트에 추가
#            window_titles = [window.title for window in visible_windows[:6]]  # 6개의 윈도우 제목만 추가
#            self.list_windows_widget.addItems(window_titles)  # "윈도우 선택" 리스트에 윈도우 제목 추가


    class MyWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Snap_Crypt_Q(화면 캡처, 암호 & 해제 App)")  # 창 제목 설정
#            self.timer = QTimer(self)
#            self.timer.timeout.connect(self.on_timer_timeout)
#            self.timer.start(1000)
            self_run = False
            self.monitors = []
            self.windows = []
            self.current_monitor_title = ""
            self.current_window_title = ""

            self.central_widget = QWidget(self)  # 중앙 위젯 생성
            self.setGeometry(100, 100, 600, 400)  # 화면 크기 (1800 x 400)
            self.setFixedSize(600, 400)  # 화면 크기 고정
            self.setCentralWidget(self.central_widget)
            self.main_layout = QVBoxLayout()  # 전체 수직 레이아웃

            Button_Info = [[F"캡처대상 선택(&S)", self.but_1], ["키 변경(&K)", self.but_2], ["화면 캡처후 암호(&C)", self.but_3], ["암호 파일 해제(&D)", self.but_4], ["폴더 변경(&V)", self.but_5]]
            self.button_layout = QHBoxLayout() #버튼을 위한 가로 레이아웃
            self.button = []    
            for i in range(len(Button_Info)):
                self.button.append(QPushButton(Button_Info[i][0], self)) # 버튼 생성
                self.button[i].setFixedHeight(30)  # 버튼 높이
                self.button[i].setStyleSheet("font-size: 12px;")  # 버튼 스타일
                self.button[i].clicked.connect(Button_Info[i][1]) # 버튼 실행 함수 연결
                self.button_layout.addWidget(self.button[i]) #layout에 배치

            self.main_layout.addLayout(self.button_layout)  # 버튼 레이아웃 추가

            self.label_log = QLabel("실행 결과", self)  # 제목 생성
            self.progress_bar = QProgressBar(self)
            self.progress_bar.setStyleSheet("""
                QProgressBar {
                    height: 1px;
                    border: none;
                    text-align: right;
                    padding: 0px;
                    background-color: #E0E0E0; /* 연한 회색 배경 */
                    color: black;
                }
                QProgressBar::chunk {
                    background-color: #4CAF50;
                    margin: 0px;
                }""")
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setMinimumWidth(270)
            self.line_edit_search_box = QLineEdit("", self)
            self.line_edit_search_box.setPlaceholderText("")
            self.line_edit_search_box.setStyleSheet("""
                QLineEdit {
                    font: 12px;
                    text-align: center;  /* 수평 중앙 정렬 */
                    padding-top: 1px;    /* 수직 중앙 정렬 */
                    padding-bottom: 1px; /* 수직 중앙 정렬 */
                }
            """)
            self.line_edit_search_box.editingFinished.connect(self.on_editing_finished)

            self.label_progress_layout = QHBoxLayout()
            self.label_progress_layout.addWidget(self.label_log)
            self.label_progress_layout.addWidget(self.progress_bar, alignment = Qt.AlignmentFlag.AlignLeft)
            self.label_progress_layout.addWidget(self.line_edit_search_box)
            self.label_progress_layout.setStretch(0, 1)  # 첫 번째 리스트 9 크기
            self.label_progress_layout.setStretch(1, 1)  # 두 번째 리스트 4 크기
            self.label_progress_layout.setStretch(2, 2)  # 두 번째 리스트 4 크기

            self.log_layout = QVBoxLayout() # 왼쪽 수직 레이아웃(Log, Progress)
            self.list_log_widget = QListWidget(self)
            self.list_log_widget.setStyleSheet("font-size: 12px;")
            self.log_layout.addLayout(self.label_progress_layout)
            self.log_layout.addWidget(self.list_log_widget)

            self.checkbox_file_or_dir = QCheckBox("일괄해제(&B)", self)
            self.checkbox_file_or_dir.setChecked(False)
            self.label_file_th = QLabel("파일 갯수", self) 
            self.label_file_th.setStyleSheet("height: 5px; border: none; text-align: right; padding: 0px; background: transparent;")

            self.label_checkbox_layout = QHBoxLayout() # 오른쪽 수평 레이아웃(Label, CheckBox)
            self.label_checkbox_layout.addWidget(self.checkbox_file_or_dir)
#            self.checkbox_file_or_dir.setStyleSheet("QCheckBox::indicator { width: 15px; height: 15px; }")
            self.label_checkbox_layout.addWidget(self.label_file_th)
            self.label_checkbox_layout.setAlignment(self.label_file_th, Qt.AlignmentFlag.AlignLeft)
            self.label_checkbox_layout.setAlignment(self.checkbox_file_or_dir, Qt.AlignmentFlag.AlignRight)
#            self.label_checkbox_layout.setStretch(0, 1)  # 첫 번째 리스트 1, 2 대칭
#            self.label_checkbox_layout.setStretch(1, 1)  # 두 번째 리스트 4 크기

            self.list_file_dir_widget = QListWidget(self)
            self.list_file_dir_widget.setStyleSheet("font-size: 12px;")
            self.list_file_dir_widget.setItemDelegate(self.ListDelegate())
            self.list_file_dir_widget.itemDoubleClicked.connect(self.list_file_viewer)

            self.file_dir_layout = QVBoxLayout() # 오른쪽 수직 레이아웃(label, checkbox, file_dir)
            self.file_dir_layout.addLayout(self.label_checkbox_layout)
            self.file_dir_layout.addWidget(self.list_file_dir_widget)

            self.log_file_dir_layout = QHBoxLayout()
            self.log_file_dir_layout.addLayout(self.log_layout)
            self.log_file_dir_layout.addLayout(self.file_dir_layout)
            self.log_file_dir_layout.setStretch(0, 9)  # 첫 번째 리스트 9 크기
            self.log_file_dir_layout.setStretch(1, 4)  # 두 번째 리스트 4 크기

            self.main_layout.addLayout(self.log_file_dir_layout)
            self.central_widget.setLayout(self.main_layout)  # 레이아웃 적용

        class ListDelegate(QStyledItemDelegate):
            def paint(self, painter, option, index):
                super().paint(painter, option, index)
                painter.setPen(QPen(QColor("black"), 1))  # 검은색 구분선 (두께 1px)
                painter.drawLine(option.rect.bottomLeft(), option.rect.bottomRight())

        def log_message_func_1(self, list_log_append, message , Console_On):
            cls_common.log_log(list_log_append = list_log_append, message = message, Console_On = Console_On)

        def progress_changed_func_1(self, value):
            self.progress_bar.setValue(value)

        def progress_finished_func_1(self):
            self.layout_QObject_setEnabled(self.button_layout, True)
            self.layout_QObject_setEnabled(self.file_dir_layout, True)
            self.layout_QObject_setEnabled(self.label_checkbox_layout, True)
            self.checkbox_file_or_dir.setChecked(False)
            self.rearrange_directory()
            QApplication.restoreOverrideCursor()

        def setUIEnabled(self, enabled):
            self.setEnabled(enabled)

        def append_text_2_list_log(self, message):
            item = QListWidgetItem(message)
            if self.list_log_widget.count() % 2 == 0:
                item.setBackground(QColor("#f0f0f0"))  # 연한 회색
            else:
                item.setBackground(QColor("#d0e8ff"))  # 연한 파란색
            self.list_log_widget.addItem(message)
            self.list_log_widget.setCurrentRow(self.list_log_widget.count() - 1)
#            self.list_log_widget.insertItem(0, message)
#            self.list_log_widget.setCurrentRow(0)

        def layout_QObject_setEnabled(self, layout, TrueFalse):
            for i in range(layout.count()):
                widget = layout.itemAt(i).widget()
                if widget is not None:
                    widget.setEnabled(TrueFalse)

        def on_editing_finished(self):
            cls_MyWindow.rearrange_directory()
#            print(self.line_edit_search_box.text())

        def make_file_location_from_editbox(self, search_text:str, target_dir:str, list_widget) -> list:
            if search_text == "":
                search_text = "*.*"
            else:
                search_text = "*" + search_text + "*"
            file_names = glob.glob(os.path.join(cls_common.dest_dir, search_text))
            return file_names        

        def but_1(self):
            cls_PopUpWindow = PopUpWindow(self)  # 부모 윈도우를 self로 설정하여 새로운 창을 생성
            cls_PopUpWindow.exec()  # 모달 창으로 수행. 자식 창이 닫힐 때까지 부모 윈도우를 비활성화 상태로 유지
            cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n화면 선택 = {self.current_monitor_title}{self.current_window_title}\n{cls_common.delimeter}")
#            self.button[0].setText(f"캡처화면 전환({cls_common.monitor_number})(&S)")
#            self.progress_finished_func_1()

        def but_2(self):
            if cls_Capture_Encrypt_Decrypt.get_key_from_user():
                cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 키 변경 성공\n{cls_common.delimeter}")
            self.progress_finished_func_1()
        def but_3(self):
            cls_Capture_Encrypt_Decrypt.capture_and_encrypt()
            self.progress_finished_func_1()
        def but_4(self):
            cls_Capture_Encrypt_Decrypt.decrypt_all_files()
            self.progress_finished_func_1()
        def but_5(self):
            self.checkbox_file_or_dir.setChecked(False)
            self.progress_finished_func_1()
            self.rearrange_directory(directory_rebuild = True)

        def open_cls_PopUpWindowdow(self):
            self.cls_PopUpWindow = PopUpWindow()  # 새로운 창 생성
            self.cls_PopUpWindow.show()  # 창 표시

        def rearrange_directory(self, directory_rebuild = False) -> None:
            cls_common.check_timeout_semaphore_exit()
            if directory_rebuild:
                old_directory = cls_common.current_directory
                cls_common.current_directory  = Path(QFileDialog.getExistingDirectory(self, "폴더 선택"))
                cls_common.dest_dir = Path(os.path.join(cls_common.current_directory, cls_common.subdirectory_name))
                cls_common.log_file = Path(os.path.join(cls_common.dest_dir, cls_common.log_file_name))
                cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 폴더 변경 {old_directory}\n    ->{cls_common.current_directory}\n{cls_common.delimeter}")
            file_count = 0
            self.list_file_dir_widget.clear()
            if pyQT:
                file_names = cls_MyWindow.make_file_location_from_editbox(cls_MyWindow.line_edit_search_box.text(), cls_common.dest_dir, self.list_file_dir_widget)
            else:
                file_names = glob.glob(os.path.join(cls_common.dest_dir, "*.json"))
            for i, file_name in enumerate(file_names):
                file_path = os.path.join(cls_common.current_directory, file_name)
                if os.path.isfile(file_path):
                    path = Path(file_name)
#                    self.list_file_dir_widget.addItem(path.name)
                    self.list_file_dir_widget.insertItem(0, path.name)
                    file_count = file_count + 1
#            self.list_file_dir_widget.setCurrentRow(self.list_file_dir_widget.count() - 1)
            self.list_file_dir_widget.setCurrentRow(0)
            self.list_file_dir_widget.setFocus()
#            a=self.list_file_dir_widget.currentItem().text()
#            print(f")))))s + {a}")
            self.label_file_th.setText(f"파일 갯수({file_count}개)")

        def list_file_viewer(self, item):
            try:
                file_path = Path(cls_common.dest_dir) / item.text()  # OS 독립적인 경로 생성
                file_path = file_path.resolve()
                os.startfile(str(file_path))  # 파일 열기
            except Exception as e:
                cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 파일 오픈 에러 - list_file_viewer!!\n{cls_common.delimeter}")
            return

    app = QApplication(sys.argv)
    cls_MyWindow = MyWindow()  # MyWindow 객체 생성
    cls_MyWindow.show()
    cls_MyWindow.rearrange_directory()
    cls_Capture_Encrypt_Decrypt = CLASS_Capture_Encrypt_Decrypt()
    sys.exit(app.exec())

else:
    cls_Capture_Encrypt_Decrypt = CLASS_Capture_Encrypt_Decrypt()
    if MENU_RUN:
        while True:
            imenu = cls_common.menu_display().lower()
            cls_common.check_timeout_semaphore_exit()
            if imenu == "k":
                if cls_Capture_Encrypt_Decrypt.get_key_from_user():
                    cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n!!! 키 변경 성공\n{cls_common.delimeter}", Console_On=True)
            elif imenu == "c":
                cls_Capture_Encrypt_Decrypt.capture_and_encrypt()
            elif imenu == "d":
                cls_Capture_Encrypt_Decrypt.decrypt_all_files()
            elif imenu == "s":
                cls_common.change_monitor()
            elif imenu == "q":
                cls_common.log_log(list_log_append = pyQT, message = f"{cls_common.delimeter}\n--- Program Exit by User\n{cls_common.delimeter}")
                break
    else:
        cls_common.menu_display()
        cls_common.timer_event_set()
        with keyboard.Listener(on_press = cls_common.on_press, on_release = cls_common.on_release) as listener:
            listener.join()
