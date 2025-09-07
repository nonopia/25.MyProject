from cryptography.hazmat.primitives import hashes    #pip install cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QInputDialog, QListWidget, QListWidgetItem, QFileDialog, QLabel, QStyledItemDelegate, QProgressBar, QCheckBox, QMessageBox, QGroupBox, QRadioButton, QListWidget, QButtonGroup, QDialog  #pip install pyQT6
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QEvent, QRegularExpression
from PyQt6.QtGui import QColor, QPen, QRegularExpressionValidator, QIntValidator

from datetime import datetime, date, timedelta
from pathlib import Path

import time
import base64
import os
import sys
import random
import json
import inspect
import re

import PyInstaller.__main__ #python make_access_info.py --build
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
#        f'--icon={os.path.join(".", "30_completed", "snap_crypt_icon.ico")}',
#        f'--add-data={os.path.join(".", "remote_info.json")}{separator}.', # ./1.json이 실행시에는 _MEI/1.json에 위치
#        f'--add-data={os.path.join(".", "data", "remote_info.json")}{separator}config', #./data/1.json이 실행시에는 _MEI/config/1.json에 위치
#        '--hidden-import=pyscreeze', '--hidden-import=pillow', '--hidden-import=numpy',
#        '--exclude-module=pwd', '--exclude-module=grp', '--exclude-module=fcntl', '--exclude-module=termios', '--exclude-module=PyQt5'
    ])
    sys.exit(0)

pyQT = True

class ConfigKeys:
    SCAN_METHOD = "scan method(local/remote/query)"
    SUDO_COMMAND = "sudo command('sudo' | else)"
    REMOTE_HOST_IP = "remote host IP"
    REMOTE_HOST_PORT = "remote host port"
    REMOTE_HOST_ROOT_ACCOUNT = "remote host root account"
    REMOTE_HOST_ROOT_PASSWORD = "remote host root password"
    DATABASE_NAME = "database name"
    DATABASE_ADMIN_NAME = "database admin name"
    DATABASE_PASSWORD = "database password"
    DATABASE_PORT = "database port"
    BLOCK_NAME = "block name"

class CLASS_crypto_gen():
    def __init__(self, password = "nono"):    
        self.time_minute = 60
        self.time_hour = self.time_minute * 60
        self.time_day = self.time_hour * 24
        self.time_baseline = self.time_day
        self.today = time.time()
        self.password = password
        self.target_day = None
        self.json_file_name = "_access_info_company.json"
        self.json_data = {
            "basic": {
                ConfigKeys.SCAN_METHOD: "",
                ConfigKeys.SUDO_COMMAND: "else",
                ConfigKeys.REMOTE_HOST_IP: "",
                ConfigKeys.REMOTE_HOST_PORT: "",
                ConfigKeys.REMOTE_HOST_ROOT_ACCOUNT: "",
                ConfigKeys.REMOTE_HOST_ROOT_PASSWORD: "",
                ConfigKeys.DATABASE_NAME: "",
                ConfigKeys.DATABASE_ADMIN_NAME: "",
                ConfigKeys.DATABASE_PASSWORD: "",
                ConfigKeys.DATABASE_PORT: "",
                ConfigKeys.BLOCK_NAME: "",
            }
        }

    def make_key_ciper(self, general_info, target_day, target_margin, password): 
        combined_input = general_info.encode("ascii") + target_day.encode("ascii") + target_margin.encode("ascii") + password.encode("ascii")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt = combined_input, iterations=1000)
        key = base64.urlsafe_b64encode(kdf.derive(combined_input)) 
        self.cipher = Fernet(key)

    def encrypt_data(self, data_bytes, general_info, target_day, target_margin, password) -> bytes:
        self.make_key_ciper(str(general_info), str(target_day), str(target_margin), password)
        encrypted_data = self.cipher.encrypt(data_bytes)
        return encrypted_data

    def decrypt_data(self, data_bytes, general_info, target_day, target_margin, password) -> bytes:
        try:
            self.make_key_ciper(str(general_info), str(target_day), str(target_margin), password)
            encrypted_data = self.cipher.decrypt(data_bytes)
            return encrypted_data
        except Exception as e:
            return None

    def encrypt(self):
        today = time.time()
        s_today = str(today)
        b_today = s_today.encode("utf-8")
        enc_today = self.encrypt_data(b_today, self.json_data["common"].get("general info", ""), self.json_data["common"].get("targ_da", "0"), self.json_data["common"].get("targ_va", "0"), self.password)
        decode_enc_today = enc_today.decode("utf-8")
        self.json_data["common"]["enprev"] = decode_enc_today

    def decrypt(self):
        try:
            enco_enc_data = self.json_data["common"].get('enprev', "None").encode("utf-8")
            b_today = self.decrypt_data(enco_enc_data, self.json_data["common"].get('general info', ""), self.json_data["common"].get('targ_da', "0"), self.json_data["common"].get('targ_va', "0"), self.password)
            if b_today is None:
                self.log_system_info(True, "Fatal error : decrypt error. Exiting program..." , inspect.getframeinfo(inspect.currentframe()).function)
            s_today = b_today.decode("utf-8")
        except:
            self.log_system_info(True, "Fatal error : corrupted file format. Exiting program..." , inspect.getframeinfo(inspect.currentframe()).function)
        return s_today


#    def get_data_location(self, filename):
#        if getattr(sys, 'frozen', False):  #빌드
#            base_path = sys._MEIPASS
#        else:
#            base_path = os.path.abspath(".")  #개발 환경
#        return os.path.join(base_path, filename)

    def get_target_margin(self):
        while True:
            try:
                target_day = float(input("현재로부터 유효기간(일) : "))
                break
            except ValueError:
                print("소수점이 포함된 숫자만 가능")
        self.json_data["common"]["targ_da"] = str(target_day * self.time_baseline) 
        self.json_data["common"]["targ_va"] = str(target_day * 0.37 * self.time_baseline)
        return
        while True:
            try:
                target_margin = float(input("유효기간 마진 일수(유효기간의 1/3 ~ 1/4 정도) : "))
                break
            except ValueError:
                print("소수점이 포함된 숫자만 가능")
        return target_day, target_margin

    def log_system_info(self, exit_on:bool = True, err_message: str="", func_name: str=""):
        print(f'{err_message} ------ {func_name}\n', False)
        if exit_on:
            input(f'{err_message}... Press Enter Key')
            sys.exit()

if pyQT:
    class MyWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Info_Gen")  # 창 제목 설정

            self.setFixedSize(600, 400)  # 화면 크기 고정
            self.central_widget = QWidget(self)  # 중앙 위젯 생성
            self.setCentralWidget(self.central_widget)
            self.main_layout = QVBoxLayout()  # 전체 수직 레이아웃

            # 입력 정보 설정
            self.line_edit_block_name = self.make_QLine_Edit("Block name")
            self.line_edit_IP = self.make_QLine_Edit("remote IP")
            self.line_edit_port = self.make_QLine_Edit("remote port")
            ip_regex = QRegularExpression(
                r"^(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\."
                r"(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\."
                r"(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\."
                r"(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$"
            )
            port_regex = QRegularExpression(
                r"^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5]?[0-9]{1,4}|0)$"
            )
            validator = QRegularExpressionValidator(ip_regex, self.line_edit_IP)
            self.line_edit_IP.setValidator(validator)
            validator = QRegularExpressionValidator(port_regex, self.line_edit_port)
            self.line_edit_port.setValidator(validator)

            self.line_edit_root = self.make_QLine_Edit("remote account")
            self.line_edit_root_password = self.make_QLine_Edit("remote password")

            self.line_edit_input_layout1 = QHBoxLayout()
            self.line_edit_input_layout1.addWidget(self.line_edit_block_name)
            self.line_edit_input_layout1.addWidget(self.line_edit_IP)
            self.line_edit_input_layout1.addWidget(self.line_edit_port)
            self.line_edit_input_layout1.addWidget(self.line_edit_root)
            self.line_edit_input_layout1.addWidget(self.line_edit_root_password)

            self.line_edit_db_name = self.make_QLine_Edit("DB name")
            self.line_edit_db_admin = self.make_QLine_Edit("DB admin name")
            self.line_edit_db_admin_password = self.make_QLine_Edit("DB admin password")
            self.line_edit_db_port = self.make_QLine_Edit("DB port")
            self.line_edit_db_port.setValidator(QIntValidator(0, 1000000, self))

            self.line_edit_input_layout2 = QHBoxLayout()
            self.line_edit_input_layout2.addWidget(self.line_edit_db_name)
            self.line_edit_input_layout2.addWidget(self.line_edit_db_admin)
            self.line_edit_input_layout2.addWidget(self.line_edit_db_admin_password)
            self.line_edit_input_layout2.addWidget(self.line_edit_db_port)

            self.line_edit_general_info = self.make_QLine_Edit(f"General info(ex: {datetime.today().strftime('%Y-%m-%d')} / Hello_world.com / ubuntu 7.5 / mySQL 5.4)")

            # 입력 정보 그룹
            self.input_group = QGroupBox("입력 정보")
            input_layout = QVBoxLayout()
            input_layout.addLayout(self.line_edit_input_layout1)
            input_layout.addLayout(self.line_edit_input_layout2)
            input_layout.addWidget(self.line_edit_general_info)
            self.input_group.setLayout(input_layout)

            # Scan Method 그룹
            self.scan_method_group = QGroupBox("Scan Method")
            scan_method_layout = QHBoxLayout()            
            self.radio_group = QButtonGroup(self)

            self.radio_undefined = QRadioButton("미정", self)
            self.radio_local = QRadioButton("Local", self)
            self.radio_remote = QRadioButton("Remote", self)
            self.radio_query = QRadioButton("Query", self)

            self.radio_undefined.setChecked(True)  # "미정" 버튼을 기본으로 선택

            self.radio_group.addButton(self.radio_undefined)
            self.radio_group.addButton(self.radio_local)
            self.radio_group.addButton(self.radio_remote)
            self.radio_group.addButton(self.radio_query)

            scan_method_layout.addWidget(self.radio_undefined)  # "미정"을 첫 번째로 추가
            scan_method_layout.addWidget(self.radio_local)
            scan_method_layout.addWidget(self.radio_remote)
            scan_method_layout.addWidget(self.radio_query)

            self.scan_method_group.setLayout(scan_method_layout)

            # Sudo 그룹 생성 및 단일 라디오 버튼 추가
            self.sudo_group = QGroupBox("Sudo")
            sudo_layout = QVBoxLayout()

            self.radio_sudo = QRadioButton("Sudo 모드", self)
            self.radio_sudo.setStyleSheet("font-size: 12px;")
            self.radio_sudo.setChecked(False)  # 기본값은 비활성화 상태 (선택 안 됨)

            sudo_layout.addWidget(self.radio_sudo)
            self.sudo_group.setLayout(sudo_layout)

            # Scan Method + Sudo 그룹을 수평으로 정렬
            scan_sudo_layout = QHBoxLayout()
            scan_sudo_layout.addWidget(self.scan_method_group, 4)
            scan_sudo_layout.addWidget(self.sudo_group, 1)

            # 버튼 설정
            Button_Info = [["생성(&G)", self.but_1], ["검증(&V)", self.but_2]]
            self.button_layout = QVBoxLayout()
            self.button = []
            for i in range(len(Button_Info)):
                self.button.append(QPushButton(Button_Info[i][0], self))  # 버튼 생성
                self.button[i].setFixedHeight(30)  # 버튼 높이
                self.button[i].setStyleSheet("font-size: 12px;")  # 버튼 스타일
                self.button[i].clicked.connect(Button_Info[i][1])  # 버튼 실행 함수 연결
                self.button_layout.addWidget(self.button[i])  # layout에 배치

            self.log_layout = QVBoxLayout()
            self.list_log_widget = QListWidget(self)
            self.list_log_widget.setStyleSheet("font-size: 12px;")
            self.log_layout.addWidget(self.list_log_widget)

            # 입력 정보 그룹 + (Scan Method + Sudo 그룹) 수직 배치
            left_layout = QVBoxLayout()
            left_layout.setSpacing(0)
            left_layout.addWidget(self.input_group)
            left_layout.addLayout(scan_sudo_layout)

            # 좌측 레이아웃과 버튼을 수평으로 배치
            right_layout = QHBoxLayout()
            right_layout.addLayout(left_layout)
            right_layout.addLayout(self.button_layout)

            # 전체 구성
            self.main_layout.addLayout(right_layout)
            self.main_layout.addLayout(self.log_layout)
            self.central_widget.setLayout(self.main_layout)

        def make_QLine_Edit(self, PlaceholderText):
            self.LineEdit = QLineEdit(self)
            self.LineEdit.setPlaceholderText(PlaceholderText)
            return self.LineEdit

        class ListDelegate(QStyledItemDelegate):
            def paint(self, painter, option, index):
                super().paint(painter, option, index)
                painter.setPen(QPen(QColor("black"), 1))  # 검은색 구분선 (두께 1px)
                painter.drawLine(option.rect.bottomLeft(), option.rect.bottomRight())

        def append_text_2_list_log(self, message):
            item = QListWidgetItem(message)
            if self.list_log_widget.count() % 2 == 0:
                item.setBackground(QColor("#f0f0f0"))  # 연한 회색
            else:
                item.setBackground(QColor("#d0e8ff"))  # 연한 파란색
            list_data = message.split("\n")
            for i in range(len(list_data)):
                self.list_log_widget.addItem(list_data[i])
            self.list_log_widget.setCurrentRow(self.list_log_widget.count() - 1)
            self.list_log_widget.addItem("")            
#            self.list_log_widget.insertItem(0, message)
#            self.list_log_widget.setCurrentRow(0)

        def get_key_from_user(self, CLASS_arg) -> bool:
            unuseful_key_value = True
            old_key = CLASS_arg.target_day
            ok = True
            while unuseful_key_value:
                if pyQT:
                    target_day, ok = QInputDialog.getText(cls_MyWindow, "유효기간 입력", "소수점이 포함된 일수 입력")
                try:
                    target_day = float(target_day)
                    if ok == True:
                        CLASS_arg.target_day = str(target_day)
#                        CLASS_arg.json_data["common"]["targ_da"] = str(target_day * CLASS_arg.time_baseline) 
#                        CLASS_arg.json_data["common"]["targ_va"] = str(target_day * 0.37 * CLASS_arg.time_baseline)
                        return target_day
                    if ok == False:
                        CLASS_arg.target_day = None
                        return False
                except ValueError:
                        CLASS_arg.target_day = None
                        return False
                else:
                    while True:
                        try:
                            target_day = float(input("현재로부터 유효기간(일) : "))
                            break
                        except ValueError:
                            print("소수점이 포함된 숫자만 가능")
                    self.json_data["common"]["targ_da"] = str(target_day * self.time_baseline) 
                    self.json_data["common"]["targ_va"] = str(target_day * 0.37 * self.time_baseline)
                    return
                    while True:
                        try:
                            target_margin = float(input("유효기간 마진 일수(유효기간의 1/3 ~ 1/4 정도) : "))
                            break
                        except ValueError:
                            print("소수점이 포함된 숫자만 가능")
                    return target_day, target_margin

        def generate_process(self, CLASS_arg):
            return_value = self.get_key_from_user(CLASS_arg)
            if  return_value is False:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Icon.Information)
                msg.setText("소수점이 포함된 숫자만 허용됩니다.")
                msg.setWindowTitle("알림")
                msg.setStandardButtons(QMessageBox.StandardButton.Ok)
                msg.exec()
                return

            is_sudo = "else"
            if self.radio_undefined.isChecked(): 
                is_remote = ""
            if self.radio_local.isChecked(): 
                is_remote = "local"
            if self.radio_remote.isChecked(): 
                is_remote = "remote"
            if self.radio_query.isChecked(): 
                is_remote = "query"
            if self.radio_sudo.isChecked(): 
                is_sudo = "sudo"
            today = date.today()
            future_date = today + timedelta(int(return_value))
            CLASS_arg.json_data.update({
                str(self.line_edit_block_name.text().strip()): {
                    ConfigKeys.SCAN_METHOD: is_remote,
                    ConfigKeys.SUDO_COMMAND: is_sudo,
                    ConfigKeys.REMOTE_HOST_IP: str(self.line_edit_IP.text()).strip(),
                    ConfigKeys.REMOTE_HOST_PORT: str(self.line_edit_port.text()).strip(),
                    ConfigKeys.REMOTE_HOST_ROOT_ACCOUNT: str(self.line_edit_root.text()).strip(),
                    ConfigKeys.REMOTE_HOST_ROOT_PASSWORD: str(self.line_edit_root_password.text()).strip(),
                    ConfigKeys.DATABASE_NAME: str(self.line_edit_db_name.text()).strip(),
                    ConfigKeys.DATABASE_ADMIN_NAME: str(self.line_edit_db_admin.text()).strip(),
                    ConfigKeys.DATABASE_PASSWORD: str(self.line_edit_db_admin_password.text()).strip(),
                    ConfigKeys.DATABASE_PORT: str(self.line_edit_db_port.text()).strip(),
                    ConfigKeys.BLOCK_NAME: str(self.line_edit_block_name.text()).strip(),
                },
                "common": {
                    "general info": str(self.line_edit_general_info.text()).strip() + f"_{today}_Mat+{return_value}",
                    "base": str(CLASS_arg.time_baseline),
                    "targ_da": str(float(CLASS_arg.target_day) * float(CLASS_arg.time_baseline)),
                    "targ_va": str(float(CLASS_arg.target_day) * 0.37 * float(CLASS_arg.time_baseline)),
                    "enprev": ""
                }
            })
            CLASS_arg.encrypt()
            json_format = json.dumps(CLASS_arg.json_data, indent="\t", ensure_ascii=False)
            with open(f'{CLASS_arg.json_file_name}', "w", encoding="utf-8") as f:
                f.write(json_format)
            self.log_log(pyQT, f"{CLASS_arg.json_file_name} 생성을 완료하였습니다.")
            self.log_log(pyQT, f"{json_format}")
            if pyQT is False:
                input(f"아무키나 누르세요.")

        def verification_process(self, CLASS_arg):
            json_file = Path(os.path.join(Path(os.path.join(os.getcwd())), f'{CLASS_arg.json_file_name}'))
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    CLASS_arg.json_data = json.load(f)
            except:
                self.log_log(pyQT, f'{CLASS_arg.json_file_name}이 없거나 형식이 다릅니다.')
                return
            json_format = json.dumps(CLASS_arg.json_data, indent="\t", ensure_ascii=False)
            self.log_log(pyQT, f"{json_format}")
            today_tick = time.time()
            prev_tick = float(CLASS_arg.decrypt())
            prev_day_localtime = time.localtime(prev_tick)
            target_day_tick = float(CLASS_arg.json_data["common"].get("targ_da", 0))
            target_day_localtime = time.localtime(prev_tick + target_day_tick)
            target_variance_tick = float(CLASS_arg.json_data["common"].get("targ_va", 0))
            random_variance_tick  = target_variance_tick * 2 - target_variance_tick
        #    random_variance_tick  = (random.random() * float(target_variance_tick) * 2) - float(target_variance_tick)
            day_gap_tick = today_tick - prev_tick - random_variance_tick
            min_day = time.localtime(prev_tick + float(CLASS_arg.json_data["common"].get("targ_da", 0)) - random_variance_tick)
            max_day = time.localtime(prev_tick + float(CLASS_arg.json_data["common"].get("targ_da", 0)) + random_variance_tick)
            output_message = f'랜덤 변화량 : {(target_variance_tick/60/60/24):.2f} 일\n'
            output_message = f'{output_message}종료 기준 시간 : {target_day_localtime.tm_year}년 {target_day_localtime.tm_mon}월 {target_day_localtime.tm_mday}일 {target_day_localtime.tm_hour}시 {target_day_localtime.tm_min}분\n'
            output_message = f'{output_message}최소 유효 시간 : {min_day.tm_year}년 {min_day.tm_mon}월 {min_day.tm_mday}일 {min_day.tm_hour}시 {min_day.tm_min}분\n'
            output_message = f'{output_message}최대 유효 시간 : {max_day.tm_year}년 {max_day.tm_mon}월 {max_day.tm_mday}일 {max_day.tm_hour}시 {max_day.tm_min}분\n'
            output_message = f'{output_message}최소 유효 시간과 최대 유효 시간내에서 실행시마다 랜덤 변화량만큼 변화되어 적용됩니다.\n'
            self.log_log(pyQT, output_message)
#            self.log_log(pyQT, f'{CLASS_arg.json_file_name} 의 검증 결과')
#            self.log_log(pyQT, f'랜덤 변화량 : {(target_variance_tick/60/60/24):.2f} 일')
#            self.log_log(pyQT, f'종료 기준 시간 : {target_day_localtime.tm_year}년 {target_day_localtime.tm_mon}월 {target_day_localtime.tm_mday}일 {target_day_localtime.tm_hour}시 {target_day_localtime.tm_min}분')
#            self.log_log(pyQT, f'최소 유효 시간 : {min_day.tm_year}년 {min_day.tm_mon}월 {min_day.tm_mday}일 {min_day.tm_hour}시 {min_day.tm_min}분')
#            self.log_log(pyQT, f'최대 유효 시간 : {max_day.tm_year}년 {max_day.tm_mon}월 {max_day.tm_mday}일 {max_day.tm_hour}시 {max_day.tm_min}분')
#            self.log_log(pyQT, f'최소 유효 시간과 최대 유효 시간내에서 실행시마다 랜덤 변화량만큼 변화되어 적용됩니다.')
            if day_gap_tick > float(CLASS_arg.json_data["common"].get("targ_da", 0)):
                output_message = f'{output_message}이미 최대 유효 기간이 지났습니다.'
                self.log_log(pyQT, output_message)
                if pyQT is False:
                    input("Enter 키를 누르세요...")
                    sys.exit()
            else:
                output_message = f'{output_message}아직 최대 유효 기간이 남았습니다.'

        def log_log(self, list_log_append:bool = False , message: str = "") -> None:
            if list_log_append:
               self.append_text_2_list_log(f'--- {message}')
            else:
               print(f'--- {message}')

        def but_1(self):
            cls_crypto_gen = CLASS_crypto_gen()
            if (self.line_edit_block_name.text().strip() == "") or re.search("[ㄱ-ㅎ가-힣]", self.line_edit_general_info.text().strip()):
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Icon.Information)
                msg.setText("Block name 은 빈칸이 허용되지 않고\nGeneral Info 는 영어, 문자, 숫자, 특수문자만 가능합니다.")
                msg.setWindowTitle("알림")
                msg.setStandardButtons(QMessageBox.StandardButton.Ok)
                msg.exec()
                return
            self.generate_process(cls_crypto_gen)

        def but_2(self):
            cls_crypto_gen = CLASS_crypto_gen()
            self.verification_process(cls_crypto_gen)

    app = QApplication(sys.argv)
    cls_MyWindow = MyWindow()  # MyWindow 객체 생성
    cls_MyWindow.show()
    sys.exit(app.exec())

else:
    mode = input("remote_info.json [generation(1) | verification(2)] : ")
    if mode == "1":
        cls_crypto_gen = CLASS_crypto_gen()

        cls_crypto_gen.get_target_margin()
        cls_crypto_gen.encrypt()
        json_format = json.dumps(cls_crypto_gen.json_data, indent="\t", ensure_ascii=False)
        with open(f'{cls_crypto_gen.json_file_name}', "w", encoding="utf-8") as f:
            f.write(json_format)
        print(json_format)
        input(f".{cls_crypto_gen.json_file_name} 생성을 완료하였습니다.")

    else:
        cls_crypto_gen = CLASS_crypto_gen()
        json_file = Path(os.path.join(Path(os.path.join(os.getcwd())), f'{cls_crypto_gen.json_file_name}'))
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                cls_crypto_gen.json_data = json.load(f)
        except:
            input("Fatal error : corrupted file format")
            sys.exit()
        today_tick = time.time()
        prev_tick = float(cls_crypto_gen.decrypt())
        prev_day_localtime = time.localtime(prev_tick)
        target_day_tick = float(cls_crypto_gen.json_data["common"].get("targ_da", 0))
        target_day_localtime = time.localtime(prev_tick + target_day_tick)
        target_variance_tick = float(cls_crypto_gen.json_data["common"].get("targ_va", 0))
        random_variance_tick  = target_variance_tick * 2 - target_variance_tick
    #    random_variance_tick  = (random.random() * float(target_variance_tick) * 2) - float(target_variance_tick)
        day_gap_tick = today_tick - prev_tick - random_variance_tick
        min_day = time.localtime(prev_tick + float(cls_crypto_gen.json_data["common"].get("targ_da", 0)) - random_variance_tick)
        max_day = time.localtime(prev_tick + float(cls_crypto_gen.json_data["common"].get("targ_da", 0)) + random_variance_tick)
        print(f'랜덤 변화량 : {(target_variance_tick/60/60/24):.2f} 일')
        print(f'종료 기준 시간 : {target_day_localtime.tm_year}년 {target_day_localtime.tm_mon}월 {target_day_localtime.tm_mday}일 {target_day_localtime.tm_hour}시 {target_day_localtime.tm_min}분')
        print(f'최소 유효 시간 : {min_day.tm_year}년 {min_day.tm_mon}월 {min_day.tm_mday}일 {min_day.tm_hour}시 {min_day.tm_min}분')
        print(f'최대 유효 시간 : {max_day.tm_year}년 {max_day.tm_mon}월 {max_day.tm_mday}일 {max_day.tm_hour}시 {max_day.tm_min}분')
        print(f'최소 유효 시간과 최대 유효 시간내에서 실행시마다 랜덤 변화량만큼 변화되어 적용됩니다.')
        if day_gap_tick > float(cls_crypto_gen.json_data["common"].get("targ_da", 0)):
            input("\n이미 최대 유효 기간이 지났습니다.")
            sys.exit()
        else:
            input("\n아직 최대 유효 기간이 남았습니다.")

