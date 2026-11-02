import ssl
import subprocess
import sys
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDialog,
    QVBoxLayout, QHBoxLayout, QFormLayout,
    QPushButton, QLabel, QMessageBox,
    QLineEdit, QSpinBox, QDialogButtonBox
)
from PyQt5.QtCore import QSettings, Qt, QThread, pyqtSignal, QTimer

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.usbmux import list_devices
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.osu.os_utils import get_os_utils

from exploits import get_exploit
from exploits.common import parse_version
from exploits.itunesstored.itunesstored import (
    DEFAULT_ATTEMPTS, DEFAULT_BACKEND_URL, ItunesstoredExploit
)


OSUTILS = get_os_utils()


def load_settings():
    settings = QSettings()
    return {
        'backend_url': settings.value('backend_url', DEFAULT_BACKEND_URL, str),
        'attempts': settings.value('attempts', DEFAULT_ATTEMPTS, int),
    }


def save_settings(settings):
    out = QSettings()
    out.setValue('backend_url', settings['backend_url'])
    out.setValue('attempts', settings['attempts'])


class SettingsDialog(QDialog):
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Settings')

        self.backend_url = QLineEdit(settings['backend_url'])
        self.backend_url.setPlaceholderText(DEFAULT_BACKEND_URL)
        self.backend_url.setMinimumWidth(320)

        self.attempts = QSpinBox()
        self.attempts.setRange(1, 99)
        self.attempts.setValue(settings['attempts'])

        layout = QFormLayout(self)
        layout.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layout.addRow(QLabel('<b>itunesstored</b>'))
        layout.addRow('Backend URL:', self.backend_url)
        layout.addRow('Attempts:', self.attempts)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def values(self):
        return {
            'backend_url': self.backend_url.text().strip() or DEFAULT_BACKEND_URL,
            'attempts': self.attempts.value(),
        }


class ActivationThread(QThread):
    status = pyqtSignal(str)
    success = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, settings):
        super().__init__()
        self.settings = settings

    def run(self):
        try:
            lockdown = create_using_usbmux()
            values = lockdown.get_value()

            if values.get('ActivationState') == 'Activated':
                self.success.emit('Device is already activated')
                return

            exploit_cls = get_exploit(parse_version(values.get('ProductVersion')), lockdown.udid)
            if exploit_cls is None:
                self.error.emit('Unsupported iOS version')
                return

            self.status.emit('Activating device...')
            exploit_cls(log=self.status.emit, **self.settings).run(lockdown)
            self.success.emit('Done!')

        except TimeoutError:
            self.error.emit(
                'Device did not reconnect in time. Please ensure it is connected and try again.'
            )
        except Exception as e:
            self.error.emit(repr(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('hacktiv8 v1.2.2')
        self.setFixedSize(500, 200)

        self.version = (0,)
        self.settings = load_settings()

        self.status = QLabel('No device connected')
        self.activate = QPushButton('Activate Device')
        self.activate.setEnabled(False)

        self.rescan = QPushButton('Rescan')
        self.rescan.setToolTip('Delete the old pairing record and reconnect')
        self.rescan.clicked.connect(self.rescan_device)

        self.settings_btn = QPushButton('\u2699')
        self.settings_btn.setFixedWidth(36)
        self.settings_btn.setToolTip('Settings')
        self.settings_btn.clicked.connect(self.open_settings)

        row = QHBoxLayout()
        row.setSpacing(4)
        row.addWidget(self.activate)
        row.addWidget(self.rescan)
        row.addWidget(self.settings_btn)

        layout = QVBoxLayout()
        layout.addWidget(self.status)
        layout.addLayout(row)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.activate.clicked.connect(self.start_activation)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_device)
        self.timer.start(1000)

    def rescan_device(self):
        udid = self._connected_udid()
        if udid is None:
            self._set_state('No device connected', False)
            return

        self.status.setText('Clearing old pairing record...')
        QApplication.processEvents()

        removed, failed = self.clear_pairing(udid)
        if failed:
            self._set_state(
                'Cannot delete system pairing record. Run hacktiv8 as Administrator.',
                False)
            return

        self._restart_amds()
        self.poll_device()

    def _connected_udid(self):
        try:
            devices = list_devices()
        except Exception:
            return None
        return devices[0].serial if devices else None

    @staticmethod
    def _pairing_record_paths(udid):
        paths = []
        try:
            paths.append(Path(OSUTILS.pair_record_path) / f'{udid}.plist')
        except Exception:
            pass
        try:
            paths.append(get_home_folder() / f'{udid}.plist')
        except Exception:
            pass
        return paths

    def clear_pairing(self, udid):
        removed, failed = [], []
        for path in self._pairing_record_paths(udid):
            if not path.exists():
                continue
            try:
                path.unlink()
                removed.append(str(path))
            except PermissionError:
                failed.append(str(path))
        return removed, failed

    @staticmethod
    def _restart_amds():
        if sys.platform != 'win32':
            return
        for action in ('stop', 'start'):
            try:
                subprocess.run(
                    ['net', action, 'Apple Mobile Device Service'],
                    capture_output=True, timeout=30)
            except Exception:
                pass

    def poll_device(self):
        # Distinguish "nothing plugged in" from "plugged in but handshake failed".
        try:
            devices = list_devices()
        except Exception:
            devices = []

        if not devices:
            self._set_state('No device connected', False)
            return

        try:
            lockdown = create_using_usbmux()
            values = lockdown.get_value()

            product = values.get('ProductType')
            version = values.get('ProductVersion')
            build = values.get('BuildVersion')
            version_tuple = parse_version(version)
            exploit_cls = get_exploit(version_tuple, lockdown.udid)
        except (ConnectionError, TimeoutError, ssl.SSLError):
            self._set_state('Device connected but pairing failed. Re-pair via iTunes', False)
            return
        except Exception as e:
            self._set_state(f'Device connected, but lockdown error: {e}', False)
            return

        if exploit_cls is None:
            self._set_state(f'Unsupported {product} iOS version: {version}', False)
            return

        try:
            supported = exploit_cls.available(product, build, lockdown.udid, **self.settings)
        except Exception:
            self._set_state('Could not reach backend. Please check your internet connection!', False)
            return

        if not supported:
            self._set_state(exploit_cls.unavailable.format(product=product, version=version), False)
            return

        self.version = version_tuple
        self._set_state(f'Connected: {product} ({version})', True)

    def _set_state(self, text, enabled):
        self.status.setText(text)
        self.activate.setEnabled(enabled)

    def open_settings(self):
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec_() == QDialog.Accepted:
            self.settings = dialog.values()
            save_settings(self.settings)

    def start_activation(self):
        if ItunesstoredExploit.supports(self.version):
            note = 'Please ensure it is connected to Wi-Fi.'
        else:
            note = 'Your device will reboot during the process.'
        QMessageBox.information(
            self,
            'Info',
            'Your device will now be activated. ' + note
        )

        self.timer.stop()
        self.activate.setEnabled(False)

        self.worker = ActivationThread(self.settings)
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