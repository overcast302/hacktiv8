import asyncio
import sys

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDialog,
    QVBoxLayout, QHBoxLayout, QFormLayout,
    QPushButton, QLabel, QMessageBox,
    QLineEdit, QSpinBox, QDialogButtonBox
)
from PyQt5.QtCore import QSettings, Qt, QThread, pyqtSignal, QTimer

from pymobiledevice3.lockdown import create_using_usbmux

from exploits import get_exploit
from exploits.common import parse_version
from exploits.itunesstored.itunesstored import (
    DEFAULT_ATTEMPTS, DEFAULT_BACKEND_URL, ItunesstoredExploit
)


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
            asyncio.run(self.activate())
        except TimeoutError:
            self.error.emit(
                'Device did not reconnect in time. Please ensure it is connected and try again.'
            )
        except Exception as e:
            self.error.emit(repr(e))

    async def activate(self):
        lockdown = await create_using_usbmux()
        try:
            values = await lockdown.get_value()

            if values.get('ActivationState') == 'Activated':
                self.success.emit('Device is already activated')
                return

            exploit_cls = await get_exploit(
                parse_version(values.get('ProductVersion')), lockdown.udid
            )
            if exploit_cls is None:
                self.error.emit('Unsupported iOS version')
                return

            self.status.emit('Activating device...')
            await exploit_cls(log=self.status.emit, **self.settings).run(lockdown)
            self.success.emit('Done!')
        finally:
            await lockdown.close()


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

        self.settings_btn = QPushButton('\u2699')
        self.settings_btn.setFixedWidth(36)
        self.settings_btn.setToolTip('Settings')
        self.settings_btn.clicked.connect(self.open_settings)

        row = QHBoxLayout()
        row.setSpacing(4)
        row.addWidget(self.activate)
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

    def poll_device(self):
        async def detect():
            lockdown = await create_using_usbmux()
            try:
                values = await lockdown.get_value()

                product = values.get('ProductType')
                version = values.get('ProductVersion')
                build = values.get('BuildVersion')
                version_tuple = parse_version(version)
                exploit_cls = await get_exploit(version_tuple, lockdown.udid)
                return product, version, build, version_tuple, exploit_cls, lockdown.udid
            finally:
                await lockdown.close()

        try:
            product, version, build, version_tuple, exploit_cls, udid = asyncio.run(detect())
        except Exception:
            self._set_state('No device connected', False)
            return

        if exploit_cls is None:
            self._set_state(f'Unsupported {product} iOS version: {version}', False)
            return

        try:
            supported = asyncio.run(exploit_cls.available(product, build, udid, **self.settings))
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