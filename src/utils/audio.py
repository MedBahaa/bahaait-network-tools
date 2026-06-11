import os
import platform

# Always try to import winsound on Windows for fallback
WINSOUND_AVAILABLE = False
if platform.system() == "Windows":
    try:
        import winsound
        WINSOUND_AVAILABLE = True
    except ImportError:
        pass

try:
    from PySide6.QtMultimedia import QSoundEffect, QMediaPlayer, QAudioOutput
    from PySide6.QtCore import QUrl
    QT_AUDIO = True
except ImportError:
    QT_AUDIO = False

class AlarmManager:
    def __init__(self):
        self.player = None
        self.audio_output = None
        self.enabled = True
        self.winsound_playing = False
        self.current_source = ""
        
        if QT_AUDIO:
            self.player = QMediaPlayer()
            self.audio_output = QAudioOutput()
            self.player.setAudioOutput(self.audio_output)
            self.audio_output.setVolume(1.0)
            
            # Loop logic (PySide6 style)
            self.player.setLoops(QMediaPlayer.Loops.Infinite)
            
            # Default alarm
            default_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "alarm.wav"))
            self.set_source(default_path)

    def set_source(self, file_path):
        if not QT_AUDIO or not self.player:
            return False
            
        if os.path.exists(file_path):
            self.current_source = file_path
            self.player.setSource(QUrl.fromLocalFile(file_path))
            return True
        return False

    def play(self):
        if not self.enabled:
            return
            
        if QT_AUDIO and self.player:
            if self.player.playbackState() != QMediaPlayer.PlaybackState.PlayingState:
                self.player.play()
        elif WINSOUND_AVAILABLE and not self.winsound_playing:
            import threading
            import time
            def _beep_loop():
                self.winsound_playing = True
                while self.winsound_playing:
                    winsound.Beep(1000, 500)
                    time.sleep(0.1)
                self.winsound_playing = False
            
            threading.Thread(target=_beep_loop, daemon=True).start()

    def stop(self):
        if QT_AUDIO and self.player:
            self.player.stop()
        self.winsound_playing = False

    def set_enabled(self, status):
        self.enabled = status
        if not status:
            self.stop()
