import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
from PySide6.QtCore import QThread, Signal
from utils.config import ConfigManager
from datetime import datetime

class EmailNotifier:
    def __init__(self, logger=None, config_manager=None):
        self.config_manager = config_manager if config_manager is not None else ConfigManager()
        self.logger = logger

    def _log_info(self, message):
        if self.logger:
            self.logger.info(message)
        else:
            print(f"[INFO] {message}")

    def _log_error(self, message):
        if self.logger:
            self.logger.error(message)
        else:
            print(f"[ERROR] {message}")

    def send_status_email_async(self, host: str, label: str, status: str, latency: int, details: str):
        """Spawns a background thread to send a status alert/recovery email."""
        # Read current config values
        enabled = self.config_manager.get("email_alerts_enabled", False)
        if not enabled:
            return

        # Filter notification status based on user preference
        if status.upper() == "UP":
            notify = self.config_manager.get("email_alert_on_up", True)
        elif status.upper() == "DOWN":
            notify = self.config_manager.get("email_alert_on_down", True)
        else:
            notify = True

        if not notify:
            return

        thread = threading.Thread(
            target=self._send_status_email_sync,
            args=(host, label, status, latency, details),
            daemon=True
        )
        thread.start()

    def _send_status_email_sync(self, host: str, label: str, status: str, latency: int, details: str):
        use_custom = self.config_manager.get("email_use_custom_smtp", False)
        if use_custom:
            smtp_host = self.config_manager.get("email_smtp_host", "smtp.gmail.com")
            smtp_port = int(self.config_manager.get("email_smtp_port", 465))
            smtp_user = self.config_manager.get("email_smtp_user", "")
            smtp_pass = self.config_manager.get("email_smtp_password", "")
            sender = self.config_manager.get("email_sender", "")
        else:
            import base64
            smtp_host = "smtp.gmail.com"
            smtp_port = 465
            smtp_user = base64.b64decode(b"YmFoYWFpdG5ldHdvcmt0b29sc0BnbWFpbC5jb20=").decode("utf-8")
            smtp_pass = base64.b64decode(b"cmdzcm9kZ2d0ZmJwc2hhag==").decode("utf-8")
            sender = base64.b64decode(b"YmFoYWFpdG5ldHdvcmt0b29sc0BnbWFpbC5jb20=").decode("utf-8")
            
        recipient = self.config_manager.get("email_recipient", "")

        if not smtp_user or not smtp_pass or not recipient:
            self._log_error("Email notification skipped: SMTP credentials or recipient missing.")
            return

        subject = f"[BahaaIT Network Alert] {label} ({host}) is {status}!"
        
        # HTML template
        status_color = "#10B981" if status == "UP" else "#F43F5E"
        status_bg = "rgba(16, 185, 129, 0.1)" if status == "UP" else "rgba(244, 63, 94, 0.1)"
        
        html_content = f"""
        <html>
        <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0F172A; color: #F1F5F9; padding: 20px; margin: 0;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #1E293B; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.05); overflow: hidden; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);">
                <!-- Header -->
                <div style="background-color: #0F172A; padding: 25px; text-align: center; border-bottom: 2px solid #6366F1;">
                    <h1 style="color: #FFFFFF; font-size: 24px; font-weight: 800; margin: 0; letter-spacing: 1px;">BahaaIT Network Tools</h1>
                    <p style="color: #94A3B8; font-size: 14px; margin: 5px 0 0 0;">Real-time Alerting System</p>
                </div>
                
                <!-- Content -->
                <div style="padding: 30px;">
                    <div style="text-align: center; margin-bottom: 30px; padding: 15px; border-radius: 10px; background-color: {status_bg}; border: 1px solid {status_color};">
                        <span style="font-size: 14px; font-weight: 700; text-transform: uppercase; color: #94A3B8; letter-spacing: 1.5px;">Device Status Change</span>
                        <h2 style="color: {status_color}; font-size: 32px; font-weight: 900; margin: 10px 0;">{status}</h2>
                    </div>
                    
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 30px;">
                        <tr>
                            <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); color: #94A3B8; font-size: 14px; font-weight: 600; width: 40%;">Device Label</td>
                            <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); color: #FFFFFF; font-size: 14px; font-weight: 700;">{label}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); color: #94A3B8; font-size: 14px; font-weight: 600;">Host Address</td>
                            <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); color: #6366F1; font-size: 14px; font-family: monospace; font-weight: 700;">{host}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); color: #94A3B8; font-size: 14px; font-weight: 600;">Current Latency</td>
                            <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); color: #FFFFFF; font-size: 14px;">{latency} ms</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); color: #94A3B8; font-size: 14px; font-weight: 600;">Timestamp</td>
                            <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); color: #FFFFFF; font-size: 14px;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); color: #94A3B8; font-size: 14px; font-weight: 600;">Details</td>
                            <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); color: #F1F5F9; font-size: 13px; font-family: monospace;">{details}</td>
                        </tr>
                    </table>
                    
                    <div style="border-top: 1px solid rgba(255, 255, 255, 0.05); padding-top: 20px; text-align: center; color: #64748B; font-size: 12px;">
                        This email was automatically generated by BahaaIT Network Tools.
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

        # Plain text alternative
        text_content = (
            f"[BahaaIT Network Alert] {label} ({host}) is {status}!\n\n"
            f"Device Label: {label}\n"
            f"Host Address: {host}\n"
            f"Current Latency: {latency} ms\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Details: {details}\n\n"
            f"This email was automatically generated by BahaaIT Network Tools."
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = formataddr((str(Header("Bahaa IT Network Tools", "utf-8")), sender))
        msg["To"] = recipient
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        try:
            self._send_raw_smtp(smtp_host, smtp_port, smtp_user, smtp_pass, sender, recipient, msg.as_string())
            self._log_info(f"Alert email sent successfully to {recipient} for host {host} ({status})")
        except Exception as e:
            self._log_error(f"Failed to send email to {recipient}: {e}")

    def _send_raw_smtp(self, host, port, user, password, sender, recipient, msg_str):
        # Determine port and security protocol
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=10) as server:
                server.login(user, password)
                server.sendmail(sender, recipient, msg_str)
        else:
            with smtplib.SMTP(host, port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(user, password)
                server.sendmail(sender, recipient, msg_str)


class EmailTestWorker(QThread):
    """Worker QThread to run a SMTP test email connection asynchronously from the settings UI."""
    finished_signal = Signal(bool, str) # success, message

    def __init__(self, smtp_host, smtp_port, smtp_user, smtp_pass, sender, recipient):
        super().__init__()
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.sender = sender
        self.recipient = recipient

    def run(self):
        subject = "[BahaaIT] Test Email Connection"
        html_content = f"""
        <html>
        <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0F172A; color: #F1F5F9; padding: 20px; margin: 0;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #1E293B; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.05); overflow: hidden; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);">
                <div style="background-color: #0F172A; padding: 25px; text-align: center; border-bottom: 2px solid #6366F1;">
                    <h1 style="color: #FFFFFF; font-size: 24px; font-weight: 800; margin: 0; letter-spacing: 1px;">BahaaIT Network Tools</h1>
                </div>
                <div style="padding: 30px; text-align: center;">
                    <h2 style="color: #10B981; font-size: 24px; margin-top: 0;">Connection Successful!</h2>
                    <p style="color: #E2E8F0; font-size: 15px; line-height: 1.6;">
                        Your SMTP email settings configuration is correct. BahaaIT is now ready to send you real-time alerts when monitored network equipment goes offline.
                    </p>
                    <div style="background-color: rgba(99, 102, 241, 0.05); border: 1px dashed rgba(99, 102, 241, 0.2); padding: 15px; border-radius: 8px; margin: 20px 0; text-align: left; font-size: 13px;">
                        <strong>SMTP Server:</strong> {self.smtp_host}<br/>
                        <strong>SMTP User:</strong> {self.smtp_user}<br/>
                        <strong>SMTP Port:</strong> {self.smtp_port}<br/>
                        <strong>Sender:</strong> {self.sender}<br/>
                        <strong>Recipient:</strong> {self.recipient}
                    </div>
                    <p style="color: #64748B; font-size: 12px; margin-bottom: 0;">
                        Sent on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

        text_content = (
            "[BahaaIT] Test Email Connection\n\n"
            "Connection Successful!\n\n"
            "Your SMTP email settings configuration is correct. BahaaIT is now ready to send you real-time alerts when monitored network equipment goes offline.\n\n"
            f"SMTP Server: {self.smtp_host}\n"
            f"SMTP User: {self.smtp_user}\n"
            f"SMTP Port: {self.smtp_port}\n"
            f"Sender: {self.sender}\n"
            f"Recipient: {self.recipient}\n\n"
            f"Sent on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = formataddr((str(Header("Bahaa IT Network Tools", "utf-8")), self.sender))
        msg["To"] = self.recipient
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        try:
            # Check port type
            if self.smtp_port == 465:
                with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=10) as server:
                    server.login(self.smtp_user, self.smtp_pass)
                    server.sendmail(self.sender, self.recipient, msg.as_string())
            else:
                with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(self.smtp_user, self.smtp_pass)
                    server.sendmail(self.sender, self.recipient, msg.as_string())
            self.finished_signal.emit(True, "")
        except Exception as e:
            self.finished_signal.emit(False, str(e))
