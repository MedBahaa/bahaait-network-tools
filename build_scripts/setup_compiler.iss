[Setup]
; Basic Application Information
AppName=BahaaIT Network Tools
AppVersion=2.0.0
AppPublisher=MedBahaa
DefaultDirName={autopf}\BahaaIT
DefaultGroupName=BahaaIT Network Tools
UninstallDisplayIcon={app}\BahaaIT.exe
SetupIconFile=..\assets\app_icon.ico

; Compression and Output
Compression=lzma2
SolidCompression=yes
OutputDir=..\dist
OutputBaseFilename=Install_BahaaIT_v2.0.0

; Permissions
PrivilegesRequired=admin

[Tasks]
Name: "desktopicon"; Description: "Créer un raccourci sur le Bureau"; GroupDescription: "Icônes supplémentaires :"

[Files]
; Copy all files from the PyInstaller onedir output folder to the installation directory
Source: "..\dist\BahaaIT\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu Icon
Name: "{group}\BahaaIT Network Tools"; Filename: "{app}\BahaaIT.exe"
; Desktop Icon
Name: "{autodesktop}\BahaaIT Network Tools"; Filename: "{app}\BahaaIT.exe"; Tasks: desktopicon

[Run]
; Launch the app after installation
Filename: "{app}\BahaaIT.exe"; Description: "Lancer BahaaIT Network Tools"; Flags: nowait postinstall skipifsilent
