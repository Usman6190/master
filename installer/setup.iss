; Inno Setup 6 script — compile with:  ISCC.exe installer\setup.iss
#define AppName "CreativeStall Security & Performance Audit Bot"
#define AppVersion "1.0.0"
#define AppExe "CreativeStallAuditBot.exe"

[Setup]
AppId={{6E0B7F7C-3C3A-4E8E-9B7C-5C4A0D17B001}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=CreativeStall
DefaultDirName={autopf}\CreativeStallAuditBot
DefaultGroupName=CreativeStall Audit Bot
OutputDir=..\dist\installer
OutputBaseFilename=CreativeStallAuditBot-Setup-{#AppVersion}
SetupIconFile=..\assets\app.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "..\dist\CreativeStallAuditBot\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Parameters: "--self-test"; Flags: runhidden waituntilterminated; StatusMsg: "Validating installation..."
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
