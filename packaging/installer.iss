; Sentinel X installer (Inno Setup 6). Built by packaging/build.py, which passes:
;   /DAppVersion=x.y.z  /DSourceDir=<dist\SentinelX>  /DOutputDir=<dist>
; Per-user install: no administrator rights, nothing outside the user's profile is changed.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6D1C4F2A-8B7E-4E5B-9C31-5F0A2D7E9B44}
AppName=Sentinel X
AppVersion={#AppVersion}
AppVerName=Sentinel X {#AppVersion}
AppPublisher=Sentinel X project
DefaultDirName={localappdata}\Programs\SentinelX
DefaultGroupName=Sentinel X
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=SentinelX-{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
InfoBeforeFile=installer_info_zh-TW.txt
UninstallDisplayName=Sentinel X {#AppVersion}
UninstallDisplayIcon={app}\SentinelX.exe
CloseApplications=yes
; Held by SentinelX.exe while it runs (app/instance.py): setup and uninstall refuse to touch files in use.
AppMutex=SentinelX-6D1C4F2A-running
RestartApplications=no

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Sentinel X"; Filename: "{app}\SentinelX.exe"
Name: "{autodesktop}\Sentinel X"; Filename: "{app}\SentinelX.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"

[CustomMessages]
DesktopIcon=建立桌面捷徑 (Create a desktop shortcut)
LaunchApp=啟動 Sentinel X (Launch Sentinel X)
KeepData=Sentinel X 已移除。你的資料（包括隔離區中的檔案）仍保留在 %LOCALAPPDATA%\SentinelX，需要時請自行刪除。

[Run]
Filename: "{app}\SentinelX.exe"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  { Remove the sign-in start entry that real-time protection may have added (per user). }
  if CurUninstallStep = usUninstall then
    RegDeleteValue(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 'SentinelX');
  { User data, the audit log and the quarantine vault are never deleted by the uninstaller. }
  if (CurUninstallStep = usPostUninstall) and not UninstallSilent then
    MsgBox(ExpandConstant('{cm:KeepData}'), mbInformation, MB_OK);
end;
