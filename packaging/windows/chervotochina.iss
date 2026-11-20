; Червоточина: установщик Inno Setup 6 для текущего пользователя, без прав администратора (этап 19е, SPEC 19е 3.3).
; Собирается ISCC только в CI (scripts/release/package-windows.sh):
;   ISCC /DAppVersion=1.2.3 /DSrcDir=<каталог с chervotochina.exe и chervotochina.ico>
;        /DTouchDate=ГГГГ-ММ-ДД /DTouchTime=ЧЧ:ММ:СС /O<каталог результата> chervotochina.iss
; Правила (проверяет scripts/release/check-iss.sh): нет [Code], [Registry], [Dirs], [INI], [InstallDelete],
; [UninstallDelete], [UninstallRun], [Tasks], [Types], [Components]; нет #include; нет {userappdata} и
; {localappdata}; нет http, кроме двух адресов проекта. Данные пользователя (%LOCALAPPDATA%\Chervotochina)
; установщик не трогает: каталог программы {autopf}\Chervotochina другой, [UninstallDelete] нет.
; AppId берётся из packaging/windows/APPID и больше НИКОГДА не меняется: от него зависит обновление поверх.
#ifndef AppVersion
  #error AppVersion is not defined (pass /DAppVersion=1.2.3)
#endif
#ifndef SrcDir
  #error SrcDir is not defined (pass /DSrcDir=<directory>)
#endif
#ifndef TouchDate
  #error TouchDate is not defined (pass /DTouchDate=YYYY-MM-DD)
#endif
#ifndef TouchTime
  #error TouchTime is not defined (pass /DTouchTime=HH:MM:SS)
#endif

[Setup]
AppId={{ADC57BB2-6DF0-4A8C-A8FA-9FD0DD33C128}
AppName=Червоточина
AppVersion={#AppVersion}
AppVerName=Червоточина {#AppVersion}
AppPublisher=Chervotochina
AppPublisherURL=https://github.com/rekc2004/chervotochina
AppSupportURL=https://github.com/rekc2004/chervotochina
DefaultDirName={autopf}\Chervotochina
DisableDirPage=yes
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
PrivilegesRequired=lowest
OutputBaseFilename=chervotochina-{#AppVersion}-windows-x86_64-setup
SetupIconFile={#SrcDir}\chervotochina.ico
UninstallDisplayIcon={app}\chervotochina.ico
UninstallDisplayName=Червоточина
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
WizardStyle=modern
ShowLanguageDialog=no
SetupLogging=yes
CloseApplications=yes
RestartApplications=no
TimeStampsInUTC=yes
TouchDate={#TouchDate}
TouchTime={#TouchTime}
VersionInfoVersion={#AppVersion}.0

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[Files]
Source: "{#SrcDir}\chervotochina.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\chervotochina.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Червоточина"; Filename: "{app}\chervotochina.exe"; IconFilename: "{app}\chervotochina.ico"; WorkingDir: "{app}"; AppUserModelID: "Chervotochina.App"

[Run]
Filename: "{app}\chervotochina.exe"; Description: "Запустить Червоточину"; Flags: nowait postinstall skipifsilent
