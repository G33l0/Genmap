; Inno Setup script for Genmap. build_release.py --installer passes
; AppVersion, SourceDir, and OutputDir on the command line.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\Genmap"
#endif
#ifndef OutputDir
  #define OutputDir "..\release"
#endif

[Setup]
AppId={{8C4E2B1A-5F7D-4E3B-9A61-2D7C0B9E4F10}
AppName=Genmap
AppVersion={#AppVersion}
AppPublisher=Genmap
AppPublisherURL=https://github.com/g33l0/genmap
DefaultDirName={autopf}\Genmap
DefaultGroupName=Genmap
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=Genmap-{#AppVersion}-setup
SetupIconFile=..\genmap\resources\branding\genmap.ico
UninstallDisplayIcon={app}\Genmap.exe
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequiredOverridesAllowed=dialog
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Genmap"; Filename: "{app}\Genmap.exe"
Name: "{autodesktop}\Genmap"; Filename: "{app}\Genmap.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Genmap.exe"; Description: "{cm:LaunchProgram,Genmap}"; Flags: nowait postinstall skipifsilent

[Code]
function NmapInstalled(): Boolean;
begin
  Result := RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Nmap') or
            RegKeyExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nmap') or
            FileExists(ExpandConstant('{commonpf32}\Nmap\nmap.exe')) or
            FileExists(ExpandConstant('{commonpf64}\Nmap\nmap.exe'));
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and not NmapInstalled() then
    MsgBox('Genmap needs Nmap, which is installed separately.' + #13#10 + #13#10 +
           'Download the Windows installer from https://nmap.org/download.html and keep the Npcap option selected.',
           mbInformation, MB_OK);
end;
