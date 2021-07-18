<#
.SYNOPSIS
  Permite implementar lineas base de DISA, CIS, etc y auditarlas
.DESCRIPTION
  Implementa o audita baseline de seguridad. Bastionado de servidores
.PARAMETER 
  -Implement (optional)
.INPUTS
.OUTPUTS
  Log file stored in .\Logs\BaselineAuditingTool_<Date>.log>
.NOTES
  Version:        1.0
  Author:         Juan Merlos García
  Creation Date:  08/10/2020
  Purpose/Change: Creación inicial del script

  Change control: 
                    Juan Merlos García. 26/04/2021. Se implementan las funciones necesarias vistas en función de los items a comprobar.
                    Juan Merlos García. 18/05/2021. Se implementan el bloque de ejecución.
                    Juan Merlos García. 13/06/2021. Se corrigen errores en la verificación de algunos items.
                    Juan Merlos García. 26/06/2021. Se implementa automatización para modificación de importtable.
                    Juan Merlos García. 27/06/2021. Se cambia la forma de obtención de la ruta del XML de la baseline.

.EXAMPLE
  BaselineAuditingTool.ps1 -Baseline "C:\pruebas\U_MS_Windows_Server_2016_STIG_V2R1_Manual-xccdf.xml"
#>

<#
Parametro opcional para implementar bastionado en lugar de auditar.
Si no se recibe parámetro, auditará.
Ejemplo: BaselineAuditingTool.ps1 -Implement
#>
param(
    # Parámetro que se recibe si se quiere implementar al guía de cumplimiento
    # Por defecto si no se recibe, audita (medir el nivel de cumplimiento)
    [Parameter(Mandatory=$false)]
    [switch] $Implement
)

#-----------------------------------------------------------[Functions]------------------------------------------------------------

<#
.SYNOPSIS Función con parámetros para creación de Log
.DESCRIPTION Lo único necesario es el mensaje, el resto son parametros opcionales,
    si no se enví­a el argumento $path escribiá en el valor por defecto del $path
.EXAMPLE Write-Log -message 'La carpeta no existe' -path c:\Logs\Script.log -level Error
	Escribe el mensaje al archivo de log especificado como un mensaje de error.
#>
function Write-Log {
    [CmdletBinding()]
    Param (
        # Mensaje
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$message,

        # Ruta por defecto sino se pasa como parametro
        [Parameter(Mandatory=$false)]
        [string]$path = "$($LogFile)",

        # Tipo de mensaje ("Error, Warning, Info")
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$level = "Info"
    )
    # Si se asigna se mostraran los log en la consola
    $VerbosePreference = 'Continue'

    # Si se va a escribir el archivo de log en una ruta que no existe, se crea la ruta.
    if (!(Test-path $path)) {
        Write-Verbose "Creando $path"
        New-Item $path -Force -ItemType File
    }

    # Formato de fecha para el log
    $formattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Escribir el tipo de mensaje que es en el log o en consola con $levelText
    switch ($level) {
        'Error' {
            Write-Error $message
            $levelText = 'ERROR:'
            }
        'Warn' {
            Write-Warning $message
            $levelText = 'WARNING:'
            }
        'Info' {
            Write-Verbose $message
            $levelText = 'INFO:'
            }
    }   
    # Escritura del log en $path
    "$formattedDate $levelText $message" | Out-File -FilePath $path -Append
}

<#
.SYNOPSIS Función que permite obtener la ruta del XML que definirá la guía técnica a auditar.
.DESCRIPTION No recibe parámetros
             Devuelve el valor de la ruta del XML en string
.EXAMPLE $variable = GetComputerType
#>
function Get-OptionBaseline (){
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $openfiledialog = New-Object System.Windows.Forms.OpenFileDialog
    $openfiledialog.InitialDirectory = $myfolder
    $openfiledialog.ShowDialog() | Out-Null
    #$openfiledialog.FileName

    if ($openfiledialog.FileName -eq "") {
        Write-Log -message "Select the correct XML. Exiting Script. Press any key to continue..."
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        Exit
    } else {
        return $openfiledialog.FileName
    }
}

<#
.SYNOPSIS Función que permite obtener información acerca de si el equipo es controlador de dominio, 
          servidor miembro o equipo de escritorio
.DESCRIPTION No recibe parámetros
             Devuelve el valor del tipo de equipo en string
.EXAMPLE $variable = GetComputerType
#>
function GetComputerType {
    $ProductType = (Get-WmiObject win32_OperatingSystem).ProductType
    switch ($ProductType) {
        1 {
            $ComputerType = "Workstation"
        }
        2 {
            $ComputerType = "Domain Controller"
        }
        3 {
            $ComputerType = "Member Server"
        }
    }

    return $ComputerType
}

<#
.SYNOPSIS Función que comprueba si el equipo tiene UEFI activo o no
.DESCRIPTION No recibe parámetros
             True = tiene UEFI activo
             False = no tiene UEFI activo
.EXAMPLE $variable = CheckUEFI
#>
function CheckUEFI {
    $CheckUefi = bcdedit | Select-String 'path\s*.*winload'
    if ($CheckUefi -like "*.efi") {
        return $true
    }elseif ($CheckUefi -like "*.exe") {
        return $false
    }
}

<#
.SYNOPSIS Función que permite comprobar si una característica de Windows está en el estado correcto
          según lo que dicta la guía técnica de seguridad
.DESCRIPTION
    Recibe dos parámetros, uno para el nombre de la característica a comprobar, y otro indicando el estado incorrecto para incumplir la guía técnica
.EXAMPLE
    Check-WindowsFeature -Feature Web-Ftp-Service -InCorrectState Installed
#>
function Check-WindowsFeature ($Feature, $InCorrectState){
    $WNCheck = Get-WindowsFeature | where Name -like $Feature
    if ($WNCheck.InstallState -eq $InCorrectState) { $global:VulnActive+=$Vuln }
}

<#
.SYNOPSIS Función que permite comprobar las políticas de permisos de usuario
          según lo que dicta la guía técnica de seguridad
.DESCRIPTION
    Recibe 4 parámetros:
        1. Item a comprobar
        2. Política de usuario a comprobar
        3. Valor correcto que debe contener para cumplir la guía técnica de seguridad
        4. Parámetro opcional. Indica si siendo nulo (no estando definida esa política de permiso) se incumple o no.
           Si puede ser nulo, se debe enviar como parámetro en este caso "true"
.EXAMPLE
    Check-UsersRightsPolicy -Vuln $Vuln -Policy SeNetworkLogonRight -Value "S-1-5-11,S-1-5-32-544,S-1-5-9"
    Check-UsersRightsPolicy -Vuln $Vuln -Policy SeNetworkLogonRight -Value "S-1-5-11,S-1-5-32-544,S-1-5-9" -CanBeNull true

#>
function Check-UsersRightsPolicy ($Vuln, $Policy, $Value, $CanBeNull){
    # Si recibe en el parametro $CanBeNull "true" significa que puede ser nulo y estaría OK. 
    # Si recibe "false" significa que no puede ser nulo
    Secedit /Export /Areas USER_RIGHTS /CFG C:\Windows\temp\seceditConfig_UsersRights.txt
    $SeceditExport = Get-content -Path "C:\Windows\temp\seceditConfig_UsersRights.txt" | select-string $Policy
            
    if($SeceditExport){
        #Está configurado, obtenemos valor
        $valueSecedit = $seceditExport.Line.Split("=").Trim()
        $ValueConfigured = $valueSecedit[1].Replace("*","") 
        #Si no esta configurado como deberia, incumple
        if ($valueConfigured -notlike $Value) {
            $global:VulnActive+=$Vuln
        }
    }else {
        if ($CanBeNull -notlike "true") {
            #Si no está configurado, incumple
            $global:VulnActive+=$Vuln
        }
        
    }
}

<#
.SYNOPSIS Función que permite comprobar las políticas de seguridad del equipo
          según lo que dicta la guía técnica de seguridad
.DESCRIPTION
    Recibe 3 parámetros:
        1. Item a comprobar
        2. Política de seguridad a comprobar
        3. Valor. Este valor puede ser recibido de las siguientes formas:
            - "!X". CUmpliría con todos los valores excepto el valor X.
            - ">X". CUmpliría siempre y cuando no supere el valor de X.
            - X..Y. Array con los valores inválidos.
            - X. Valor inválido
.EXAMPLE
    Check-SecurityPolicy -Vuln $Vuln -Policy TicketValidateClient -Value 0
    Check-SecurityPolicy -Vuln $Vuln -Policy MaxTicketAge -Value "!0"
    Check-SecurityPolicy -Vuln $Vuln -Policy MaxTicketAge -Value ">10"
    Check-SecurityPolicy -Vuln $Vuln -Policy LockoutDuration -Value 1..14
#>
function Check-SecurityPolicy ($Vuln, $Policy, $Value){
    #REVISAR# EN EL SECEDIT APARECE ADMINSITRATORS O EL SID??S-1-5-32-544 (Administrators)
    Secedit /Export /Areas SecurityPolicy /CFG C:\Windows\temp\seceditConfig_SecurityPolicy.txt
    $SeceditExport = Get-content -Path "C:\Windows\temp\seceditConfig_SecurityPolicy.txt" | select-string $Policy
            
    if($SeceditExport){
        #Está configurado, obtenemos valor
        $valueSecedit = $seceditExport.Line.Split("=").Trim()
        
        #EL value que se puede pasar puede ser de dos tipos:
        #Los valores que están permitidos (1,2,3,4,5,6)
        #Todo es válido menos el valor X: se pasa con una exclamación antes (!1)

        #Se pasa el valor que no es válido
        if ($value -like "!*") {
            if ($valueSecedit[1] -like $value.Substring(1)) {
                $global:VulnActive+=$Vuln
            }    
        
        } elseif ($value -like ">*") {
        #Valor inválido mayor que X. Si es mayor que X, incumple 
            if ($valueSecedit[1] -gt $value.Substring(1)) {
                $global:VulnActive+=$Vuln
            }
        } else {
            #En este caso se le pasan los valores inválidos
            if ($value -contains $valueSecedit[1]) {
                $global:VulnActive+=$Vuln
            }
        }
        
    }else {
        #Si no está configurado, incumple
        $global:VulnActive+=$Vuln
    }
}

<#
.SYNOPSIS Función que permite recibiendo la descripción del item de tipo clave de registro de la guía técnica en bruto,
          dividir la información y obtener los valores de la clave de registro a comprobar
.DESCRIPTION
    Recibe 1 parámetro:
        1. Item a comprobar
.EXAMPLE
    ObtainRegeditData -Item $vuln
#>
function ObtainRegeditData ($Item) {
    $RegistryObject = [PSCustomObject]@{
        HKEY = ''
        Path = ''
        Name = ''
        Type = ''
        Value = ''
    }

    $Data = $item.Rule.Check."Check-content".Split([Environment]::NewLine)
    foreach ($element in $data) {
        switch -wildcard ($element) {
            '*Registry Hive*' {
                $HKEYWithoutFormat = $element.Split(":").Trim()[1]
                if ($HKEYWithoutFormat -like "HKEY_LOCAL_MACHINE") { $RegistryObject.HKEY = "HKLM" } 
                elseif ($HKEYWithoutFormat -like "HKEY_CURRENT_USER") { $RegistryObject.HKEY = "HKCU"}
            }
            '*Registry Path*' {
                $RegistryObject.Path = $element.Split(":")[1].Trim()
            }
            '*Value Name*' {
                $RegistryObject.Name = $element.Split(":").Trim()[1]
            }
            '*Type*:*' {
                $RegistryObject.Type = $element.Split(":").Trim()[1]
            }
            'Value:*' {
                $ValueWithoutFormat = $element.Split(":").Trim()[1]
                if ($ValueWithoutFormat -match "^\d+x\d+") {
                    $RegistryObject.Value = [int]$ValueWithoutFormat.Split(" ")[0]
                } else {
                    $RegistryObject.Value = $ValueWithoutFormat
                }
            }
        }
    }
    return $RegistryObject
    
}

<#
.SYNOPSIS Función que permite, recibiendo un item de tipo clave de registro de la guía técnica en bruto,
          comprobar si la clave de registro se encuentra correctamente configurada
.DESCRIPTION
    Recibe 2 parámetros:
        1. Item a comprobar
        2. Parámetro opcional. Indica si siendo nulo (no estando definida esa clave de registro) se incumple o no.
           Si puede ser nulo, se debe enviar como parámetro en este caso "true"
.EXAMPLE
    Check-RegistryVuln -Item $vuln
#>
function Check-RegistryVuln ($Vuln, $CanBeNull) {
    #Obtain de data of registry item
    $RegeditKeyData = ObtainRegeditData -Item $Vuln
    
    #Check registry item
    $WNCheck = Get-ItemProperty -Path "$($RegeditKeyData.HKEY):$($RegeditKeyData.Path)" -Name $RegeditKeyData.Name -ErrorAction Ignore
    $Name = $RegeditKeyData.Name

    if ($CanBeNull -eq "true") {
        if (($WNCheck) -and ($WNCheck.$Name -notlike $RegeditKeyData.Value)) { $global:VulnActive+=$Vuln }
    } else {
        if ((!$WNCheck) -or ($WNCheck.$Name -notlike $RegeditKeyData.Value)) { $global:VulnActive+=$Vuln }
    }

    # Debug lines
    #Write-Log -message "RegeditKeyData: $($RegeditKeyData.HKEY):$($RegeditKeyData.Path), Clave:$($RegeditKeyData.Name), $($RegeditKeyData.Type), $($RegeditKeyData.Value)" -level Warn
    #Write-Log -message "loquehay configurado: $($WNCheck.$Name)" -level Warn
    #Read-Host
}

<#
.SYNOPSIS Función que permite, auditar el item de la guía técnica
.DESCRIPTION
    Recibe 1 parámetros:
        1. Item a comprobar
.EXAMPLE
    OthersVulnerabilities -Vuln $vuln
#>
function OthersVulnerabilities ($Vuln) {
    switch -wildcard ($Vuln.Rule.Version) {
        #region WN16-DC
        'WN16-DC-000010' {
            if ((GetComputerType) -eq "Domain Controller"){
                $WNCheck = Get-ADGroupMember "Administrators" | Where-Object {($_.ObjectClass -like "User") -and ($_.Name -notlike "Administrator")}
                if ($WNCheck){
                    Write-Log -message "Hay usuarios en el grupo de administradores locales. No deben haber para solventar la vulnerabilidad $($Vuln)" -level Warn
                    $global:VulnActive+=$Vuln
                }    
            }
        }
        'WN16-DC-000020' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-SecurityPolicy -Vuln $Vuln -Policy TicketValidateClient -Value 0
            }
        }
        'WN16-DC-000030' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-SecurityPolicy -Vuln $Vuln -Policy MaxServiceAge -Value "!0"
                Check-SecurityPolicy -Vuln $Vuln -Policy MaxServiceAge -Value ">600"
            }
        }
        'WN16-DC-000040' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-SecurityPolicy -Vuln $Vuln -Policy MaxTicketAge -Value "!0"
                Check-SecurityPolicy -Vuln $Vuln -Policy MaxTicketAge -Value ">10"
            }
        }
        'WN16-DC-000050' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-SecurityPolicy -Vuln $Vuln -Policy MaxRenewAge -Value ">7"
            }
        }
        'WN16-DC-000060' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-SecurityPolicy -Vuln $Vuln -Policy MaxClockSkew -Value ">5"
            }
        }
        'WN16-DC-000070' {
            if ((GetComputerType) -eq "Domain Controller"){
                $WNCheck1 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "Database log files path"
                $WNCheck2 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "DSA Database file"

                if ($WNCheck1.'Database log files path' -ne "C:\Windows\NTDS*") {
                    (get-acl "$($WNCheck1.'Database log files path')\*.*").access | select IdentityReference,FileSystemRights | foreach {
                        if (($_.IdentityReference -notlike "BUILTIN\Administrators") -or ($_.IdentityReference -notlike "NT AUTHORITY\SYSTEM")){
                            $IsVuln = $true
                        }
                    }
                }
                if (($WNCheck2.'DSA Database file' -ne "C:\Windows\NTDS*") -and ($WNCheck2.'DSA Database file' -ne $WNCheck1.'Database log files path')) {
                    (get-acl "$($WNCheck1.'Database log files path')\*.*").access | select IdentityReference,FileSystemRights | foreach {
                        if (($_.IdentityReference -notlike "BUILTIN\Administrators") -or ($_.IdentityReference -notlike "NT AUTHORITY\SYSTEM")){
                            $IsVuln = $true                                                        
                        }
                    }
                }

                if ($IsVuln) {$global:WarningActive+=$Vuln}
            }
        }
        'WN16-DC-000080' {
            if ((GetComputerType) -eq "Domain Controller"){
                $ACLSYSVOL = Get-SmbShare -Name "SYSVOL" | select Path
                $acls = (icacls $ACLSYSVOL.Path)
                $Status = "OK"
                foreach ($acl in $acls) {
                    if (!$acl) { continue } 
                    elseif ($acl -like '*NT AUTHORITY\Authenticated Users:(RX)') { continue } 
                    elseif ($acl -like '*NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(GR,GE)') { continue } 
                    elseif ($acl -like '*BUILTIN\Server Operators:(RX)') { continue } 
                    elseif ($acl -like '*BUILTIN\Server Operators:(OI)(CI)(IO)(GR,GE)*') { continue }
                    elseif ($acl -like '*BUILTIN\Administrators:(M,WDAC,WO)*') { continue }
                    elseif (($acl -like '*BUILTIN\Administrators:(OI)(CI)(IO)(F)*') -or ($acl -like '*BUILTIN\Administrators:(OI)(CI)(IO)(WDAC,WO,GR,GW,GE)*')) { continue }
                    elseif ($acl -like '*NT AUTHORITY\SYSTEM:(F)*') { continue }
                    elseif ($acl -like '*NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)*') { continue }
                    elseif ($acl -like '*BUILTIN\Administrators:(RX,W,WDAC,WO)*') { continue }
                    elseif (($acl -like '*CREATOR OWNER:(OI)(CI)(IO)(F)*') -or ($acl -like '*CREATOR OWNER:(OI)(CI)(IO)(WDAC,WO,GR,GW,GE)*')) { continue }
                    elseif ($acl -like 'Successfully processed*') { continue }
                    $status = 'FAILED'
                }
                if ($status -like "*FAILED*") { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-DC-000090' {
            $global:WarningActive+=$Vuln
        }
        'WN16-DC-000100' {
            if ((GetComputerType) -eq "Domain Controller"){
                Set-location ad:
                 (Get-acl (Get-ADOrganizationalUnit -Filter 'Name -like "*Domain Controllers*"').DistinguishedName).Access | select IdentityReference,accesscontroltype,ActiveDirectoryRights | foreach {
                    if ((($_.IdentityReference -notlike "*SYSTEM*") -and ($_.IdentityReference -notlike "*Domain Admins*") -and ($_.IdentityReference -notlike "*Enterprise Admins*") -and ($_.IdentityReference -notlike "*Administrators*")) -and ($_.ActiveDirectoryRights -like "GenericAll")) {
                        $global:VulnActive+=$Vuln
                    }
                 }
            }
            Set-Location C:
        }
        'WN16-DC-000110' {
            $global:WarningActive+=$Vuln
        }
        'WN16-DC-000120' {
            if ((GetComputerType) -eq "Domain Controller"){
                $WNCheck1 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "DSA Database file"
                get-smbshare | where-object {($_.Name -notlike "NETLOGON") -and ($_.Name -notlike "SYSVOL") -and ($_.Name -notlike "*$")} | foreach {
                    if ($_.Path.Substring(0,2) -eq $WNCheck1.'DSA Database file'.Substring(0,2)) {
                        $global:VulnActive+=$Vuln
                    }
                }
            }
        }
        'WN16-DC-000130' {
            if ((GetComputerType) -eq "Domain Controller"){
                Get-WindowsFeature | where-object {($_.InstallState -eq "Installed") -and ($_.FeatureType -eq "Role")} | foreach {
                    if (($_.DisplayName -notlike "Active Directory Domain Services") -and ($_.DisplayName -notlike "DNS Server") -and ($_.DisplayName -notlike "File and Storage Services")){
                        $global:VulnActive+=$Vuln
                    }
                }
            }
        }
        'WN16-DC-000140' {
            $global:WarningActive+=$Vuln
        }
        'WN16-DC-000150' {
            $global:WarningActive+=$Vuln
        }
        'WN16-DC-000160' {
            if ((GetComputerType) -eq "Domain Controller"){
                $DNSRoot = (Get-ADDomain).DNSRoot.Split(".")
                $dom = $DNSRoot[0]
                $ext = $DNSRoot[1]
                $ldapAttributes = dsquery * "cn=Default Query Policy,cn=Query-Policies,cn=Directory Service, cn=Windows NT,cn=Services,cn=Configuration,dc=$dom,dc=$ext" -attr LDAPAdminLimits
                foreach ($atr in $ldapAttributes.Split(";")) {
                    
                    if ($atr -like "*MaxConnIdleTime*") {
                        if (!($atr.Split("=").Trim()[1]) -or ([int]$atr.Split("=").Trim()[1] -gt 300)){
                            $global:VulnActive+=$Vuln
                        }
                    }
                    
                }
            }
        }
        'WN16-DC-000170' {
            if ((GetComputerType) -eq "Domain Controller"){
                $AllGPO = Get-Gpo -All
                foreach ($GPO in $AllGPO) {
                     Get-Acl -Path ("AD:\" + $GPO.Path) -Audit | Select Audit | foreach {
                        $flag = $false
                        $_.Audit | foreach {
                            if (($_.IdentityReference -like "Everyone") -and ($_.AuditFlags -like "*Fail*")){
                                $flag = $true
                            }
                        }
                    
                     }
                     if (!$flag) {$global:VulnActive+=$Vuln;break;}
                }
            }
        }
        'WN16-DC-000180' {
            if ((GetComputerType) -eq "Domain Controller"){
                import-module ActiveDirectory
                Set-Location ad:
                $DSOU = (Get-ADDomain).DistinguishedName
                $AuditPolicies = (get-acl -Path $DSOU -Audit).Audit | select IdentityReference,AuditFlags
                $flag = $false
                foreach ($auditPolicy in $AuditPolicies) {
                    if (($auditPolicy.IdentityReference -like "Everyone") -and ($auditPolicy.AuditFlags -like "*Fail*")){
                        $flag = $true
                    }
                }
                if (!$flag) {$global:VulnActive+=$Vuln}
                Set-Location C:
            }
        }
        'WN16-DC-000190' {
            $DSOU = (Get-ADObject -Filter 'Name -like "*Infras*"').DistinguishedName
            Set-Location ad:
            $AuditPolicies = (get-acl -Path $DSOU -Audit).Audit | select IdentityReference,AuditFlags
            $flag = $false
            foreach ($auditPolicy in $AuditPolicies) {
                if (($auditPolicy.IdentityReference -like "Everyone") -and ($auditPolicy.AuditFlags -like "*Fail*")){
                    $flag = $true
                }
            }
            if (!$flag) {$global:VulnActive+=$Vuln}
            Set-Location C:
        }
        'WN16-DC-000200' {
            if ((GetComputerType) -eq "Domain Controller"){
                
                import-module ActiveDirectory
                Set-Location ad:
                #$DSOU = (Get-ADOrganizationalUnit -Filter 'Name -like "*Domain Controllers*"').DistinguishedName
                $DSOU =(Get-ADObject -Filter {ObjectClass -like "organizationalunit"} | Where-Object {$_.DistinguishedName -like "*Domain Controllers*"}).DistinguishedName
                $AuditPolicies = (get-acl -Path $DSOU -Audit).Audit | select IdentityReference,AuditFlags
                $flag = $false
                foreach ($auditPolicy in $AuditPolicies) {
                    if (($auditPolicy.IdentityReference -like "Everyone") -and ($auditPolicy.AuditFlags -like "*Fail*")){
                        $flag = $true
                    }
                }
                if (!$flag) {$global:VulnActive+=$Vuln}
                Set-Location C:
            }
        }
        'WN16-DC-000210' {

            if ((GetComputerType) -eq "Domain Controller"){
                import-module ActiveDirectory
                Set-Location ad:
                $DSOU =(Get-ADObject -Filter {ObjectClass -like "container"} | Where-Object {$_.DistinguishedName -like "*Admin*"}).DistinguishedName
                $AuditPolicies = (get-acl -Path $DSOU -Audit).Audit | select IdentityReference,AuditFlags
                $flag = $false
                foreach ($auditPolicy in $AuditPolicies) {
                    if (($auditPolicy.IdentityReference -like "Everyone") -and ($auditPolicy.AuditFlags -like "*Fail*")){
                        $flag = $true
                    }
                }
                if (!$flag) {$global:VulnActive+=$Vuln}
                Set-Location C:
            }
        }
        'WN16-DC-000220' {
            if ((GetComputerType) -eq "Domain Controller"){
                import-module ActiveDirectory
                Set-Location ad:
                $DSOU =(Get-ADObject -Filter {ObjectClass -like "ridmanager"} | Where-Object {$_.DistinguishedName -like "*RID Manager*"}).DistinguishedName
                $AuditPolicies = (get-acl -Path $DSOU -Audit).Audit | select IdentityReference,AuditFlags
                $flag = $false
                foreach ($auditPolicy in $AuditPolicies) {
                    if (($auditPolicy.IdentityReference -like "Everyone") -and ($auditPolicy.AuditFlags -like "*Fail*")){
                        $flag = $true
                    }
                }
                if (!$flag) {$global:VulnActive+=$Vuln}
                Set-Location C:
            }
        }
        'WN16-DC-000230' {
            if ((GetComputerType) -eq "Domain Controller"){
                $WNCheck = auditpol /get /category:* | Select-String "Computer Account Management"
                if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-DC-000240' {
            if ((GetComputerType) -eq "Domain Controller"){
                $WNCheck = auditpol /get /category:* | Select-String "Directory Service Access"
                if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-DC-000250' {
            if ((GetComputerType) -eq "Domain Controller"){
                $WNCheck = auditpol /get /category:* | Select-String "Directory Service Access"
                if ($WNCheck -notlike "*Failure*") { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-DC-000260' {
            if ((GetComputerType) -eq "Domain Controller"){
                $WNCheck = auditpol /get /category:* | Select-String "Directory Service Changes"
                if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-DC-000270' {
            if ((GetComputerType) -eq "Domain Controller"){
                $WNCheck = auditpol /get /category:* | Select-String "Directory Service Changes"
                if ($WNCheck -notlike "*Failure*") { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-DC-000280' {
            if ((GetComputerType) -eq "Domain Controller"){
                $global:WarningActive+=$Vuln
            }
        }
        'WN16-DC-000290' {
            if ((GetComputerType) -eq "Domain Controller"){
                $global:WarningActive+=$Vuln
            }
        }
        'WN16-DC-000300' {
            if ((GetComputerType) -eq "Domain Controller"){
                $flag = $true
                $WNCheck = Get-ADUser -Filter * | Where-Object {($_.Enabled -eq "True") -and ($_.Name -notlike "Administrator")} | foreach {
                    if ($_.UserPrincipalName -notlike "*@*"){
                        $flag = $false
                    }
                }
                if (!$flag) { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-DC-000310' {
            if ((GetComputerType) -eq "Domain Controller"){
                $WNCheck = Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)} | FT Name
                if ($WNCheck) { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-DC-000320' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-RegistryVuln $Vuln
            }
        }
        'WN16-DC-000330' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-RegistryVuln $Vuln
            }
        }
        'WN16-DC-000340' {
            if ((GetComputerType) -eq "Domain Controller"){
                # Administrators, Enterprise Domain Controllers, Authenticated users
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeNetworkLogonRight -Value "S-1-5-11,S-1-5-32-544,S-1-5-9"
            }
        }
        'WN16-DC-000350' {            
            if ((GetComputerType) -eq "Domain Controller"){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeMachineAccountPrivilege -Value "S-1-5-32-544"
            }
        }
        'WN16-DC-000360' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeRemoteInteractiveLogonRight -Value "S-1-5-32-544"
            }
        }
        'WN16-DC-000370' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeDenyNetworkLogonRight -Value "S-1-5-32-546"
            }
        }
        'WN16-DC-000380' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeDenyBatchLogonRight -Value "S-1-5-32-546"
            }
        }
        'WN16-DC-000390' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeDenyServiceLogonRight -Value "" -CanBeNull "true"    
            }
        }
        'WN16-DC-000400' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeDenyInteractiveLogonRight -Value "S-1-5-32-546"
                
            }
        }
        'WN16-DC-000410' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeDenyRemoteInteractiveLogonRight -Value "S-1-5-32-546"
            }
        }
        'WN16-DC-000420' {
            if ((GetComputerType) -eq "Domain Controller"){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeEnableDelegationPrivilege -Value "S-1-5-32-544"
            }
        }
        'WN16-DC-000430' {
            if ((GetComputerType) -eq "Domain Controller"){
                $WNCheck = Get-ADUser -Identity krbtgt -Properties PasswordLastSet | where {$_.PasswordLastSet -le (Get-Date).AddDays(-180)}
                if ($WNCheck) { $global:VulnActive+=$Vuln }
            }
        }

        #endregion WN16-DC

        #region WN16-00
        'WN16-00-000010' {
            $global:WarningActive+=$Vuln
        }
        'WN16-00-000030' {
            if ((GetComputerType) -eq "Domain Controller"){
                $WNCheck = Get-ADUser -Filter * -Properties PasswordLastSet | Where SID -Like "*-500" | where {$_.PasswordLastSet -le (Get-Date).AddDays(-60)} | Format-Table -property name, SID, PasswordLastSet;
                if ($WNCheck) { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-00-000040' {
            $global:WarningActive+=$Vuln
        }
        'WN16-00-000050' {
            if (Get-ADGroupMember "Backup Operators") {
                #Manual
                $global:WarningActive+=$Vuln
            }
        }
        'WN16-00-000060' {
            $global:WarningActive+=$Vuln
        }
        'WN16-00-000070' {
            $WNCheck = Get-AdUser -Filter * -Properties PasswordLastSet | where-object {($_.PasswordLastSet -lt ((Get-Date).AddYears(-1))) -and ($_.Enabled -like "True")}
            if ($WNCheck) { $global:VulnActive+=$Vuln }
        }
        'WN16-00-000080' {
            $global:WarningActive+=$Vuln
        }
        'WN16-00-000090' {
            if (((GetComputerType) -eq "Member Server") -or ((GetComputerType) -eq "Workstation")){
                Import-Module AppLocker
                $AppLockerList = Get-AppLockerPolicy -Effective -XML | select -Skip 1
                if (-not($AppLockerList)) {
                    $global:VulnActive+=$Vuln
                }
            }
        }
        'WN16-00-000100' {
            $NotCOmpatibleTPM = (Get-WmiObject Win32_COmputerSystem).Model

            if ($NotCOmpatibleTPM -notlike "Virtualbox") {
                $WNCheck = (Get-tpm -errorAction Ignore).Enabled
                if (!$WNCheck) { $global:VulnActive+=$Vuln }
            }
            
        }
        'WN16-00-000110' {
            $WNCheck = Get-WmiObject Win32_OperatingSystem | select BuildNumber

            if ($WNCheck.BuildNumber -lt 14393) {
                $global:VulnActive+=$Vuln
            }
        }
        'WN16-00-000120' {
            $Defender = (get-service windefend).Status
            $OtherAV = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntiVirusProduct -ErrorAction Ignore | Select-Object -ExpandProperty DisplayName 
            if (($Defender -notlike "running") -and (!$OtherAV)) {
                $global:VulnActive+=$Vuln
            }
        }
        'WN16-00-000140' {
            $global:WarningActive+=$Vuln
        }
        'WN16-00-000150' {
             $WNCheck = Get-Volume | WHERE {$_.DriveType -eq 'Fixed'} | WHERE {$_.FileSystem -ne 'NTFS'} | WHERE {$_.FileSystem -ne 'ReFS'} | SELECT DriveLetter, FileSystemLabel,FileSystem   
             if ($WNCheck) { $global:VulnActive+=$Vuln }
        }
        'WN16-00-000160' {
            $WNCheck = (get-acl "C:\").access | where-object {($_.IdentityReference -like "*Users*" -or $_.IdentityReference -like "Authenticated Users") -and ($_.RegistryRights -like "FullControl")} 
            if ($WNCheck) { $global:VulnActive+=$Vuln }
        }
        'WN16-00-000170' {
            $WNCheck = (get-acl "C:\Program Files").access | where-object {($_.IdentityReference -like "*Users*" -or $_.IdentityReference -like "Authenticated Users") -and ($_.RegistryRights -like "FullControl")}
            $WNCheck2 = (get-acl "C:\Program Files (x86)").access | where-object {($_.IdentityReference -like "*Users*" -or $_.IdentityReference -like "Authenticated Users") -and ($_.RegistryRights -like "FullControl")}
            if ($WNCheck -or $WNCheck2) { $global:VulnActive+=$Vuln }
        }
        'WN16-00-000180' {
            $WNCheck = (get-acl "C:\Windows").access | where-object {($_.IdentityReference -like "*Users*" -or $_.IdentityReference -like "Authenticated Users") -and ($_.RegistryRights -like "FullControl")} 
            if ($WNCheck) { $global:VulnActive+=$Vuln }
        }
        'WN16-00-000190' {
            $Folders = @("HKLM:\SECURITY", "HKLM:\SOFTWARE", "HKLM:\SYSTEM")
            
            foreach ($folder in $Folders) {
                #$WNCheck = (get-acl $folder).access | where-object {($_.IdentityReference -like "*Users*" -or $_.IdentityReference -like "Everyone") -and ($_.RegistryRights -notlike "ReadKey")} 
                $WNCheck = (get-acl $folder).access | where-object {($_.IdentityReference -like "*Users*" -or $_.IdentityReference -like "Everyone") -and (($_.RegistryRights -notlike "ReadKey") -and ($_.RegistryRights -Notmatch "\d+"))} 
                if ($WNCheck) { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-00-000200' {
            if (Get-Printer | where-object {$_.Name -notlike "*Microsoft*" -and $_.Shared -eq "True"}) {
                #REVISAR falta comprobar los permisos de la compartida
                if ($WNCheck) { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-00-000210' {
            $WNCheck = Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00 | where-object {($_.SID -notlike "*500" -and $_.SID -notlike "*501" -and $_.SID -notlike "*503") -and ($_.Enabled -eq "True")}
            if ($WNCheck) { $global:VulnActive+=$Vuln }
        }
        'WN16-00-000220' {
            $WNCheck = Get-Aduser -Filter * -Properties Passwordnotrequired | where-object {$_.PasswordNotrequired -like "True" -and $_.Enabled -like "True"}
            if ($WNCheck) { $global:VulnActive+=$Vuln }
        }
        'WN16-00-000230' {
            $WNCheck = Search-ADAccount -PasswordNeverExpires -UsersOnly | where-object {$_.PasswordNeverExpires -like "True" -and $_.Enabled -like "True"}
            if ($WNCheck) { $global:VulnActive+=$Vuln }
        }
        'WN16-00-000240' {
            $global:WarningActive+=$Vuln
        }
        'WN16-00-000250' {
            $WNCheck = Get-WmiObject -Class Win32_Share | Where-Object {($_.Name -notlike '*$') -and ($_.Name -notlike "SYSVOL") -and ($_.Name -notlike "NETLOGON")} |foreach {Write-Output $_.Name; (Get-SmbShareAccess -name $_.Name) | where-object {($_.AccountName -like "*Users*" -or $_.AccountName -like "Everyone") -and ($_.AccessRight -notlike "Read")}}
            if ($WNCheck) { $global:VulnActive+=$Vuln }
        }
        <#
        'WN16-00-000270' {
            $WNCheck = Get-WMIObject Win32_LogicalDisk -filter 'DriveType = 3' | Select-Object DeviceID | ForEach-Object {Get-Childitem ($_.DeviceID + '\') -include *.p12,*.pfx -recurse}
            if ($WNCheck) { $global:VulnActive+=$Vuln }
        }
        #>
        'WN16-00-000280' {
            $global:WarningActive+=$Vuln
        }
        'WN16-00-000290' {
            $global:WarningActive+=$Vuln
        }
        'WN16-00-000300' {
            $global:WarningActive+=$Vuln
        }
        'WN16-00-000310' {
            $global:WarningActive+=$Vuln
        }
        'WN16-00-000320' {
            $global:WarningActive+=$Vuln
        }
        'WN16-00-000330' {
            $WNCheck = Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate
            if ($WNCheck) { $global:VulnActive+=$Vuln }
        }
        'WN16-00-000340' {
            $WNCheck = Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate
            if ($WNCheck) { $global:VulnActive+=$Vuln }
        }
        'WN16-00-000350' {
            Check-WindowsFeature -Feature Fax -InCorrectState Installed
        }
        'WN16-00-000360' {
            Check-WindowsFeature -Feature Web-Ftp-Service -InCorrectState Installed
        }
        'WN16-00-000370' {
            Check-WindowsFeature -Feature PNRP -InCorrectState Installed
        }
        'WN16-00-000380' {
            Check-WindowsFeature -Feature Simple-TCPIP -InCorrectState Installed
        }
        'WN16-00-000390' {
            Check-WindowsFeature -Feature Telnet-Client -InCorrectState Installed
        }
        'WN16-00-000400' {
            Check-WindowsFeature -Feature TFTP-Client -InCorrectState Installed
        }
        'WN16-00-000410' {
            Check-WindowsFeature -Feature FS-SMB1 -InCorrectState Installed
        }
        'WN16-00-000411' {
            if ((Get-WindowsFeature | where Name -like "FS-SMB1").INstallState -like "Installed") {
                Check-RegistryVuln $Vuln
            }
        }
        'WN16-00-000412' {
            Check-RegistryVuln $Vuln
        }
        'WN16-00-000420' {
            Check-WindowsFeature -Feature PowerShell-v2 -InCorrectState Installed
        }
        'WN16-00-000430' {
            if ((Get-WindowsFeature | where name -like "*ftp*").InstallState -eq "Installed"){
                $WNCheck = Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name Enabled | select Value
                if ($WNCheck) { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-00-000440' {
            if ((Get-WindowsFeature | where name -like "*ftp*").InstallState -eq "Installed"){
                Import-Module IISAdministration  
                $SitesPath = Get-ChildItem IIS:\Sites | foreach {$_.PhysicalPath}
                foreach ($Site in $SitesPath) {´                    if (($SitesPath -contains "%systemdrive%\*") -or ($SitesPath -contains "C:\*")) {
                        $global:VulnActive+=$Vuln
                    }                }
            }
        }
        'WN16-00-000450' {
            if ((GetComputerType) -notlike "Domain Controller"){
                $WNCheck = w32tm /query /configuration | Select-String -Pattern 'NTPServer'
                if ($WNCheck -like "*local*") { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-00-000460' {
            Secedit /Export /Areas USER_RIGHTS /CFG C:\Windows\temp\seceditConfig_UsersRights.txt
            $SeceditExport = Get-content -Path "C:\Windows\temp\seceditConfig_UsersRights.txt" | select-string "\*S-1-"
            if ($SeceditExport) { $global:WarningActive+=$Vuln }
            
        }
        'WN16-00-000470' {
            if (CheckUEFI) {
                $WNCheck = Confirm-SecureBootUEFI
                if (!($WNCheck)) { $global:VulnActive+=$Vuln }    
            }

        }
        'WN16-00-000480' {
            if (!(CheckUEFI)) { $global:VulnActive+=$Vuln }    
        }
        #endregion WN16-00

        #region WN16-AC
        'WN16-AC-000010' {
            Check-SecurityPolicy -Vuln $Vuln -Policy LockoutDuration -Value 1..14
        }
        'WN16-AC-000020' {
            Secedit /Export /Areas SecurityPolicy /CFG C:\Windows\temp\seceditConfig.txt
            $SeceditExport = Get-content -Path "C:\Windows\temp\seceditConfig.txt" | select-string "LockoutBadCount"
            if($SeceditExport){
                $valueSecedit = $seceditExport.Line.Split("=").Trim()
                if (($valueSecedit[1] -gt 3) -or ($ValueSecedit[1] -eq 0)) {
                    $global:VulnActive+=$Vuln
                }
            }else {
                $global:VulnActive+=$Vuln
            }
        }
        'WN16-AC-000030' {
            Check-SecurityPolicy -Vuln $Vuln -Policy ResetLockoutCount -Value 1..14
        }
        'WN16-AC-000040' {
            Check-SecurityPolicy -Vuln $Vuln -Policy PasswordHistorySize -Value 1..24
        }
        'WN16-AC-000050' {
            
            Secedit /Export /Areas SecurityPolicy /CFG C:\Windows\temp\seceditConfig.txt
            $SeceditExport = Get-content -Path "C:\Windows\temp\seceditConfig.txt" | select-string "MaximumPasswordAge"
            if($SeceditExport){
                $valueSecedit = $seceditExport.Line.Split("=").Trim()
                if (($valueSecedit[1] -gt 60) -or ($ValueSecedit[1] -eq 0)) {
                    $global:VulnActive+=$Vuln
                }
            }else {
                $global:VulnActive+=$Vuln
            }
        }
        'WN16-AC-000060' {
            Check-SecurityPolicy -Vuln $Vuln -Policy MinimumPasswordAge -Value !0
        }
        'WN16-AC-000070' {
            Check-SecurityPolicy -Vuln $Vuln -Policy MinimumPasswordLength -Value 1..13
        }
        'WN16-AC-000080' {
            Check-SecurityPolicy -Vuln $Vuln -Policy PasswordComplexity -Value !0
        }
        'WN16-AC-000090' {
            Check-SecurityPolicy -Vuln $Vuln -Policy ClearTextPassword -Value !1

        }
        #endregion WN16-AC

        #region WN16-AU
        'WN16-AU-000010' {
            $global:WarningActive+=$Vuln
        }
        'WN16-AU-000020' {
            $global:WarningActive+=$Vuln
        }

        'WN16-AU-000030' {
            $DefaultRute = "$($env:SystemRoot)\System32\winevt\Logs\Application.evtx";
            $acls = (icacls $DefaultRute)
            $Status = "OK"
            foreach ($acl in $acls) {
                if (!$acl) { continue } 
                elseif ($acl -like '*NT AUTHORITY\SYSTEM:(I)(F)') { continue } 
                elseif ($acl -like '*BUILTIN\Administrators:(I)(F)') { continue } 
                elseif ($acl -like '*NT SERVICE\EventLog:(I)(F)') { continue } 
                elseif ($acl -like 'Successfully processed*') { continue }
                $status = 'FAILED'
            }
            if ($status -like "*FAILED*") { $global:VulnActive+=$Vuln }
            
        }
        'WN16-AU-000040' {
            $DefaultRute = "$($env:SystemRoot)\System32\winevt\Logs\Security.evtx";
            $acls = (icacls $DefaultRute)
            $Status = "OK"
            foreach ($acl in $acls) {
                if (!$acl) { continue } 
                elseif ($acl -like '*NT AUTHORITY\SYSTEM:(I)(F)') { continue } 
                elseif ($acl -like '*BUILTIN\Administrators:(I)(F)') { continue } 
                elseif ($acl -like '*NT SERVICE\EventLog:(I)(F)') { continue } 
                elseif ($acl -like 'Successfully processed*') { continue }
                $status = 'FAILED'


            }
            if ($status -like "*FAILED*") { $global:VulnActive+=$Vuln }
            
        }
        'WN16-AU-000050' {
            $DefaultRute = "$($env:SystemRoot)\System32\winevt\Logs\System.evtx";
            $acls = (icacls $DefaultRute)
            $Status = "OK"
            foreach ($acl in $acls) {
                if (!$acl) { continue } 
                elseif ($acl -like '*NT AUTHORITY\SYSTEM:(I)(F)') { continue } 
                elseif ($acl -like '*BUILTIN\Administrators:(I)(F)') { continue } 
                elseif ($acl -like '*NT SERVICE\EventLog:(I)(F)') { continue } 
                elseif ($acl -like 'Successfully processed*') { continue }
                $status = 'FAILED'


            }
            if ($status -like "*FAILED*") { $global:VulnActive+=$Vuln }
            
        }
        'WN16-AU-000060' {
            $WNCheck = (Get-Acl -Path C:\Windows\system32\eventvwr.exe).Access | foreach {if (($_.FileSystemRights -like "FullControl") -and ($_.IdentityReference -notlike "TrustedInstaller")){$WNCheck = $_.IdentityReference}}
            if ($WNCheck) { $global:VulnActive+=$Vuln } 
        }
        'WN16-AU-000070' {
            $WNCheck = auditpol /get /category:* | Select-String "Credential Validation"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln } 
        }
        'WN16-AU-000080' {
            $WNCheck = auditpol /get /category:* | Select-String "Credential Validation"
            if ($WNCheck -notlike "*failure*") { $global:VulnActive+=$Vuln } 
        }
        'WN16-AU-000100' {
            #$WNCheck = auditpol /get /category:* | Select-String "Otros eventos de administración de cuentas"
            $WNCheck = auditpol /get /category:* | Select-String "Other Account Management Events"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000120' {
            $WNCheck = auditpol /get /category:* | Select-String "Security Group Management"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000140' {
            $WNCheck = auditpol /get /category:* | Select-String "User Account Management"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000150' {
            $WNCheck = auditpol /get /category:* | Select-String "User Account Management"
            if ($WNCheck -notlike "*Failure*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000160' {
            $WNCheck = auditpol /get /category:* | Select-String "Plug and Play Events"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000170' {
            $WNCheck = auditpol /get /category:* | Select-String "Process Creation"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000220' {
            $WNCheck = auditpol /get /category:* | Select-String "Account Lockout"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000230' {
            $WNCheck = auditpol /get /category:* | Select-String "Account Lockout"
            if ($WNCheck -notlike "*Failure*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000240' {
            $WNCheck = auditpol /get /category:* | Select-String "Group Membership"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000250' {
            $WNCheck = auditpol /get /category:* | Select-String "Logoff"
            if ($WNCheck[1] -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000260' {
            $WNCheck = auditpol /get /category:* | Select-String "Logon"
            if ($WNCheck[1] -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000270' {
            $WNCheck = auditpol /get /category:* | Select-String "Logon"
            if ($WNCheck[1] -notlike "*Failure*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000280' {
            $WNCheck = auditpol /get /category:* | Select-String "Special Logon"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000285' {
            $WNCheck = auditpol /get /category:* | Select-String "Other Object Access Events"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000286' {
            $WNCheck = auditpol /get /category:* | Select-String "Other Object Access Events"
            if ($WNCheck -notlike "*Failure*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000290' {
            $WNCheck = auditpol /get /category:* | Select-String "Removable Storage"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000300' {
            $WNCheck = auditpol /get /category:* | Select-String "Removable Storage"
            if ($WNCheck -notlike "*Failure*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000310' {
            $WNCheck = auditpol /get /category:* | Select-String "Audit Policy Change"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000320' {
            $WNCheck = auditpol /get /category:* | Select-String "Audit Policy Change"
            if ($WNCheck -notlike "*Failure*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000330' {
            $WNCheck = auditpol /get /category:* | Select-String "Authentication Policy Change"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000340' {
            $WNCheck = auditpol /get /category:* | Select-String "Authorization Policy Change"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000350' {
            $WNCheck = auditpol /get /category:* | Select-String "Sensitive Privilege Use"
            if ($WNCheck[1] -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000360' {
            $WNCheck = auditpol /get /category:* | Select-String "Sensitive Privilege Use"
            if ($WNCheck[1] -notlike "*Failure*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000370' {
            $WNCheck = auditpol /get /category:* | Select-String "IPsec Driver"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000380' {
            $WNCheck = auditpol /get /category:* | Select-String "IPsec Driver"
            if ($WNCheck -notlike "*Failure*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000390' {
            $WNCheck = auditpol /get /category:* | Select-String "Other System Events"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000400' {
            $WNCheck = auditpol /get /category:* | Select-String "Other System Events"
            if ($WNCheck -notlike "*Failure*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000410' {
            $WNCheck = auditpol /get /category:* | Select-String "Security State Change"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000420' {
            $WNCheck = auditpol /get /category:* | Select-String "Security System Extension"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000440' {
            $WNCheck = auditpol /get /category:* | Select-String "System Integrity"
            if ($WNCheck -notlike "*Success*") { $global:VulnActive+=$Vuln }
        }
        'WN16-AU-000450' {
            $WNCheck = auditpol /get /category:* | Select-String "System Integrity"
            if ($WNCheck -notlike "*Failure*") { $global:VulnActive+=$Vuln }
        }
        #endregion WN16-AU

        #region WN16-CC
        'WN16-CC-000010' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000030' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000040' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000050' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000060' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000070' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000080' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000090' {
	        #Check-RegistryVuln $Vuln
            $WNCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\" -Name "\\*\NETLOGON" -ErrorAction Ignore
            if ((!$WNCheck) -or ($WNCheck.'\\*\NETLOGON' -notlike "RequireMutualAuthentication=1,RequireIntegrity=1")) { $global:VulnActive+=$Vuln }
            
            $WNCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\" -Name "\\*\SYSVOL" -ErrorAction Ignore
            if ((!$WNCheck) -or ($WNCheck.'\\*\SYSVOL' -notlike "RequireMutualAuthentication=1,RequireIntegrity=1")) { $global:VulnActive+=$Vuln }

        }
        'WN16-CC-000100' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000110' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000140' {
	        #Check-RegistryVuln $Vuln
            $WNCheck = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" -Name "DriverLoadPolicy" -ErrorAction Ignore
            if ($WNCheck.'DriverLoadPolicy' -like "7") { $global:VulnActive+=$Vuln }
        }
        'WN16-CC-000150' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000160' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000170' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000180' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000210' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000220' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000240' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000250' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000260' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000270' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000280' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000290' {
	        #Check-RegistryVuln $Vuln
            $WNCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name "AllowTelemetry" -ErrorAction Ignore
            if ((!$WNCheck) -or (($WNCheck.'AllowTelemetry' -notlike 0) -and ($WNCheck.'AllowTelemetry' -notlike 1))) { $global:VulnActive+=$Vuln }
        }
        'WN16-CC-000300' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000310' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000320' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000330' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000340' {
	        Check-RegistryVuln $Vuln -CanBeNull "true"
        }
        'WN16-CC-000350' {
	        Check-RegistryVuln $Vuln -CanBeNull "true"
        }
        'WN16-CC-000360' {
	        Check-RegistryVuln $Vuln -CanBeNull "true"
        }
        'WN16-CC-000370' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000380' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000390' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000400' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000410' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000420' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000421' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000430' {
	        Check-RegistryVuln $Vuln -CanBeNull "true"
        }
        'WN16-CC-000440' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000450' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000460' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000470' {
	        Check-RegistryVuln $Vuln -CanBeNull "true"
        }
        'WN16-CC-000480' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000490' {
	        #Check-RegistryVuln $Vuln
            $WNCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name "EnableScriptBlockLogging" -ErrorAction Ignore
            if ((!$WNCheck) -or ($WNCheck.'EnableScriptBlockLogging' -notlike 1)) { $global:VulnActive+=$Vuln }
    

        }
        'WN16-CC-000500' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000510' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000520' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000530' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000540' {
	        Check-RegistryVuln $Vuln
        }
        'WN16-CC-000550' {
	        Check-RegistryVuln $Vuln
        }
        #endregion WN16-CC

        #region WN16-MS

        'WN16-MS-000010' {
            if (((GetComputerType) -eq "Member Server") -or ((GetComputerType) -eq "Workstation")){
                $AdmMembers = Get-ADGroupMember Administrators
                
                # Si hay algún usuario estandar que no sea el adminsitrador built-in, es una vulnerabilidad
                $AdmMembers | where ObjectClass -eq "User" | foreach {
                    if ($_.SID -notlike "*-500") {$global:VulnActive+=$Vuln}
                }
                $AdmMembers | where ObjectClass -eq "Group" | foreach { 
                    if ($_.SID -like "S-1-5-domain-512") {$global:VulnActive+=$Vuln}
                }
            }
        }
        'WN16-MS-000020' {
            if ((GetComputerType) -like "Member Server"){
                Check-RegistryVuln $Vuln
            }
        }
        'WN16-MS-000030' {
            if ((GetComputerType) -eq "Member Server"){
                Check-RegistryVuln $Vuln
            }
        }
        'WN16-MS-000040' {
            if ((GetComputerType) -eq "Member Server"){
                Check-RegistryVuln $Vuln
            }
        }
        'WN16-MS-000050' {
            if ((GetComputerType) -eq "Member Server"){
                Check-RegistryVuln $Vuln
            }
        }
        'WN16-MS-000120' {
            if ((GetComputerType) -eq "Member Server"){
                $WNCheck = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" | select SecurityServicesRunning
                if ($WNCheck -notcontains 1) { $global:VulnActive+=$Vuln }
            }
        }
        'WN16-MS-000310' {
            if ((GetComputerType) -eq "Member Server"){
                Check-RegistryVuln $Vuln
            }
        }
        'WN16-MS-000340' {
            if (((GetComputerType) -eq "Member Server") -or ((GetComputerType) -eq "Workstation")){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeNetworkLogonRight -Value "S-1-5-32-544,S-1-5-11"
            }
        }
        'WN16-MS-000370' {
            if (((GetComputerType) -eq "Member Server") -or ((GetComputerType) -eq "Workstation")){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeDenyNetworkLogonRight -Value "S-1-5-root domain-519, S-1-5-domain-512, S-1-5-113, S-1-5-32-546"
            }
        }
        'WN16-MS-000380' {
            if (((GetComputerType) -eq "Member Server") -or ((GetComputerType) -eq "Workstation")){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeDenyBatchLogonRight -Value "S-1-5-root domain-519, S-1-5-domain-512, S-1-5-32-546"
            }
        }
        'WN16-MS-000390' {
            if (((GetComputerType) -eq "Member Server") -or ((GetComputerType) -eq "Workstation")){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeDenyServiceLogonRight -Value "S-1-5-root domain-519, S-1-5-domain-512"
            }
        }
        'WN16-MS-000400' {
            if (((GetComputerType) -eq "Member Server") -or ((GetComputerType) -eq "Workstation")){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeDenyInteractiveLogonRight -Value "S-1-5-root domain-519, S-1-5-domain-512, S-1-5-32-546"
            }
        }
        'WN16-MS-000410' {
            if (((GetComputerType) -eq "Member Server") -or ((GetComputerType) -eq "Workstation")){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeDenyRemoteInteractiveLogonRight -Value "S-1-5-root domain-519, S-1-5-domain-512, S-1-5-113, S-1-5-32-546"
            }
        }
        'WN16-MS-000420' {
            if (((GetComputerType) -eq "Member Server") -or ((GetComputerType) -eq "Workstation")){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeEnableDelegationPrivilege
            }
        }
        #endregion WN16-MS
        
        #region WN16-SO

        'WN16-SO-000010' {
            Check-SecurityPolicy -Vuln $Vuln -Policy EnableGuestAccount -Value !1
        }
        'WN16-SO-000020' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000030' {
            #Check-SecurityPolicy -Vuln $Vuln -Policy NewAdministratorName -Value 
            Secedit /Export /Areas SecurityPolicy /CFG C:\Windows\temp\seceditConfig_SecurityPolicy.txt
            $SeceditExport = Get-content -Path "C:\Windows\temp\seceditConfig_SecurityPolicy.txt" | select-string NewAdministratorName
            
            if($SeceditExport){
                #Está configurado, obtenemos valor
                $valueSecedit = $seceditExport.Line.Split("=").Trim()
                
                #Si no esta configurado como deberia, incumple
                if ($valueSecedit[1] -like "Administrator") {
                    $global:VulnActive+=$Vuln
                }
            }else {
                #Si no está configurado, incumple
                $global:VulnActive+=$Vuln
            }
        }
        'WN16-SO-000040' {
            #Check-SecurityPolicy -Vuln $Vuln -Policy "NewGuestName" -Value 
            Secedit /Export /Areas SecurityPolicy /CFG C:\Windows\temp\seceditConfig_SecurityPolicy.txt
            $SeceditExport = Get-content -Path "C:\Windows\temp\seceditConfig_SecurityPolicy.txt" | select-string NewGuestName
            
            if($SeceditExport){
                #Está configurado, obtenemos valor
                $valueSecedit = $seceditExport.Line.Split("=").Trim()
                
                #Si no esta configurado como deberia, incumple
                if ($valueSecedit[1] -like "Guest") {
                    $global:VulnActive+=$Vuln
                }
            }else {
                #Si no está configurado, incumple
                $global:VulnActive+=$Vuln
            }
        }
        'WN16-SO-000050' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000080' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000090' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000100' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000110' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000120' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000130' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000140' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000150' {
            #Check-RegistryVuln $Vuln
            $WNCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LegalNoticeText
            
            if ($WNCheck.LegalNoticeText -notlike "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only*") { $global:VulnActive+=$Vuln }
        }
        'WN16-SO-000160' {
            #Check-RegistryVuln $Vuln
            $WNCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LegalNoticeCaption
            
            if ($WNCheck.LegalNoticeCaption -notlike "*US Department of Defense Warning Statement*") { $global:VulnActive+=$Vuln }
        }
        'WN16-SO-000180' {
            #Check-RegistryVuln $Vuln
            $WNCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name scremoveoption -ErrorAction Ignore
            if ((!$WNCheck) -or (($WNCheck.scremoveoption -notlike "1") -and ($WNCheck.scremoveoption -notlike "2"))) { $global:VulnActive+=$Vuln }
        }
        'WN16-SO-000190' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000200' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000210' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000230' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000240' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000250' {
            Check-SecurityPolicy -Vuln $Vuln -Policy LSAAnonymousNameLookup -Value !1
        }
        'WN16-SO-000260' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000270' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000290' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000300' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000320' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000330' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000340' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000350' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000360' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000380' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000390' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000400' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000410' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000420' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000430' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000450' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000460' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000470' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000480' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000490' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000500' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000510' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000520' {
            Check-RegistryVuln $Vuln
        }
        'WN16-SO-000530' {
            Check-RegistryVuln $Vuln
        }
        #endregion WN16-SO

        #region WN16-UC
        'WN16-UC-000030' {
            $WNCheck = Get-ItemProperty -Path "HKCU:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name SaveZoneInformation -ErrorAction Ignore
            if (($WNCheck -like "1")) { $global:VulnActive+=$Vuln }
        }
        #endregion WN16-UC

        #region WN16-UR
        'WN16-UR-000010' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeTrustedCredManAccessPrivilege -CanBeNull true
        }
        'WN16-UR-000030' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeTcbPrivilege -CanBeNull true
        }
        'WN16-UR-000050' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeInteractiveLogonRight -Value "S-1-5-32-544"
        }
        'WN16-UR-000070' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeBackupPrivilege -Value "S-1-5-32-544"
        }
        'WN16-UR-000080' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeCreatePagefilePrivilege -Value "S-1-5-32-544"
        }
        'WN16-UR-000090' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeCreateTokenPrivilege -CanBeNull true
        }
        'WN16-UR-000100' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeCreateGlobalPrivilege -Value "S-1-5-19,S-1-5-20,S-1-5-32-544,S-1-5-6"
            <# ID - Group
            S-1-5-32-544 (Administrators)
            S-1-5-6 (Service)
            S-1-5-19 (Local Service)
            S-1-5-20 (Network Service)
            #>
        }
        'WN16-UR-000110' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeCreatePermanentPrivilege -CanBeNull true
        }
        'WN16-UR-000120' {
            $HyperVCheck = Get-WindowsFeature | Where {$_.Name -eq 'Hyper-V'} | SELECT 'InstallState' | Format-List
            if ($HyperVCheck -like "*Installed*"){
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeCreateSymbolicLinkPrivilege -value "S-1-5-83-0,S-1-5-32-544"
            }else {
                Check-UsersRightsPolicy -Vuln $Vuln -Policy SeCreateSymbolicLinkPrivilege -value "S-1-5-32-544"
            }
        }
        'WN16-UR-000130' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeDebugPrivilege -Value "S-1-5-32-544"
        }
        'WN16-UR-000200' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeRemoteShutdownPrivilege -Value "S-1-5-32-544"
        }
        'WN16-UR-000210' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeAuditPrivilege -Value "S-1-5-19,S-1-5-20"
            
        }
        'WN16-UR-000220' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeImpersonatePrivilege -Value "S-1-5-19,S-1-5-20,S-1-5-32-544,S-1-5-6"
            
        }
        'WN16-UR-000230' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeIncreaseBasePriorityPrivilege -Value "S-1-5-32-544"
            
        }
        'WN16-UR-000240' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeLoadDriverPrivilege -Value "S-1-5-32-544"
            
        }
        'WN16-UR-000250' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeLockMemoryPrivilege -CanBeNull true
            
        }
        'WN16-UR-000260' {
            #si hay otro, dar como info ya que puede ser grupo de auditores
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeSecurityPrivilege -Value "S-1-5-32-544"
        }
        'WN16-UR-000270' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeSystemEnvironmentPrivilege -Value "S-1-5-32-544"
        }
        'WN16-UR-000280' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeManageVolumePrivilege -Value "S-1-5-32-544"
        }
        'WN16-UR-000290' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeProfileSingleProcessPrivilege -Value "S-1-5-32-544"
        }
        'WN16-UR-000300' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeRestorePrivilege -Value "S-1-5-32-544"
        }
        'WN16-UR-000310' {
            Check-UsersRightsPolicy -Vuln $Vuln -Policy SeTakeOwnershipPrivilege -Value "S-1-5-32-544"
        }
        #endregion WN16-UR

        #region WN16-PK
        'WN16-PK-000010' {
            $DODCerts = Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD Root CA*"
            if (!$DODCerts) {
                $global:VulnActive+=$Vuln
            }
        }
        'WN16-PK-000020' {
            
            #$DODCerts = Get-ChildItem -Path Cert:Localmachine\disallowed | Where Subject -Like "*DoD*" | FL Subject, Issuer, Thumbprint, NotAfter
            $DODCerts = Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"}
            if (!$DODCerts) {
                $global:VulnActive+=$Vuln
            }     
        }
        'WN16-PK-000030' {
            $DODCerts3 = Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*"
            if (!$DODCerts3) { $global:VulnActive+=$Vuln }
        }
        #endregion WN16-PK
    }
    
}


#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$Baseline = Get-OptionBaseline

#Set Error Action to Silently Continue
$ErrorActionPreference = "Inquire"

# Log
$DirLog = "$($PSScriptRoot)\Logs"
$ScriptName = $MyInvocation.MyCommand.Name.Split('.')[0]
$LogFile = "$($DirLog)\$($ScriptName)_$(Get-Date -Format "yyyy-MM-dd").log"


#-----------------------------------------------------------[Execution]------------------------------------------------------------

Write-Log -Message "Running $($ScriptName) with $($env:USERNAME). Start: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level Info

if ($Implement) {
    #Importación de certificados utilizando lautilidad de DOD DISA
    Start-Process -FilePath "msiexec" -ArgumentList "/i $($PSScriptRoot)\CertificatesUtility\InstallRoot_5.5x64.msi" -Wait
    Start-Process -FilePath "C:\Program Files\DoD-PKE\InstallRoot\InstallRoot.exe" -ArgumentList "--insert" -Wait
    Start-Process -FilePath "msiexec" -ArgumentList "/x $($PSScriptRoot)\CertificatesUtility\InstallRoot_5.5x64.msi /qn" -Wait

    #Modify lDAP atributes
    ntdsutil "LDAP policies" connections "connect to server W2016-DC1" quit "Set MaxConnIdleTime to 200" "Commit Changes" quit quit

    if ((Get-WindowsFeature | where name -like "*SMB1*").InstallState -eq "Installed"){ Get-WindowsFeature -Name "*SMB1*" | Remove-WindowsFeature }
    
    # Importar políticas DOD
    Add-Type -AssemblyName Microsoft.VisualBasic

    $DomainAdminsGroup = [Microsoft.VisualBasic.Interaction]::InputBox('Enter the name of DOMAIN ADMINS group of 
    your organization 

    Eg: PRUEBA\DOMAIN ADMINS)',
    'Importing DISA STIGs')
    
    $EnterpriseAdminsGroup = [Microsoft.VisualBasic.Interaction]::InputBox('Enter the name of ENTERPRISE ADMINS group of 
    your organization 

    Eg: PRUEBA\ENTERPRISE ADMINS)',
    'Importing DISA STIGs')

    
    [xml] $ImportTable = Get-Content ".\U_STIG_GPO_Package_November_2020\Support Files\importtable.migtable"
    $ImportTable.MigrationTable.Mapping | foreach {
        if ($_.Source -like "ADD YOUR DOMAIN ADMINS") {
            $_.Source = $DomainAdminsGroup
        }
        if ($_.Source -like "ADD YOUR ENTERPRISE ADMINS") {
            $_.Source = $EnterpriseAdminsGroup
        }
    }
    $ImportTable.Save("$($PSScriptRoot)\U_STIG_GPO_Package_November_2020\Support Files\importtable.migtable")
    
    $Command = "$($PSScriptRoot)\U_STIG_GPO_Package_November_2020\Support Files\DISA_GPO_Baseline_Import.ps1 -gpoimportFile '$($PSScriptRoot)\U_STIG_GPO_Package_November_2020\Support Files\DISA_Quarterly_Import_Nov2020.csv' -importtable '$($PSScriptRoot)\U_STIG_GPO_Package_November_2020\Support Files\importtable.migtable'"
    $Script = "$($PSScriptRoot)\U_STIG_GPO_Package_November_2020\'Support Files'\DISA_GPO_Baseline_Import.ps1"
    $params = '-gpoimportFile "C:\temp\BaselineAuditingTool\U_STIG_GPO_Package_November_2020\Support Files\DISA_Quarterly_Import_Nov2020.csv" -importtable "C:\temp\BaselineAuditingTool\U_STIG_GPO_Package_November_2020\Support Files\importtable.migtable"'
    Invoke-Expression "$Script $params"
    
} else {
    # Comprobamos la introducción del XML del paráemtro
    if (!(Test-path $Baseline)){
        Write-Log "Specified file not found. $($Baseline) " -level Warn
        Exit 1
    }

    # Importamos el fichero XML y creamos los arrays principales que almacenan los items failed y warnings
    [xml]$XMLContent = Get-Content -Path $Baseline
    $global:VulnActive = @()
    $global:WarningActive = @()

    # Recorremos los items del XML
    foreach ($VulnItem in $XMLContent.Benchmark.Group){
        #Se muestra por pantalla el item que está analizando en cada momento
        $VulnID = $VulnItem.id
        $VulnWN = $VulnItem.Rule.Version
        Write-Log -message "Analyzing vulnerability $($VulnID) - $($VulnWN)" -level Info

        # Analizamos los items
        Set-Location C:
        OthersVulnerabilities -Vuln $VulnItem
    }

    #region Muestra de resultados
    ### MUESTRA DE RESULTADOS

    $VulnActiveFormatArray = @()
    foreach ($VulnWithoutFormat in $global:VulnActive) {
        $VulnActiveFormat = [PSCustomObject]@{
            ID = $VulnWithoutFormat.ID
            WN = $VulnWithoutFormat.Rule.Version
            Severity = $VulnWithoutFormat.Rule.Severity
            Description = $VulnWithoutFormat.Rule.Check."Check-content"
        }
        $VulnActiveFormatArray+=$VulnActiveFormat
    }

    $WarningsFormatArray = @()
    foreach ($WarningWithoutFormat in $global:WarningActive) {
        $WarningFormat = [PSCustomObject]@{
            ID = $WarningWithoutFormat.ID
            WN = $WarningWithoutFormat.Rule.Version
            Severity = $WarningWithoutFormat.Rule.Severity
            Description = $WarningWithoutFormat.Rule.Check."Check-content"
        }
        $WarningsFormatArray+=$WarningFormat
    }

    $WarningsFormatArray | Out-GridView -Title "Warnings Active in $($env:COMPUTERNAME)"
    $VulnActiveFormatArray | Out-GridView -Title "Vulnerabilities Active in $($env:COMPUTERNAME)"
    $WarningsFormatArray | Select ID,WN,Severity | export-csv -Path ".\ResultsCSV\warnings_$($(Get-Date -Format "yyyy-MM-dd_HH-mm-ss")).csv"
    $VulnActiveFormatArray | Select ID,WN,Severity | export-csv -Path ".\ResultsCSV\vulnes_$($(Get-Date -Format "yyyy-MM-dd_HH-mm-ss")).csv"

    $totalItems = $XMLContent.Benchmark.Group.Count
    $totalPassed = $totalItems-$global:WarningActive.Count-$global:VulnActive.Count

    Write-Log -message "Total de items: $($totalItems)" -level Info
    Write-Log -message "Total de vulnerabilidades (failed): $($global:VulnActive.Count)" -level Info
    Write-Log -message "Total de Warnings: $($global:WarningActive.Count)" -level Info
    Write-Log -message "Total de passed: $($totalPassed)" -level Info
    Write-Log -message "------------------------------------------------------" -level Info
    Write-Log -message "Failed: $(($global:VulnActive.Count/$totalItems)*100)%" -level Info
    Write-Log -message "Warnings: $(($global:WarningActive.Count/$totalItems)*100)%" -level Info
    Write-Log -message "Passed: $(($totalPassed/$totalItems)*100)%" -level Info

    [System.Windows.MessageBox]::Show(
    "Total of items checked: $($totalItems)
    Total of vulnerabilities active: $($global:VulnActive.Count)
    Total of warnings (require of supervise by SSOO Department): $($global:WarningActive.Count)
    Total of items passed correctly: $($totalPassed)

    ---------------------------------------------------------------------------
    Failed: $([math]::Round((($global:VulnActive.Count/$totalItems)*100),2))%
    Warnings: $([math]::Round((($global:WarningActive.Count/$totalItems)*100),2))%
    Passed: $([math]::Round((($totalPassed/$totalItems)*100),2))%",
    'Resume of auditing DISA baseline','OK','None')
    #endregion Muestra de resultados
}


