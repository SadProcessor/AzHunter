#########################################################
## AzHunter
#
# Get-AzHunterToken         >  Get Token MDE/Sentinel [internal]
# Update-AzHunterToken      >  Update Session Token   [internal]
#
# New-AzHunterSession       >  Create AzHunter Session [MDE/Sentinel]
# Get-AzHunterSession       >  Get AzHunter Session
# Select-AzHunterSession    >  Select AzHunter Session
# Remove-AzHunterSession    >  Remove AzHunter Session
#
# Invoke-AzHunter           >  Fetch Events from MDE/Sentinel [KQL]
# Invoke-AzWriter           >  Write Events to Sentinel [<LogType>_CL]
#
#########################################################


################################################### Cache
# AzHunter Sessions
if(-Not$AzHunter.TenantID){$AzHunter = [System.Collections.ArrayList]@()}


################################################### Utils

<#
.Synopsis
   Select-NotEmpty
.DESCRIPTION
   Remove unpopulated props
.EXAMPLE
   $Obj|NotEmpty
#>
Function Select-NotEmpty{
    [Alias('NotEmpty')]
    Param(
    [Parameter(ValueFromPipeline)][PSObject]$Object
    )
    Begin{}
    Process{
        $PropList = foreach($Prop in ($Obj | Get-Member | Where-Object MemberType -eq NoteProperty).name){if($Obj.$Prop){$Prop}}
        $Obj | select-Object $PropList
        }
    End{}
    }
#End


################################################### Token

<#
.Synopsis
   Get-AzHunterToken
.DESCRIPTION
   Get AzHunter Token
.EXAMPLE
   Get-AzHunterToken $TenantID $AppID $AppSecret -resource 'https://api.loganalytics.io'
.EXAMPLE
   Get-AzHunterToken $TenantID $AppID $AppSecret -resource 'https://api.securitycenter.microsoft.com'
#>
Function Get-AzHunterToken{
    Param(
        # Tenant ID
        [Parameter(Mandatory=1,Position=0)][String]$Tenant,
        # App ID
        [Parameter(Mandatory=1,Position=1)][String]$App,
        # App Secret
        [Parameter(Mandatory=1,Position=2)][String]$Secret,
        # Resource
        [Parameter(Mandatory=1,Position=4)][String]$Resource
        )
    # Prep
    $Uri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $Body = [Ordered] @{
        resource      = $Resource
        client_id     = $app
        client_secret = $Secret
        grant_type    = 'client_credentials'
        }
    # Call
    Invoke-RestMethod -Method Post -Uri $Uri -Body $Body
    }
#End



<#
.Synopsis
   Update-AzHunterToken
.DESCRIPTION
   Update AzHunter Token
.EXAMPLE
   Update-AzHunterToken -IfNeeded
#>
function Update-AzHunterToken{
    Param(
        [Parameter()][String[]]$id=$(($AzHunter|? x).id),
        [Parameter()][Switch]$IfNeeded
        )
    foreach($Sess in $ID){
        # Token Expiry
        $Tok = ($AzHunter| where id -eq $Sess).token
        $Exp = if($IfNeeded){[datetime]::new(1970,1,1).AddSeconds($Tok.expires_on)}else{([datetime]::new(1970,1,1))}
        $Now = [DateTime]::UtcNow
        # If new token required
        if($Now -gt $exp){
            Write-Verbose "Refreshing session token "
            # Session info
            $SessData = ($AzHunter| where id -eq $Sess)
            $TenantID = $SessData.TenanTID
            $AppID    = $SessData.AppID
            $AppSec   = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SessData.AppSec))
            # New Token
            $NewToken = if($SessData.Target -eq 'MDE'){
                # MDE Token
                Get-AzHunterToken $TenantID $AppID $AppSecret -Resource 'https://api.securitycenter.microsoft.com'
                }
            elseif($SessData.Target -eq 'Sentinel'){
                # Sentinel Token
                Get-AzHunterToken $TenantID $AppID $AppSec -Resource 'https://api.loganalytics.io'
                }
            # Replace token
            ($AzHunter| Where id -eq $Sess).token = $NewToken
            }}}
#########End



################################################### Session

<#
.Synopsis
   New-AzHunterSession
.DESCRIPTION
   New AzHunter Session
.EXAMPLE
   New-AzHunterSession $TenantID $AppID $AppSecret
   Create new MDE Session
.EXAMPLE
   New-AzHunterSession $TenantID $AppID $AppSecret $Workspace -Tag 'Prod'
   Create new Sentinel session with specific tag
.EXAMPLE
   New-AzHunterSession $TenantID $AppID $AppSecret $Workspace $SharedKey
   Create new Sentinel session including Sharedkey for AzWriter
#>
function New-AzHunterSession{
    Param(
        [Parameter(Position=0)][String]$TenantID,
        [Parameter(Position=1)][String]$AppID,
        [Parameter(Position=2)][String]$AppSecret,
        [Parameter(Position=3)][String]$Workspace,
        [Parameter(Position=4)][String]$SharedKey,
        [Parameter()][String]$Tag
        )
    # Sentinel|MDE
    $Target = if($WorkSpace){'Sentinel'}else{'MDE'}
    # Uri
    $Uri = Switch($Target){
        Sentinel{"https://api.loganalytics.io/v1/workspaces/$Workspace/query"}
        MDE     {'https://api.securitycenter.microsoft.com/api/advancedqueries/run'}
        }
    # Token
    $Token  = if($AppID -AND $AppSecret){Switch($Target){
        Sentinel{Get-AzHunterToken $TenantID $AppID $AppSecret -Resource 'https://api.loganalytics.io'}
        MDE     {Get-AzHunterToken $TenantID $AppID $AppSecret -Resource 'https://api.securitycenter.microsoft.com'}
        }}
    if($Token.access_token -OR ($SharedKey -AND $Target -eq 'Sentinel')){
        $NewID = if(Get-AzHunterSession){[Int](Get-AzHunterSession | sort-object id -Descending | select-object -First 1 -expand id) +1}else{0}
        If(-Not$Tag){$Tag="Session_$NewID"}
        $Null = $AzHunter.add([PSCustomObject]@{
            x         = ''
            ID        = $NewID
            Target    = $Target
            Tag       = $Tag
            TenantID  = $TenantID
            AppID     = $AppID
            AppSec    = if($AppSecret){$AppSecret | ConvertTo-SecureString -AsPlainText -Force}else{}
            Workspace = $WorkSpace
            SharedKey = if($SharedKey){$SharedKey | ConvertTo-SecureString -AsPlainText -Force}else{}
            Uri       = $Uri
            Token     = $Token
            })
        Select-AzHunterSession $NewID
        }Else{Write-Warning 'Missing Parameters - No Session Created'}}
#####End


<#
.Synopsis
   Get-AzHunterSession
.DESCRIPTION
   Get AzHunter Session
.EXAMPLE
   Get-AzHunterSession
.EXAMPLE
   Get-AzHunterSession -Selected
.EXAMPLE
   Get-AzHunterSession -Full
#>
function Get-AzHunterSession{
    [CmdletBinding(DefaultParameterSetName='short')]
    [Alias('AzHunterSession')]
    Param(
        [Parameter(ParameterSetName='x')][Alias('x')][Switch]$Selected,
        [Parameter(ParameterSetName='full')][Switch]$Full
        )
    if($Full){$AzHunter|%{$_}}
    elseif($Selected){$AzHunter|? x|%{$_|Select-object x,id,Tag,Workspace}}
    else{$AzHunter|%{$_|Select-object x,id,Tag,Workspace}}
    }
#End


<#
.Synopsis
   Select-AzHunterSession
.DESCRIPTION
   Select AzHunter Session
.EXAMPLE
   Select-AzHunterSession 2,3
.EXAMPLE
   Select-AzHunterSession -None
#>
function Select-AzHunterSession{
    [CmdletBinding(DefaultParameterSetName='ID')]
    Param(
        [Parameter(ParameterSetName='None')][Switch]$None,
        [Parameter(ParameterSetName='ID',Position=0)][Int[]]$ID
        )
    if($None){$AZHunter|? x|%{$_.x=$Null}}
    else{
        $AZHunter|? x|%{$_.x=$Null}
        $AzHunter|? id -in ($ID)|%{$_.x='x'}
        }}
#####End


<#
.Synopsis
   Get AzHunter Session
.DESCRIPTION
   Remove AzHunter Session
.EXAMPLE
   Remove-AzHunterSession 1
#>
function Remove-AzHunterSession{
    Param(
        [Parameter(Mandatory=1)][Int[]]$Id
        )
    foreach($Session in ($ID)){
        $AzHunter.remove(($AzHunter|? id -eq $Session))
        }}
#####End



################################################### AzHunter

<#
.Synopsis
   Invoke-AzHunter
.DESCRIPTION
   Invoke AzHunter Query
.NOTES
   https://docs.microsoft.com/en-us/azure/azure-monitor/logs/api/overview
.EXAMPLE
   AzHunter "DeviceEvents | take 1"
.EXAMPLE
   $Query1,$Query2,$Query3 | AzHunter -Id 2,3 -Tag | Group-Object Tag
#>
function Invoke-AzHunter{
    [Alias('AzHunter','KQL')]
    Param(
        [Parameter(ValueFromPipeline=1,Mandatory=1,Position=0)][String[]]$Query,
        [Parameter()][Int]$Take,
        [Parameter()][String[]]$Project,
        [Parameter()][Switch]$NoEmpty,
        [Parameter()][Switch]$Tag,
        [Parameter()][Switch]$Report,
        #[Parameter()][Switch]$DBG,
        [Parameter()][Alias('Session')][Int[]]$Id=$(($AzHunter|? x).id),
        [Parameter()][Switch]$Raw
        )
    Begin{}
    Process{
        Foreach($TargetID in $ID){
            # Set target
            $Target = $AzHunter | ? id -eq $TargetID
            # Return if 'Write-Only' Session
            if(-Not$Target.Token.access_token){Write-Warning "Hunting requires AppID and AppSecret";RETURN}
            # Renew Token if needed
            Update-AzHunterToken -id $TargetID -IfNeeded
            Foreach($KQL in $Query){
                if($Take){$KQL += "`r`n| take $Take"}
                if($Project){$KQL += "`r`n| project $($Project-join',')"}
                ## Prep
                $Head = @{'Content-type'="application/json"; Authorization="Bearer $($Target.token.access_token)"}
                Switch($Target.target){
                    MDE{$Body = @{Query=$KQL} | ConvertTo-Json
                        $Uri  = [Web.HttpUtility]::UrlPathEncode($target.Uri)
                        $Meth = 'POST'
                        $Q    = $KQL
                        }
                    Sentinel{$Body = $Null
                        $WebQ = $KQL.replace("`r`n",'%20').replace(" ",'%20')
                        $Uri  = [Web.HttpUtility]::UrlPathEncode("$($Target.uri)?query=$WebQ")
                        $Meth = 'GET'
                        $Q    = $KQL
                        }}
                ## Debug
                if($Dbg){Return [PSCustomObject]@{Method=$Meth;Uri=$Uri;Head=$Head;Body=$Body;Query=$Q}}
                ## Call
                $Reply = Try{Invoke-RestMethod -Method $Meth -Uri $Uri -Headers $Head -Body $Body}catch{
                    Write-Warning ($Error[0].ErrorDetails.Message|ConvertFrom-Json).error.message}
                ## Output
                if($Raw){Return $Reply}
                else{Switch($Target.target){
                        MDE{$Obj = $Reply.Results
                            if($Tag){$Obj|Add-Member -MemberType NoteProperty -Name 'Tag' -Value $Target.tag}
                            if($NoEmpty){$Obj=$Obj|NotEmpty}
                            if($Report){[PSCustomObject]@{Tag=$Target.Tag;Query=$KQL;Result=$Obj}}else{$Obj}
                            }
                        Sentinel{
                            $Rows    = ($Reply.tables|? name -eq 'PrimaryResult').rows
                            $Columns = ($Reply.tables|? name -eq 'PrimaryResult').columns
                            if($Report){[Collections.ArrayList]$Res=@()}
                            Foreach($Row in $Rows){
                                $Obj = [PSCustomObject]@{}
                                $i=0
                                foreach($R in $Row){
                                    $Obj | Add-Member -MemberType NoteProperty -Name ($Columns.name)[$i] -Value $R -force
                                    $i+=1
                                    }
                                if($Tag){$Obj|Add-Member -MemberType NoteProperty -Name 'Tag' -Value $Target.tag}
                                if($NoEmpty){$Obj = $Obj|NotEmpty}
                                if($Report){$Null = $Res.add($Obj)}else{$Obj}
                                }
                            if($Report){[PSCustomObject]@{Tag=$Target.Tag;Query=$KQL;Result=$Res}}
                            }}}}}}
    End{}#######################
    }
#End


################################################### AzWriter

<#
.SYNOPSIS
Invoke Azure Event Writer
.DESCRIPTION
Write Events to Azure HTTP Data Collector API
.NOTES
https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
.EXAMPLE
Invoke-AzWriter -LogType 'MyCustomTable' -EventID '123' -Message 'This is a test'
#>
Function Invoke-AzWriter{
    [Alias('AzWriter')]
    Param(
        # Table (Type)
        [Parameter(Mandatory=0)][Alias('Table')][String]$LogType='AzWriter',
        # Event ID
        [Parameter(Mandatory=0)][String]$EventID='1337',
        # Message
        [Parameter(Mandatory=0)][Alias('Description')][String]$Message='AzWriter - Custom Event',
        # Other Props
        [Parameter(Mandatory=0)][hashtable]$Property=@{},
        # Computer
        [Parameter(Mandatory=0)][Alias('Type')][String]$Computer=$env:COMPUTERNAME,
        # TimeStamp <--------------------------------------------------------------------- Not picked up / wrong format ??
        [Parameter(Mandatory=0)][DateTime]$TimeStamp,
        # _Ressourceid <------------------------------------------------------------------ we be usin' ??
        [Parameter(Mandatory=0)][String]$AzResourceId,
        # DEBUG
        #[Parameter(Mandatory=0)][Switch]$DBG,
        # AzHunter SessionID
        [Parameter(Mandatory=0)][Alias('Session')][int[]]$ID = $(($AzHunter|? x).id)
        )
    Foreach($Sess in $ID){
        # Session Vars
        $AzID  = ($AzHunter | Where id -eq $Sess).Workspace
        $AzKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($($AzHunter|? id -eq $Sess|Select -expand SharedKey)))
        if(-Not$AzKey){Write-Warning "Session $Sess : No Shared Key - No Event written";Break}
        # Call Vars
        $Meth="POST"; $content="application/json"; $API="/api/logs"; $Version='2016-04-01'
        # Body [Obj>Json>Bytes]
        $Property.add('EventID',"$EventID")
        $Property.add('Message',$Message)
        $Property.add('Computer',$Computer)
        $Body = [Text.Encoding]::UTF8.GetBytes(($Property|Convertto-Json))
        # Date [rfc7234]
        $Date = [DateTime]::UtcNow.ToString("r")
        # Auth [AzID:Signature]
        $Sha256 = [Security.Cryptography.HMACSHA256]::New()
        $Sha256.Key = [Convert]::FromBase64String("$AzKey")
        $Byte = [Text.Encoding]::UTF8.GetBytes((($Meth,"$($Body.Length)",$Content,"x-ms-date:$Date",$API)-join"`n"))
        $Hash = [Convert]::ToBase64String(($Sha256.ComputeHash($Byte)))
        $Auth = "SharedKey ${AzId}:${Hash}"
        # Uri
        $uri = "https://"+$AzID+".ods.opinsights.azure.com"+$API+"?api-version=$Version"
        # Head
        $head = @{'Authorization'=$Auth;'Log-Type'=$LogType;'x-ms-date'=$Date}
        # Head [Option]
        if($TimeStamp){$Head.add('time-generated-field',"$($TimeStamp.ToUniversalTime().Tostring('O'))")}
        if($AzResourceId){$Head.add('x-ms-AzureResourceId',"$AzResourceId")}
        ## Debug ##
        #if($DBG){RETURN [PSCustomObject]@{Head=$Head;Body=$Body;Uri=$Uri}}
        ## CALL
        Try{$Null = Invoke-RestMethod -Method $Meth -Uri $uri -ContentType $content -Headers $head -Body $body}
        Catch{Write-Warning ($Error[0].ErrorDetails.Message|convertfrom-Json).message}
        }}
#####End



############################################################## EOF