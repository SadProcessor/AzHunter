#################################################################################
## AzHunter.ps1 <-------------------------- ToDo: Stop using aliases all over the place!!
#
#### Token Stuff [Internal]
# Get-AzHunterToken         >  Get Token MDE/Sentinel/Management
# Update-AzHunterToken      >  Update Session Token
#
#### Session Stuff
# New-AzHunterSession       >  Create AzHunter Session [MDE/Sentinel]
# Get-AzHunterSession       >  Get AzHunter Session
# Select-AzHunterSession    >  Select AzHunter Session
# Remove-AzHunterSession    >  Remove AzHunter Session
#
#### AzHunter Stuff [Log Analytic - Advanced Queries]
# Invoke-AzHunter           >  Fetch Events from MDE/Sentinel [KQL]
#
#### AzWriter Stuff [Http Connector]
# Invoke-AzWriter            >  Write Custom Events to Sentinel [<LogType>_CL]
#
#### AzWatcher Stuff [Management API]
# Invoke-AzWatcher          >  Manipulate Sentinel Watchlists/Alerts [internal]
#
# Get-AzWatcher             >  Get Watchlist/WatchlistItem
# New-AzWatcher             >  Create Watchlist/WatchlistItem
# Set-AzWatcher             >  Set Watchlist/WatchlistItem
# Remove-AzWatcher          >  Remove Watchlist/WatchlistItem
#
# Get-AzWatcherIncident     >  Get Sentinel Incidents/Alerts
#
########################################################################################

########################################################################################




################################################### Cache
# AzHunter Sessions
#if(-Not$AzHunter.TenantID){$AzHunter = [System.Collections.ArrayList]@()}





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
    [Parameter(ValueFromPipeline)][PSObject]$Obj
    )
    Begin{}
    Process{
        $PropList = foreach($Prop in ($Obj | Get-Member | Where-Object MemberType -eq NoteProperty).name){if($Obj.$Prop -OR $Obj.$Prop -eq 0){$Prop}}
        $Obj | select-Object $PropList
        }
    End{}
    }
#End


function Read-SecureString{
    Param(
        [Parameter(Mandatory,ValuefromPipeline)][Security.SecureString[]]$SecureString
        )
    Begin{}
    Process{Foreach($SecStr in @($SecureString)){
        [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecStr)).tostring()
        }}
    End{}
    }
#End


<#
.Synopsis
   Convert-CustomObjectToHashtable [Internal/DIY]
.DESCRIPTION
   Custom Object To Hashtable
.EXAMPLE
   $CustomObject|ToHashTable
#>
Function Convert-CustomObjectToHashTable{
    [Alias('ToHashtable')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline=1)][PSCustomObject[]]$Object
        )
    Begin{}
    Process{foreach($Obj in $Object){
        $HashTable=@{}
        ($Obj|GM|? membertype -eq NoteProperty).name|%{
            $HashTable[$_]=$Obj.$_
            }
        $HashTable
        }}
    End{}
    }
#End


function WarnAzError{
    $Errr = ($Error[0].ErrorDetails.message|convertfrom-Json).error
    Write-Warning "$($Errr.Code) - $($Errr.Message)"
    }

#################################################################### AzToken

<#
.Synopsis
   Get-AzHunterToken
.DESCRIPTION
   Get AzHunter Token
.EXAMPLE
   Get-AzHunterToken $TenantID $AppID $AppSecret -resource 'https://api.loganalytics.io'
.EXAMPLE
   Get-AzHunterToken $TenantID $AppID $AppSecret -resource 'https://api.securitycenter.microsoft.com'
.EXAMPLE
   Get-AzHunterToken $TenantID $AppID $AppSecret -resource 'https://management.azure.com'
#>
Function Get-AzHunterToken{
    Param(
        # Tenant ID
        [Parameter(Mandatory=1,Position=0)][String]$Tenant,
        # App ID
        [Parameter(Mandatory=1,Position=1)][Security.SecureString]$App,
        # App Secret
        [Parameter(Mandatory=1,Position=2)][Security.SecureString]$Secret,
        # Resource
        [Parameter(Mandatory=1,Position=4)][String]$Resource
        )
    # Prep
    $Uri = "https://login.microsoftonline.com/$Tenant/oauth2/token"
    $Body = [Ordered] @{
        resource      = $Resource
        client_id     = $app | Read-SecureString
        client_secret = $Secret | Read-SecureString
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
.EXAMPLE
   Update-AzHunterToken -xToken -id 2,3
#>
function Update-AzHunterToken{
    Param(
        [Parameter()][String[]]$id=$(($AzHunter|? x).id),
        [Parameter()][Switch]$xToken,
        [Parameter()][Switch]$IfNeeded
        )
    $TokType = if($XToken){'xToken'}else{'Token'}
    foreach($Sess in $ID){
        # Token Expiry
        $Tok = ($AzHunter| where id -eq $Sess).$TokType
        if(-Not$Tok){Write-Warning "No $TokType found in Session $Sess";RETURN}
        $Exp = if($IfNeeded){[datetime]::new(1970,1,1).AddSeconds($Tok.expires_on)}else{([datetime]::new(1970,1,1))}
        $Now = [DateTime]::UtcNow
        # If new token required
        if($Now -gt $exp){
            Write-Verbose "Refreshing session $TokType for session $Sess"
            # Session info
            $SessData = ($AzHunter| where id -eq $Sess)
            $TenantID = $SessData.TenanTID
            $AppID    = $SessData.AppID
            $AppSec   = $SessData.AppSec
            # New Token
            $NewToken = if($xToken){Get-AzHunterToken $TenantID $AppID $AppSec -resource 'https://management.azure.com'}
                else{
                    if($SessData.Target -eq 'MDE'){
                        # MDE Token
                        Get-AzHunterToken $TenantID $AppID $AppSec -Resource 'https://api.securitycenter.microsoft.com'
                        }
                    elseif($SessData.Target -eq 'Sentinel'){
                        # Sentinel Token
                        Get-AzHunterToken $TenantID $AppID $AppSec -Resource 'https://api.loganalytics.io'
                        }}
            # Replace token
            ($AzHunter| Where id -eq $Sess).$TokType = $NewToken
            }
        }}
#####End


############################################################## AzHunter Session

<#
.Synopsis
   New-AzHunterSession
.DESCRIPTION
   New AzHunter Session
.EXAMPLE
   New-AzHunterSession $TenantID $AppID $AppSecret
   Create new MDE Session
.EXAMPLE
   New-AzHunterSession $TenantID $AppID $AppSecret $Workspace [-Tag 'Prod']
   Create new Sentinel session [with specific tag]
   (Advanced Query)
.EXAMPLE
   New-AzHunterSession $TenantID $AppID $AppSecret $Workspace $SharedKey
   Create new Sentinel session including Sharedkey for AzWriter
   (Advanced Query + HTTP Collector)
.EXAMPLE
   New-AzHunterSession $TenantID $AppID $Appsecret $WorkSpaceID $SharedKey $SubscriptionID $WorkspaceName $ResourceGroup
   Create new Sentinel session including xtra Info for AzWatcher
   (Advanced Query + HTTP Collector + Management API)
#>
function New-AzHunterSession{
    Param(
        [Parameter(Position=0)][String]$TenantID,
        [Parameter(Position=1)][Security.SecureString]$AppID,
        [Parameter(Position=2)][Security.SecureString]$AppSecret,
        [Parameter(Position=3)][String]$Workspace,
        [Parameter(Position=4)][Security.SecureString]$SharedKey,
        [Parameter(Position=5)][String]$SubScriptionID,
        [Parameter(Position=6)][String]$WorkspaceName,
        [Parameter(Position=7)][String]$RessourceGroup,
        [Parameter()][String]$Tag
        )
    $ASCII = '    Invoke-AzHunter
=======================
==   P    , ,    S   ==
==  _*_  {0,0}  _*_  ==
==  |A|  /)_)   |N|  ==
==  |Z|   /"\   |I|  ==
==  |U|  / @ \  |N|  ==
==  |R| /_____\ |J|  ==
==  |E|/_______\|A|  ==
==  |*|__K.Q.L__|*|  ==
=======================
:. SadProcessor@2022 :.
=======================
         Alpha
';  if(-Not$AzHunter.TenantID){$Script:AzHunter = [System.Collections.ArrayList]@()
        Write-Host $ASCII -ForegroundColor Blue
        }
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
    # xToken (Mgmt API)
    $xToken = if($Token.access_token -AND $Target -eq 'Sentinel'){
        Get-AzHunterToken $TenantID $AppID $AppSecret -resource 'https://management.azure.com'
        }
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
            AppSec    = $AppSecret
            Workspace = $WorkSpace
            SharedKey = if($SharedKey -ne $Null){$SharedKey}else{}
            Uri       = $Uri
            Token     = $Token
            xToken         = $xToken
            WorkspaceName  = $WorkspaceName
            SubscriptionID = $SubscriptionID
            ResourceGroup  = $ResourceGroup
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
        $AzHunter.remove(($AzHunter|Where id -eq $Session))
        }}
#####End



####################################################################### AzHunter KQL

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
        [Parameter()][Switch]$ShowEmpty,
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
                # Strip Comments (full line)
                $KQL = ($KQL.split("`n")-notmatch"^\s*\/\/"-join"`n").trim()
                # Strip Comments Inline
                $KQL = ($KQL-replace"\/\/(.*)\n","`n").trim()
                # If take
                if($Take){$KQL = $KQL.trimEnd() + "`r`n| take $Take"}
                # if project
                if($Project){$KQL = $KQL.trimEnd() + "`r`n| project $($Project-join',')"}
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
                $Reply = Try{Invoke-RestMethod -Method $Meth -Uri $Uri -Headers $Head -Body $Body}catch{WarnAzError;RETURN}
                ## Output
                if($Raw){Return $Reply}
                else{Switch($Target.target){
                        MDE{$Obj = $Reply.Results
                            if($Tag){$Obj|Add-Member -MemberType NoteProperty -Name 'Tag' -Value $Target.tag}
                            if(-Not$ShowEmpty){$Obj=$Obj|NotEmpty}
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
                                if(-Not$ShowEmpty){$Obj=$Obj|NotEmpty}
                                if($Report){$Null = $Res.add($Obj)}else{$Obj}
                                }
                            if($Report){[PSCustomObject]@{Tag=$Target.Tag;Query=$KQL;Result=$Res}}
                            }}}}}}
    End{}#######################
    }
#End


############################################################## AzWriter

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
        [Parameter(Mandatory=0)][Alias('Table')][String]$LogType='AzHunter',
        # Event ID
        [Parameter(Mandatory=0)][String]$EventID='1337',
        # Message
        [Parameter(Mandatory=0)][Alias('Description')][String]$Message='AzWriter - Custom Event',
        # Other Props
        [Parameter(Mandatory=0)][hashtable]$Property=@{},
        # Computer
        [Parameter(Mandatory=0)][Alias('Type')][String]$Computer=$env:COMPUTERNAME,
        # TimeStamp <--------------------------------------------------------------------- Not picked up / wrong format ??
        [Parameter(Mandatory=0)][DateTime]$TimeStamp=[DateTime]::UTCNow,
        # _Ressourceid
        [Parameter(Mandatory=0)][String]$AzResourceId,
        # DEBUG
        #[Parameter(Mandatory=0)][Switch]$DBG,
        # AzHunter SessionID
        [Parameter(Mandatory=0)][Alias('Session')][int[]]$ID = $(($AzHunter|? x).id)
        )
    Foreach($Sess in $ID){
        # Session Vars
        $AzID  = ($AzHunter | Where id -eq $Sess).Workspace
        $AzKey = $($AzHunter|? id -eq $Sess).SharedKey | Read-SecureString
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
        if($DBG){RETURN [PSCustomObject]@{Head=$Head;Body=$Body;Uri=$Uri}}
        ## CALL
        Try{$Null = Invoke-RestMethod -Method $Meth -Uri $uri -ContentType $content -Headers $head -Body $body}Catch{WarnAzError}
        }}
#####End



############################################################## AzWatcher

<#
.SYNOPSIS
Invoke Azure WatchList
.DESCRIPTION
Manipulate Azure WatchLists [Internal]
Use Get/Set/New/Delete dash AzWatcherList or Get-AzWatcherAlert
.NOTES
# API info
# https://docs.microsoft.com/en-us/rest/api/securityinsights/stable/watchlists
# https://docs.microsoft.com/en-us/rest/api/securityinsights/stable/watchlist-items
.EXAMPLE
AzWatcher GetList
#>
Function Invoke-AzWatcher{
    [Alias('AzWatcherAPI')]
    Param(
        [ValidateSet('GetList','PutList','DeleteList','GetItem','PutItem','DeleteItem','GetIncident','GetAlert')]
        [Parameter(Mandatory=0,Position=0)][String]$Action='GetList',
        [Parameter(Mandatory=0,Position=1)][String]$Name,
        [Parameter(Mandatory=0,Position=2)][String]$ItemID,
        [Parameter(Mandatory=0,Position=3)][HashTable]$Body,
        [Parameter(Mandatory=0)][String]$APIversion='2021-10-01',
        [Parameter(Mandatory=0)][Switch]$DBG,
        [Parameter(Mandatory=0)][Alias('Id')][int[]]$Session=($AzHunter|? x).id
        )
    Foreach($Sess in $Session){
        # Checks
        $SessData = $AzHunter | Where id -eq $Sess
        if(-Not($SessData.SubscriptionID -AND $SessData.WorkspaceName -AND $SessData.ResourceGroup)){Write-Warning "Cannot use this cmdlet with session $Sess";Break}
        else{Update-AzHunterToken -xToken -id $Sess -IfNeeded}
        # Head
        $Head = @{'Content-type'='application/json'; Authorization="Bearer $($SessData.xToken.access_token)"}
        # Body
        if($Body){$Props=$Body|Convertto-Json -Compress}
        # URI
        $URI = "https://management.azure.com/subscriptions/$($SessData.SubscriptionID)/resourceGroups/$($SessData.ResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($SessData.WorkspaceName)/providers/Microsoft.SecurityInsights/watchlists"
        if($Action -eq 'GetIncident' -OR $Action -eq 'GetAlert'){
            $URI = "https://management.azure.com/subscriptions/$($SessData.SubscriptionID)/resourceGroups/$($SessData.ResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($SessData.WorkspaceName)/providers/Microsoft.SecurityInsights/incidents"
            }
        if($Name){$URI+="/$Name"}
        $URI+= Switch($Action){
            GetItem   {'/watchlistItems'}
            PutItem   {'/watchlistItems'}
            DeleteItem{'/watchlistItems'}
            GetAlert  {'/alerts'}
            Default   {''}
            }
        if($ItemID -AND $ItemID -ne '*'){$URI+="/$ItemId"}
        # Method
        $Mthd = if($Action -eq 'GetAlert'){'POST'}else{($Action-replace'Item'-replace'List'-replace'Incident').ToUpper()}
        # API
        $URI += "?api-version=$APIversion"
        ## Debug
        if($DBG -eq $true){Return [PSCustomObject]@{Method=$Mthd;Uri=$Uri;Head=$Head;Body=$Props}}
        # Call
        Try{Invoke-RestMethod -Method $Mthd -Uri $URI -Headers $Head -Body $Props}Catch{WarnAzError}
        }
    }
#End


<#
.Synopsis
   Get AzWatcher
.DESCRIPTION
   Get AzWatcher List/Item
.EXAMPLE
   Get-AzWatcher $ListName
   Get list object
.EXAMPLE
   Get-AzWatcher $ListName -ItemID *
   Get all list items
.EXAMPLE
   Get-AzWatcher $ListName -ItemID $ItemID
   Get all list items
#>
function Get-AzWatcher{
    [Alias('AzWatcher')]
    Param(
        [Parameter(Mandatory=0)][Alias('List')][String]$Name,
        [Parameter(Mandatory=0)][String]$ItemID,
        [Parameter(Mandatory=0)][Switch]$ShowDeleted,
        [Parameter(Mandatory=0)][Switch]$NoUnpack,
        [Parameter(Mandatory=0)][Switch]$Raw,
        [Parameter(Mandatory=0)][Switch]$DBG,
        [Parameter(Mandatory=0)][Alias('Id')][int[]]$Session=($AzHunter|? x).id
        )
    # Result
    $Res = if($ItemID){AzWatcherAPI GetItem $Name $ItemID -Session $Session -DBG:$DBG}
        else{AzWatcherAPI GetList $Name -Session $Session -DBG:$DBG}
    # Output
    if($Raw){Return $Res}
    if((-Not$Name) -OR ($ItemID -eq '*')){$Res = $Res.Value}
    if(-Not$ShowDeleted){$Res = $Res|?{$_.Properties.isdeleted -eq $False}}
    if($NoUnpack){$Res}else{if($ItemID){foreach($Itm in $Res.properties){$IID = $Itm.watchlistItemID;$Itm.itemskeyValue|Select-Object *,@{n='AzGUID';e={$IID}}-ea 0}}else{$Res.Properties}}
    }
#End


<#
.Synopsis
   Set AzWatcher
.DESCRIPTION
   Set AzWatcher List/Item
.EXAMPLE
   Set-AzWatcher $NewListName
   Create new list
.EXAMPLE
   Get-Process p* | select ProcessName,id,CPU,Handle | Set-AzWatcher -list ProcessList
   Create new list and bulk import items
.EXAMPLE
   Get-Process m* | select ProcessName,id,CPU,Handle | Set-AzWatcher -list ProcessList -ItemID *
   Append multiple items to an existing list
#>
function Set-AzWatcher{
    [CmdletBinding(DefaultParameterSetName='List')]
    Param(
        [Parameter(Mandatory=1,Position=0)][Alias('List')][String]$Name,
        [Parameter(Mandatory=0,Position=1,ParameterSetName='Item')][String]$ItemID,
        [Parameter(Mandatory=0,Position=0)][HashTable]$Properties,
        [Parameter(Mandatory=0,Position=0,ValueFromPipeline)][PSCustomObject]$KeyValue,
        [Parameter(Mandatory=0)][Switch]$DBG,
        [Parameter(Mandatory=0)][Alias('Id')][int[]]$Session=($AzHunter|? x).id
        )
    ## PREP
    Begin{
        $ListExists = Get-AzWatcher $Name -ea 0 -verbose:$False -wa 0
        if($ItemID -AND -Not$ListExists){Write-Warning "Must create list first for bulk import [Remove -ItemID <val> from Command]";Break}
        if($PSCmdlet.ParameterSetName -eq 'List'){[Collections.ArrayList]$Collect=@()}
        $Props = if($Properties.count){@{properties=$Properties}}else{@{properties=@{}}}
        }
    ## EACH ITEM
    Process{foreach($KV in $KeyValue){
        ## LIST
        if($PSCmdlet.ParameterSetName -eq 'List'){
            # Collect Pipline for End
            $null = $Collect.add($KV)
            }
        ## ITEM
        if($PSCmdlet.ParameterSetName -eq 'Item'){
            # if New item
            if($ItemID -eq "*"){
                $GUID = [GUID]::NewGUID();Write-Verbose "Create Item $GUID"
                }
            else{$GUID = $ItemID;Write-Verbose "Update Item $GUID";}
            # add KV to props
            $Props = if($Properties.count){@{properties=$Properties}}else{@{properties=@{}}}
            $Props.Properties.add('itemsKeyValue',$KV)
            # PUT Item
            AzWatcherAPI PutItem $Name $GUID -Body $Props -DBG:$DBG -Session $Session
            }}}
    ## BULK
    End{## LIST
        if($PSCmdlet.ParameterSetName -eq 'List'){
            $RawContent = ($Collect | ConvertTo-Csv -NoTypeInformation)-join("`r`n") <#-ea 0#>
            # If list exists
            if($ListExists){
                $Props = $ListExists | ToHashtable
                # Check if props > Return if empty / -Bulk
                if($Collect.Count){Write-Warning "No bulk import to existing list [Add -ItemID * for import]";RETURN}
                if(-Not$Props.Properties.Count){Write-Warning "Must provide -Properties <hashtable> to update";RETURN}
                Write-Verbose "Update List $Name"
                $Props.properties.add('rawContent',$("$($ListExists.properties.Description)"+"`r`n"+"$RawContent"))
                }
            # If List is new
            else{
                Write-Verbose "Create List $Name"
                # Check minimal props > default if missing > add rawcontent
                if(-Not$Props.properties.displayName){$Props.properties.add('displayName',$Name)}
                if(-Not$Props.properties.source){$Props.properties.add('source','Script')}
                if(-Not$Props.properties.provider){$Props.properties.add('provider','PowerShell')}
                $Desc = if(-Not$Props.properties.description){"This Watchlist was generated by $($Props.properties.provider)"}else{$Props.properties.description}
                if(-Not$Props.properties.description){$Props.properties.add('description',$Desc)}
                if(-Not$Props.properties.numberOfLinesToSkip){$Props.properties.add('numberOfLinesToSkip',[int]$Desc.split("`n").count)}
                if(-Not$Props.properties.itemsSearchKey){$Props.properties.add('itemsSearchKey',$(($Collect|Get-Member|Where membertype -eq noteproperty).name[0]))}
                if(-Not$Props.properties.content){$Props.properties.add('contentType','text/csv')}
                $Props.properties.add('rawContent',$("$Desc"+"`r`n"+"$RawContent"))
                }
            # PUT List
            AzWatcherAPI PutList $Name -Body $Props -DBG:$DBG -Session $Session
            }
        ## ITEM
        else{<#NoOp#>}
        }}
#####End


<#
.Synopsis
   Remove AzWatcher
.DESCRIPTION
   Remove AzWatcher List/Item
.EXAMPLE
   Remove-AzWatcher $ListName -DeleteList
   Delete list (entire object)
.EXAMPLE
   Remove-AzWatcher $ListName -ItemID $GUID
   Delete single list Items (but not list itself)
.EXAMPLE
   Get-AzWatcher $ListName -ItemID * | Remove-AzWatcher $ListName
   Delete all list Items (but not list itself)
#>
function Remove-AzWatcher{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=1)][Alias('List')][String]$Name,
        [Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][Alias('AzGUID')][String]$ItemID,
        [Parameter(Mandatory=0)][Alias('NoWarning')][Switch]$DeleteList,
        [Parameter(Mandatory=0)][Switch]$DBG,
        [Parameter(Mandatory=0)][Alias('Id')][int[]]$Session=($AzHunter|? x).id
        )
    Begin{}
    Process{
        # Confirm Delete List
        if(-Not$ItemID -AND -not$DeleteList.IsPresent){Write-Warning "Add -DeleteList to Delete full list";RETURN}
        # Delete Item
        $Null = if($ItemID){Switch($ItemID){
            '*'    {Get-AzWatcher $Name -itemID * -Session $Session | Remove-AzWatcher $Name -Session $Session -DBG:$DBG}
            Default{AzWatcherAPI DeleteItem -Name $Name -itemID $ItemID -Session $Session -DBG:$DBG}
                }}
        # Delete List
        else{AzWatcherAPI DeleteList -Name $Name -Session $Session -DBG:$DBG}
        }
    End{}
    }
#End




function Get-AzWatcherIncident{
    [Alias('AzWatcherIncident')]
    Param(
        [Parameter(Mandatory=0)][Alias('List')][String]$Name,
        [Parameter(Mandatory=0)][Switch]$Alert,
        [Parameter(Mandatory=0)][Alias('ShowResolved')][Switch]$ShowClosed,
        [Parameter(Mandatory=0)][Switch]$NoUnpack,
        [Parameter(Mandatory=0)][Switch]$Raw,
        [Parameter(Mandatory=0)][Switch]$DBG,
        [Parameter(Mandatory=0)][Alias('Id')][int[]]$Session=($AzHunter|? x).id
        )
    # Result
    $Res=if($Alert){
            if(-Not$Name){
                $IncidentList = (AzWatcherAPI GetIncident -Session $Session).Value.Name
                $IncidentList | % {AzWatcherAPI GetAlert $_ -Session $Session -DBG:$DBG}
                }
            else{AzWatcherAPI GetAlert $Name -Session $Session -DBG:$DBG}
            }
         else{AzWatcherAPI GetIncident $Name -Session $Session -DBG:$DBG}
    # Output
    if($Raw){Return $Res}
    if((-Not$Name) -OR ($Alert)){$Res = $Res.Value}
    if(-Not$ShowClosed){$Res = $Res|?{$_.Properties.status -notmatch "Closed|Resolved"}}
    if($NoUnpack){$Res}else{$Res.Properties}
    }
#End

####################################################################################### EOF


