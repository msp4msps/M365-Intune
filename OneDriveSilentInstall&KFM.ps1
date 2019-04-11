<#
.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.
#>

#Add the following#
1. OneDriveADMX
2. Silent Account Config
3. Silent redirect Windows KFM
4. KFM Block opt out
5. Enable Files on Demand

#################################################
Install-Module -Name Microsoft.Graph.Intune

Connect-MSGraph -AdminConsent

####################################################

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $User
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | select -Unique

            }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "https://graph.microsoft.com"

$authority = "https://login.microsoftonline.com/$Tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}

####################################################

Function Add-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to add an device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy
.EXAMPLE
Add-DeviceConfigurationPolicy -JSON $JSON
Adds a device configuration policy in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"
Write-Verbose "Resource: $DCP_resource"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Add-DeviceConfigurationPolicyAssignment(){

<#
.SYNOPSIS
This function is used to add a device configuration policy assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy assignment
.EXAMPLE
Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
Adds a device configuration policy assignment in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicyAssignment
#>

[cmdletbinding()]

param
(
    $ConfigurationPolicyId,
    $TargetGroupId
)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/deviceConfigurations/$ConfigurationPolicyId/assign"
    
    try {

        if(!$ConfigurationPolicyId){

        write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        $ConfPolAssign = "$ConfigurationPolicyId" + "_" + "$TargetGroupId"

$JSON = @"
{
  "deviceConfigurationGroupAssignments": [
    {
      "@odata.type": "#microsoft.graph.deviceConfigurationGroupAssignment",
      "id": "$ConfPolAssign",
      "targetGroupId": "$TargetGroupId"
    }
  ]
}
"@

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Test-JSON(){

<#
.SYNOPSIS
This function is used to test if the JSON passed to a REST Post request is valid
.DESCRIPTION
The function tests if the JSON passed to the REST Post is valid
.EXAMPLE
Test-JSON -JSON $JSON
Test if the JSON is valid before calling the Graph REST interface
.NOTES
NAME: Test-AuthHeader
#>

param (

$JSON

)

    try {

    $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
    $validJson = $true

    }

    catch {

    $validJson = $false
    $_.Exception

    }

    if (!$validJson){
    
    Write-Host "Provided JSON isn't in valid JSON format" -f Red
    break

    }

}

####################################################

Function Get-AADGroup(){

<#
.SYNOPSIS
This function is used to get AAD Groups from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Groups registered with AAD
.EXAMPLE
Get-AADGroup
Returns all users registered with Azure AD
.NOTES
NAME: Get-AADGroup
#>

[cmdletbinding()]

param
(
    $GroupName,
    $id,
    [switch]$Members
)

# Defining Variables
$graphApiVersion = "v1.0"
$Group_resource = "groups"
    
    try {

        if($id){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=id eq '$id'"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }
        
        elseif($GroupName -eq "" -or $GroupName -eq $null){
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
        }

        else {
            
            if(!$Members){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
            }
            
            elseif($Members){
            
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
            $Group = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
                if($Group){

                $GID = $Group.id

                $Group.displayName
                write-host

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)/$GID/Members"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                }

            }
        
        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

########################################################################

# Setting Tenant ID #

$TenantID = Read-Host -Prompt "Enter the Azure TenantID"



####################################################



$OneDrive = @"
{
    "@odata.type":  "#microsoft.graph.windows10CustomConfiguration",
    "id":  "f2d6ce45-3bc7-4584-b391-120aa53eabea",
    "lastModifiedDateTime":  "2018-09-09T13:47:31.4040135Z",
    "createdDateTime":  "2018-07-07T14:21:22.3292533Z",
    "description":  "",
    "displayName":  "OneDrive Configuration",
    "version":  7,
    "omaSettings":  [
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "OneDrive.admx",
                            "description":  null,
                            "omaUri":  "./Vendor/MSFT/Policy/ConfigOperations/ADMXInstall/OneDriveNGSC/Policy/OneDriveAdmx",
                            "value":  "\u003cpolicyDefinitions xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" revision=\"1.0\" schemaVersion=\"1.0\" xmlns=\"http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions\"\u003e\n  \u003cpolicyNamespaces\u003e\n    \u003ctarget prefix=\"OneDriveNGSC\" namespace=\"Microsoft.Policies.OneDriveNGSC\" /\u003e\n    \u003cusing prefix=\"windows\" namespace=\"Microsoft.Policies.Windows\" /\u003e\n  \u003c/policyNamespaces\u003e\n  \u003cresources minRequiredRevision=\"1.0\" /\u003e\n  \u003ccategories\u003e\n    \u003ccategory name=\"OneDriveNGSC\" displayName=\"$(string.OneDriveNGSCSettingCategory)\"/\u003e\n  \u003c/categories\u003e\n  \u003cpolicies\u003e\n    \u003cpolicy name=\"DisablePersonalSync\" class=\"User\" displayName=\"$(string.DisablePersonalSync)\" explainText=\"$(string.DisablePersonalSync_help)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"DisablePersonalSync\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003cenabledValue\u003e\n        \u003cdecimal value=\"1\" /\u003e\n      \u003c/enabledValue\u003e\n      \u003cdisabledValue\u003e\n        \u003cdecimal value=\"0\" /\u003e\n      \u003c/disabledValue\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"EnableEnterpriseUpdate\" class=\"User\" displayName=\"$(string.EnableEnterpriseUpdate)\" explainText=\"$(string.EnableEnterpriseUpdate_help)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"EnableEnterpriseUpdate\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003cenabledValue\u003e\n        \u003cdecimal value=\"1\" /\u003e\n      \u003c/enabledValue\u003e\n      \u003cdisabledValue\u003e\n        \u003cdecimal value=\"0\" /\u003e\n      \u003c/disabledValue\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"DefaultRootDir\" class=\"User\" displayName=\"$(string.DefaultRootDir)\" explainText=\"$(string.DefaultRootDir_help)\" presentation=\"$(presentation.DefaultRootDir_Pres)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"DefaultRootDir\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003celements\u003e\n        \u003clist id=\"DefaultRootDirList\" key=\"Software\\Policies\\Microsoft\\OneDrive\\DefaultRootDir\" additive=\"true\" expandable=\"true\" explicitValue=\"true\" /\u003e\n      \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"DisableCustomRoot\" class=\"User\" displayName=\"$(string.DisableCustomRoot)\" explainText=\"$(string.DisableCustomRoot_help)\" presentation=\"$(presentation.DisableCustomRoot_Pres)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"DisableCustomRoot\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n        \u003celements\u003e\n            \u003clist id=\"DisableCustomRootList\" key=\"Software\\Policies\\Microsoft\\OneDrive\\DisableCustomRoot\" additive=\"true\" explicitValue=\"true\"/\u003e\n        \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"EnableAllOcsiClients\" class=\"User\" displayName=\"$(string.EnableAllOcsiClients)\" explainText=\"$(string.EnableAllOcsiClients_help)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"EnableAllOcsiClients\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003cenabledValue\u003e\n        \u003cdecimal value=\"1\" /\u003e\n      \u003c/enabledValue\u003e\n      \u003cdisabledValue\u003e\n        \u003cdecimal value=\"0\" /\u003e\n      \u003c/disabledValue\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"EnableHoldTheFile\" class=\"User\" displayName=\"$(string.EnableHoldTheFile)\" explainText=\"$(string.EnableHoldTheFile_help)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"EnableHoldTheFile\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003cenabledValue\u003e\n        \u003cdecimal value=\"1\" /\u003e\n      \u003c/enabledValue\u003e\n      \u003cdisabledValue\u003e\n        \u003cdecimal value=\"0\" /\u003e\n      \u003c/disabledValue\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"AutomaticUploadBandwidthPercentage\" class=\"Machine\" displayName=\"$(string.AutomaticUploadBandwidthPercentage)\" explainText=\"$(string.AutomaticUploadBandwidthPercentage_help)\"  presentation=\"$(presentation.AutomaticUploadBandwidthPercentage_Pres)\"  key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003celements\u003e\n        \u003cdecimal id=\"BandwidthSpinBox\" valueName=\"AutomaticUploadBandwidthPercentage\" minValue=\"10\" maxValue=\"99\"  /\u003e\n      \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"UploadBandwidthLimit\" class=\"User\" displayName=\"$(string.UploadBandwidthLimit)\" explainText=\"$(string.UploadBandwidthLimit_help)\"  presentation=\"$(presentation.UploadBandwidthLimit_Pres)\"  key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003celements\u003e\n        \u003cdecimal id=\"UploadRateValue\" valueName=\"UploadBandwidthLimit\" minValue=\"1\" maxValue=\"100000\"  /\u003e\n      \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"DownloadBandwidthLimit\" class=\"User\" displayName=\"$(string.DownloadBandwidthLimit)\" explainText=\"$(string.DownloadBandwidthLimit_help)\"  presentation=\"$(presentation.DownloadBandwidthLimit_Pres)\"  key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003celements\u003e\n        \u003cdecimal id=\"DownloadRateValue\" valueName=\"DownloadBandwidthLimit\" minValue=\"1\" maxValue=\"100000\"  /\u003e\n      \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"RemoteAccessGPOEnabled\" class=\"User\" displayName=\"$(string.RemoteAccessGPOEnabled)\" explainText=\"$(string.RemoteAccessGPOEnabled_help)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"GPOEnabled\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003cenabledValue\u003e\n        \u003cdecimal value=\"1\" /\u003e\n      \u003c/enabledValue\u003e\n      \u003cdisabledValue\u003e\n        \u003cdecimal value=\"0\" /\u003e\n      \u003c/disabledValue\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"PreventNetworkTrafficPreUserSignIn\" class=\"Machine\" displayName=\"$(string.PreventNetworkTrafficPreUserSignIn)\" explainText=\"$(string.PreventNetworkTrafficPreUserSignIn_help)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"PreventNetworkTrafficPreUserSignIn\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003cenabledValue\u003e\n        \u003cdecimal value=\"1\" /\u003e\n      \u003c/enabledValue\u003e\n      \u003cdisabledValue\u003e\n        \u003cdecimal value=\"0\" /\u003e\n      \u003c/disabledValue\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"SilentAccountConfig\" class=\"Machine\" displayName=\"$(string.SilentAccountConfig)\" explainText=\"$(string.SilentAccountConfig_help)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"SilentAccountConfig\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003cenabledValue\u003e\n        \u003cdecimal value=\"1\" /\u003e\n      \u003c/enabledValue\u003e\n      \u003cdisabledValue\u003e\n        \u003cdecimal value=\"0\" /\u003e\n      \u003c/disabledValue\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"DiskSpaceCheckThresholdMB\" class=\"Machine\" displayName=\"$(string.DiskSpaceCheckThresholdMB)\" explainText=\"$(string.DiskSpaceCheckThresholdMB_help)\"  presentation=\"$(presentation.DiskSpaceCheckThresholdMB_Pres)\"  key=\"Software\\Policies\\Microsoft\\OneDrive\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003celements\u003e\n        \u003clist id=\"DiskSpaceCheckThresholdMBList\" key=\"Software\\Policies\\Microsoft\\OneDrive\\DiskSpaceCheckThresholdMB\" additive=\"true\" explicitValue=\"true\"/\u003e\n      \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"FilesOnDemandEnabled\" class=\"Machine\" displayName=\"$(string.FilesOnDemandEnabled)\" explainText=\"$(string.FilesOnDemandEnabled_help)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"FilesOnDemandEnabled\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows_10_0_RS3\" /\u003e\n      \u003cenabledValue\u003e\n        \u003cdecimal value=\"1\" /\u003e\n      \u003c/enabledValue\u003e\n      \u003cdisabledValue\u003e\n        \u003cdecimal value=\"0\" /\u003e\n      \u003c/disabledValue\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"DehydrateSyncedTeamSites\" class=\"Machine\" displayName=\"$(string.DehydrateSyncedTeamSites)\" explainText=\"$(string.DehydrateSyncedTeamSites_help)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"DehydrateSyncedTeamSites\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows_10_0_RS3\" /\u003e\n      \u003cenabledValue\u003e\n        \u003cdecimal value=\"1\" /\u003e\n      \u003c/enabledValue\u003e\n      \u003cdisabledValue\u003e\n        \u003cdecimal value=\"0\" /\u003e\n      \u003c/disabledValue\u003e\n    \u003c/policy\u003e    \n    \u003cpolicy name=\"AllowTenantList\" class=\"Machine\" displayName=\"$(string.AllowTenantList)\" explainText=\"$(string.AllowTenantList_help)\" presentation=\"$(presentation.AllowTenantList_Pres)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n        \u003celements\u003e\n            \u003clist id=\"AllowTenantListBox\" key=\"Software\\Policies\\Microsoft\\OneDrive\\AllowTenantList\" additive=\"true\"/\u003e\n        \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"BlockTenantList\" class=\"Machine\" displayName=\"$(string.BlockTenantList)\" explainText=\"$(string.BlockTenantList_help)\" presentation=\"$(presentation.BlockTenantList_Pres)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n        \u003celements\u003e\n            \u003clist id=\"BlockTenantListBox\" key=\"Software\\Policies\\Microsoft\\OneDrive\\BlockTenantList\" additive=\"true\"/\u003e\n        \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"SharePointOnPremFrontDoorUrl\" class=\"Machine\" displayName=\"$(string.SharePointOnPremFrontDoorUrl)\" explainText=\"$(string.SharePointOnPremFrontDoorUrl_help)\" presentation=\"$(presentation.SharePointOnPremFrontDoorUrl_Pres)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003celements\u003e\n        \u003ctext id=\"SharePointOnPremFrontDoorUrlBox\" maxLength=\"2000\" required=\"true\" valueName=\"SharePointOnPremFrontDoorUrl\"/\u003e\n      \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"SharePointOnPremPrioritization\" class=\"Machine\" displayName=\"$(string.SharePointOnPremPrioritization)\" explainText=\"$(string.SharePointOnPremPrioritization_help)\" presentation=\"$(presentation.SharePointOnPremPrioritization_Pres)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003celements\u003e\n        \u003cenum id=\"SharePointOnPremPrioritization_Dropdown\" valueName=\"SharePointOnPremPrioritization\"\u003e\n          \u003citem displayName=\"$(string.PrioritizeSPO)\"\u003e\n            \u003cvalue\u003e\n              \u003cdecimal value=\"0\" /\u003e\n            \u003c/value\u003e\n          \u003c/item\u003e\n          \u003citem displayName=\"$(string.PrioritizeSharePointOnPrem)\"\u003e\n            \u003cvalue\u003e\n              \u003cdecimal value=\"1\" /\u003e\n            \u003c/value\u003e\n          \u003c/item\u003e\n        \u003c/enum\u003e\n      \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"DisableFRETutorial\" class=\"User\" displayName=\"$(string.DisableFRETutorial)\" explainText=\"$(string.DisableFRETutorial_help)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"DisableTutorial\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003cenabledValue\u003e\n        \u003cdecimal value=\"1\" /\u003e\n      \u003c/enabledValue\u003e\n      \u003cdisabledValue\u003e\n        \u003cdecimal value=\"0\" /\u003e\n      \u003c/disabledValue\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"BlockKnownFolderMove\" class=\"Machine\" displayName=\"$(string.BlockKnownFolderMove)\" explainText=\"$(string.BlockKnownFolderMove_help)\" presentation=\"$(presentation.BlockKnownFolderMove_Pres)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003celements\u003e\n        \u003cenum id=\"BlockKnownFolderMove_Dropdown\" valueName=\"KFMBlockOptIn\"\u003e\n          \u003citem displayName=\"$(string.KnownFolderMoveNoOptIn)\"\u003e\n            \u003cvalue\u003e\n              \u003cdecimal value=\"1\" /\u003e\n            \u003c/value\u003e\n          \u003c/item\u003e\n          \u003citem displayName=\"$(string.KnownFolderMoveUndoAndNoOptIn)\"\u003e\n            \u003cvalue\u003e\n              \u003cdecimal value=\"2\" /\u003e\n            \u003c/value\u003e\n          \u003c/item\u003e\n        \u003c/enum\u003e\n      \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"KFMOptInWithWizard\" class=\"Machine\" displayName=\"$(string.KFMOptInWithWizard)\" explainText=\"$(string.KFMOptInWithWizard_help)\" presentation=\"$(presentation.KFMOptInWithWizard_Pres)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003celements\u003e\n        \u003ctext id=\"KFMOptInWithWizard_TextBox\" maxLength=\"2000\" required=\"true\" valueName=\"KFMOptInWithWizard\"/\u003e\n      \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"KFMOptInNoWizard\" class=\"Machine\" displayName=\"$(string.KFMOptInNoWizard)\" explainText=\"$(string.KFMOptInNoWizard_help)\" presentation=\"$(presentation.KFMOptInNoWizard_Pres)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n      \u003celements\u003e\n        \u003ctext id=\"KFMOptInNoWizard_TextBox\" maxLength=\"2000\" required=\"true\" valueName=\"KFMSilentOptIn\"/\u003e\n        \u003cenum id=\"KFMOptInNoWizard_Dropdown\" valueName=\"KFMSilentOptInWithNotification\"\u003e\n          \u003citem displayName=\"$(string.KFMOptInNoWizardNoToast)\"\u003e\n            \u003cvalue\u003e\n              \u003cdecimal value=\"0\" /\u003e\n            \u003c/value\u003e\n          \u003c/item\u003e\n          \u003citem displayName=\"$(string.KFMOptInNoWizardToast)\"\u003e\n            \u003cvalue\u003e\n              \u003cdecimal value=\"1\" /\u003e\n            \u003c/value\u003e\n          \u003c/item\u003e\n        \u003c/enum\u003e\n      \u003c/elements\u003e\n    \u003c/policy\u003e\n    \u003cpolicy name=\"KFMBlockOptOut\" class=\"Machine\" displayName=\"$(string.KFMBlockOptOut)\" explainText=\"$(string.KFMBlockOptOut_help)\" key=\"SOFTWARE\\Policies\\Microsoft\\OneDrive\" valueName=\"KFMBlockOptOut\"\u003e\n      \u003cparentCategory ref=\"OneDriveNGSC\" /\u003e\n      \u003csupportedOn ref=\"windows:SUPPORTED_Windows7\" /\u003e\n       \u003cenabledValue\u003e\n        \u003cdecimal value=\"1\" /\u003e\n      \u003c/enabledValue\u003e\n      \u003cdisabledValue\u003e\n        \u003cdecimal value=\"0\" /\u003e\n      \u003c/disabledValue\u003e\n    \u003c/policy\u003e\n\u003c!-- Insert multi-tenant settings here --\u003e\n\u003c!-- See http://go.microsoft.com/fwlink/p/?LinkId=797547 for configuration instructions --\u003e\n\n  \u003c/policies\u003e\n\u003c/policyDefinitions\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "SilentAccountConfig",
                            "description":  "Silently configure OneDrive using the primary Windows account",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/OneDriveNGSC~Policy~OneDriveNGSC/SilentAccountConfig",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "KFMOptInNoWizard",
                            "description":  "Silently redirect Windows known folders to OneDrive",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/OneDriveNGSC~Policy~OneDriveNGSC/KFMOptInNoWizard",
                            "value":  "\u003cenabled/\u003e\n\u003cdata id=\"KFMOptInNoWizard_TextBox\" value=\"$TenantID\"/\u003e\n\u003cdata id=\"KFMOptInNoWizard_Dropdown\" value=\"0\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "KFMBlockOptOut ",
                            "description":  "Prevent users from redirecting their Windows known folders to their PC ",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/OneDriveNGSC~Policy~OneDriveNGSC/KFMBlockOptOut",
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "FilesOnDemandEnabled",
                            "description":  "Enable OneDrive Files On-Demand",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/OneDriveNGSC~Policy~OneDriveNGSC/FilesOnDemandEnabled",
                            "value":  "\u003cenabled/\u003e"
                        }
                    ]
}

"@

####################################################


# Setting application AAD Group to assign Policy

$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where policies will be assigned"

$TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

####################################################

Write-Host "Adding OneDrive Configuration from JSON..." -ForegroundColor Yellow

$CreateResult_OneDrive = Add-DeviceConfigurationPolicy -JSON $OneDrive

Write-Host "Device Restriction Policy created as" $CreateResult_OneDrive.id
write-host
write-host "Assigning Device Restriction Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_ONeDrive = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_OneDrive.id -TargetGroupId $TargetGroupId

Write-Host "Assigned '$AADGroup' to $($CreateResult_OneDrive.displayName)/$($CreateResult_OneDrive.id)"
Write-Host
