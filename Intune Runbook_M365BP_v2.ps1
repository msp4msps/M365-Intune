<#
.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.
#>

<#
.SYNOPSIS
After you run this script, you will have

1.White labeled Terms and Conditions
2.A device compliance policy for: Windows, iOS/ipad, Android for Work, Android Device Owner, macOS
3.A Windows 10 Endpoint Protection Profile for Windows Devices for Silent Bitlocker Encryption
4.365 Business Suite to Windows 10 and MacOS
5.Office Suite for iOS and Android (Word, PowerPoint, Excel, Teams, OneDrive, Outlook)
6.Microsoft Authenticator pushed out as a required App for iOS and Android devices
7.App Protection Policies for Android and iOS without enrollment
8.Windows Information Protection policies with or without enrollment (2 policies)

#>

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
        Write-Host "AzureAD PowerShell module not found, Installing Module"
        $AadModule = Install-Module -Name "AzureAD"
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
NAME: Test-JSON
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

Function Get-itunesApplication(){

<#
.SYNOPSIS
This function is used to get an iOS application from the itunes store using the Apple REST API interface
.DESCRIPTION
The function connects to the Apple REST API Interface and returns applications from the itunes store
.EXAMPLE
Get-itunesApplication -SearchString "Microsoft Corporation"
Gets an iOS application from itunes store
.EXAMPLE
Get-itunesApplication -SearchString "Microsoft Corporation" -Limit 10
Gets an iOS application from itunes store with a limit of 10 results
.NOTES
NAME: Get-itunesApplication
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $SearchString,
    [int]$Limit
)

    try{

    Write-Verbose $SearchString

    # Testing if string contains a space and replacing it with a +
    $SearchString = $SearchString.replace(" ","+")

    Write-Verbose "SearchString variable converted if there is a space in the name $SearchString"

        if($Limit){

        $iTunesUrl = "https://itunes.apple.com/search?country=us&media=software&entity=software,iPadSoftware&term=$SearchString&limit=$limit"
    
        }

        else {

        $iTunesUrl = "https://itunes.apple.com/search?entity=software&term=$SearchString&attribute=softwareDeveloper"

        }

    write-verbose $iTunesUrl
    $apps = Invoke-RestMethod -Uri $iTunesUrl -Method Get

    # Putting sleep in so that no more than 20 API calls to itunes API
    sleep 3

    return $apps
    
    }
    
    catch {

    write-host $_.Exception.Message -f Red        
    write-host $_.Exception.ItemName -f Red
    write-verbose $_.Exception
    write-host
    break

    }

}

####################################################
Function Add-iOSApplication(){

<#
.SYNOPSIS
This function is used to add an iOS application using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an iOS application from the itunes store
.EXAMPLE
Add-iOSApplication -AuthHeader $AuthHeader
Adds an iOS application into Intune from itunes store
.NOTES
NAME: Add-iOSApplication
#>

[cmdletbinding()]

param
(
    $itunesApp
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps"
    
    try {
    
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        
    $app = $itunesApp

    Write-Verbose $app
            
    Write-Host "Publishing $($app.trackName)" -f Yellow

    # Step 1 - Downloading the icon for the application
    $iconUrl = $app.artworkUrl60

        if ($iconUrl -eq $null){

        Write-Host "60x60 icon not found, using 100x100 icon"
        $iconUrl = $app.artworkUrl100
        
        }
        
        if ($iconUrl -eq $null){
        
        Write-Host "60x60 icon not found, using 512x512 icon"
        $iconUrl = $app.artworkUrl512
        
        }

    $iconResponse = Invoke-WebRequest $iconUrl
    $base64icon = [System.Convert]::ToBase64String($iconResponse.Content)
    $iconType = $iconResponse.Headers["Content-Type"]

        if(($app.minimumOsVersion.Split(".")).Count -gt 2){

        $Split = $app.minimumOsVersion.Split(".")

        $MOV = $Split[0] + "." + $Split[1]

        $osVersion = [Convert]::ToDouble($MOV)

        }

        else {

        $osVersion = [Convert]::ToDouble($app.minimumOsVersion)

        }

    # Setting support Operating System Devices
    if($app.supportedDevices -match "iPadMini"){ $iPad = $true } else { $iPad = $false }
    if($app.supportedDevices -match "iPhone6"){ $iPhone = $true } else { $iPhone = $false }

    # Step 2 - Create the Hashtable Object of the application

    $description = $app.description -replace "[^\x00-\x7F]+",""

    $graphApp = @{
        "@odata.type"="#microsoft.graph.iosStoreApp";
        displayName=$app.trackName;
        publisher=$app.artistName;
        description=$description;
        largeIcon= @{
            type=$iconType;
            value=$base64icon;
        };
        isFeatured=$false;
        appStoreUrl=$app.trackViewUrl;
        applicableDeviceType=@{
            iPad=$iPad;
            iPhoneAndIPod=$iPhone;
        };
        minimumSupportedOperatingSystem=@{
            v8_0=$osVersion -lt 9.0;
            v9_0=$osVersion -eq 9.0;
            v10_0=$osVersion -gt 9.0;
        };
    };

    $JSON = ConvertTo-Json $graphApp

    # Step 3 - Publish the application to Graph
    Write-Host "Creating application via Graph"
    $createResult = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body (ConvertTo-Json $graphApp) -Headers $authToken
    Write-Host "Application created as $uri/$($createResult.id)"
    write-host

    return $createResult
    
    }
    
    catch {

    $ex = $_.Exception
    Write-Host "Request to $Uri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" -f Red

    $errorResponse = $ex.Response.GetResponseStream()
    
    $ex.Response.GetResponseStream()

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

Function Add-ApplicationAssignment(){

<#
.SYNOPSIS
This function is used to add an application assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a application assignment
.EXAMPLE
Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
Adds an application assignment in Intune
.NOTES
NAME: Add-ApplicationAssignment
#>

[cmdletbinding()]

param
(
    $ApplicationId,
    $TargetGroupId,
    $InstallIntent
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"
    
    try {

        if(!$ApplicationId){

        write-host "No Application Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        
        if(!$InstallIntent){

        write-host "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment" -f Red
        break

        }

$JSON = @"
{
    "mobileAppAssignments": [
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId"
        },
        "intent": "$InstallIntent"
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

###################################################################

Function Add-TermsAndConditions(){

<#
.SYNOPSIS
This function is used to add Terms and Conditions using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds Terms and Conditions Statement
.EXAMPLE
Add-TermsAndConditions -JSON $JSON
Adds Terms and Conditions into Intune
.NOTES
NAME: Add-TermsAndConditions
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/termsAndConditions"
    
    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }
    
    catch {

    Write-Host
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

Function Add-TermsAndConditions(){

<#
.SYNOPSIS
This function is used to add Terms and Conditions using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds Terms and Conditions Statement
.EXAMPLE
Add-TermsAndConditions -JSON $JSON
Adds Terms and Conditions into Intune
.NOTES
NAME: Add-TermsAndConditions
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/termsAndConditions"
    
    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }
    
    catch {

    Write-Host
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

Function Assign-TermsAndConditions(){

<#
.SYNOPSIS
This function is used to assign Terms and Conditions from Intune to a Group using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and assigns terms and conditions to a group
.EXAMPLE
Assign-TermsAndConditions -id $id -TargetGroupId
.NOTES
NAME: Assign-TermsAndConditions
#>   

[cmdletbinding()]

param
(
    $id,
    $TargetGroupId
)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/termsAndConditions/$id/groupAssignments"

    try {

        if(!$id){

        Write-Host "No Terms and Conditions ID was passed to the function, specify a valid terms and conditions ID" -ForegroundColor Red
        Write-Host
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        Write-Host
        break

        }

        else {

$JSON = @"
{
    "targetGroupId":"$TargetGroupId"
}
"@

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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

###########################################################################

Function Add-MDMApplication(){

<#
.SYNOPSIS
This function is used to add an MDM application using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an MDM application from the itunes store
.EXAMPLE
Add-MDMApplication -JSON $JSON1
Adds an application into Intune
.NOTES
NAME: Add-MDMApplication
#>

[cmdletbinding()]

param
(
    $JSON1
)

$graphApiVersion = "Beta"
$App_resource = "deviceAppManagement/mobileApps"

    try {

        if(!$JSON1){

        write-host "No JSON was passed to the function, provide a JSON variable" -f Red
        break

        }

        Test-JSON -JSON $JSON1

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON1 -Headers $authToken

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

Function Add-ApplicationAssignment(){

<#
.SYNOPSIS
This function is used to add an application assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a application assignment
.EXAMPLE
Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
Adds an application assignment in Intune
.NOTES
NAME: Add-ApplicationAssignment
#>

[cmdletbinding()]

param
(
    $ApplicationId,
    $TargetGroupId,
    $InstallIntent
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"
    
    try {

        if(!$ApplicationId){

        write-host "No Application Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        
        if(!$InstallIntent){

        write-host "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment" -f Red
        break

        }

$JSON1 = @"
{
    "mobileAppAssignments": [
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId"
        },
        "intent": "$InstallIntent"
    }
    ]
}
"@

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON1 -ContentType "application/json"

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

###################################################################################

Function Add-DeviceCompliancePolicy(){

<#
.SYNOPSIS
This function is used to add a device compliance policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device compliance policy
.EXAMPLE
Add-DeviceCompliancePolicy -JSON $JSON
Adds an Android device compliance policy in Intune
.NOTES
NAME: Add-DeviceCompliancePolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceCompliancePolicies"
    
    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }
    
    catch {

    Write-Host
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

Function Add-DeviceCompliancePolicyAssignment(){

<#
.SYNOPSIS
This function is used to add a device compliance policy assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device compliance policy assignment
.EXAMPLE
Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CompliancePolicyId -TargetGroupId $TargetGroupId
Adds a device compliance policy assignment in Intune
.NOTES
NAME: Add-DeviceCompliancePolicyAssignment
#>

[cmdletbinding()]

param
(
    $CompliancePolicyId,
    $TargetGroupId
)

$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceCompliancePolicies/$CompliancePolicyId/assign"
    
    try {

        if(!$CompliancePolicyId){

        write-host "No Compliance Policy Id specified, specify a valid Compliance Policy Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

$JSON = @"
    {
        "assignments": [
        {
            "target": {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": "$TargetGroupId"
            }
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

Function Add-AndroidApplication(){

<#
.SYNOPSIS
This function is used to add an Android application using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an Android application from the itunes store
.EXAMPLE
Add-AndroidApplication -JSON $JSON -IconURL pathtourl
Adds an Android application into Intune using an icon from a URL
.NOTES
NAME: Add-AndroidApplication
#>

[cmdletbinding()]

param
(
    $JSON3,
    $IconURL
)

$graphApiVersion = "Beta"
$App_resource = "deviceAppManagement/mobileApps"

    try {

        if(!$JSON3){

        write-host "No JSON was passed to the function, provide a JSON variable" -f Red
        break

        }


        if($IconURL){

        write-verbose "Icon specified: $IconURL"

            if(!(test-path "$IconURL")){

            write-host "Icon Path '$IconURL' doesn't exist..." -ForegroundColor Red
            Write-Host "Please specify a valid path..." -ForegroundColor Red
            Write-Host
            break

            }

        $iconResponse = Invoke-WebRequest "$iconUrl"
        $base64icon = [System.Convert]::ToBase64String($iconResponse.Content)
        $iconExt = ([System.IO.Path]::GetExtension("$iconURL")).replace(".","")
        $iconType = "image/$iconExt"

        Write-Verbose "Updating JSON to add Icon Data"

        $U_JSON3 = ConvertFrom-Json $JSON3

        $U_JSON3.largeIcon.type = "$iconType"
        $U_JSON3.largeIcon.value = "$base64icon"

        $JSON3 = ConvertTo-Json $U_JSON3

        Write-Verbose $JSON3

        Test-JSON -JSON $JSON3

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON3 -Headers $authToken

        }

        else {

        Test-JSON -JSON $JSON3

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON3 -Headers $authToken

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

#########################################################

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

#############################################################################

Function Add-ApplicationAssignment(){

<#
.SYNOPSIS
This function is used to add an application assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a application assignment
.EXAMPLE
Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
Adds an application assignment in Intune
.NOTES
NAME: Add-ApplicationAssignment
#>

[cmdletbinding()]

param
(
    $ApplicationId,
    $TargetGroupId,
    $InstallIntent
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"
    
    try {

        if(!$ApplicationId){

        write-host "No Application Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        
        if(!$InstallIntent){

        write-host "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment" -f Red
        break

        }

$JSON4 = @"
{
    "mobileAppAssignments": [
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId"
        },
        "intent": "$InstallIntent"
    }
    ]
}
"@

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON4 -ContentType "application/json"

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

##########################################################################################

Function Add-ManagedAppPolicy(){

<#
.SYNOPSIS
This function is used to add an Managed App policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a Managed App policy
.EXAMPLE
Add-ManagedAppPolicy -JSON $JSON
Adds a Managed App policy in Intune
.NOTES
NAME: Add-ManagedAppPolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/managedAppPolicies"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for a Managed App Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }

    catch {

    Write-Host
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

Function Assign-ManagedAppPolicy(){

<#
.SYNOPSIS
This function is used to assign an AAD group to a Managed App Policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and assigns a Managed App Policy with an AAD Group
.EXAMPLE
Assign-ManagedAppPolicy -Id $Id -TargetGroupId $TargetGroupId -OS Android
Assigns an AAD Group assignment to an Android App Protection Policy in Intune
.EXAMPLE
Assign-ManagedAppPolicy -Id $Id -TargetGroupId $TargetGroupId -OS iOS
Assigns an AAD Group assignment to an iOS App Protection Policy in Intune
.NOTES
NAME: Assign-ManagedAppPolicy
#>

[cmdletbinding()]

param
(
    $Id,
    $TargetGroupId,
    $OS
)

$graphApiVersion = "Beta"
    
    try {

        if(!$Id){

        write-host "No Policy Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

$JSON = @"
{
    "assignments":[
    {
        "target":
        {
            "groupId":"$TargetGroupId",
            "@odata.type":"#microsoft.graph.groupAssignmentTarget"
        }
    }
    ]
}
"@

        if($OS -eq "" -or $OS -eq $null){

        write-host "No OS parameter specified, please provide an OS. Supported value Android or iOS..." -f Red
        Write-Host
        break

        }

        elseif($OS -eq "Android"){

        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$ID')/assign"
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken

        }

        elseif($OS -eq "iOS"){

        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/iosManagedAppProtections('$ID')/assign"
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken

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

######################################################

Function Add-WindowsInformationProtectionPolicy(){

<#
.SYNOPSIS
This function is used to add a Windows Information Protection policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a Windows Information Protection policy
.EXAMPLE
Add-WindowsInformationProtectionPolicy -JSON $JSON
Adds a Windows Information Protection policy in Intune
.NOTES
NAME: Add-WindowsInformationProtectionPolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/windowsInformationProtectionPolicies"
    
    try {
        
        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the iOS Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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

Function Add-MDMWindowsInformationProtectionPolicy(){

<#
.SYNOPSIS
This function is used to add a Windows Information Protection policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a Windows Information Protection policy
.EXAMPLE
Add-MDMWindowsInformationProtectionPolicy -JSON $JSON
Adds a Windows Information Protection policy in Intune
.NOTES
NAME: Add-MDMWindowsInformationProtectionPolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mdmWindowsInformationProtectionPolicies"
    
    try {
        
        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the iOS Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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

Function Assign-WindowsInformationProtectionPolicy(){

<#
.SYNOPSIS
This function is used to assign an AAD group to a WIP App Policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and assigns a WIP App Policy with an AAD Group
.EXAMPLE
Assign-WindowsInformationProtectionPolicy -Id $Id -TargetGroupId $TargetGroupId
Assigns an AAD Group assignment to a WIP App Protection Policy in Intune
.NOTES
NAME: Assign-WindowsInformationProtectionPolicy
#>

[cmdletbinding()]

param
(
    $Id,
    $TargetGroupId
)

$graphApiVersion = "Beta"
    
    try {

        if(!$Id){

        write-host "No Policy Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }


$JSON = @"
{
  "assignments": [
    {
      "target": {
        "groupId": "$TargetGroupId",
        "@odata.type": "#microsoft.graph.groupAssignmentTarget"
      }
    }
  ]
}
"@

    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies('$ID')/assign"
    Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken
    
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

Function Assign-MDMWindowsInformationProtectionPolicy(){

<#
.SYNOPSIS
This function is used to assign an AAD group to a WIP App Policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and assigns a WIP App Policy with an AAD Group
.EXAMPLE
Assign-MDMWindowsInformationProtectionPolicy -Id $Id -TargetGroupId $TargetGroupId
Assigns an AAD Group assignment to a WIP App Protection Policy in Intune
.NOTES
NAME: Assign-MDMWindowsInformationProtectionPolicy
#>

[cmdletbinding()]

param
(
    $Id,
    $TargetGroupId
)

$graphApiVersion = "Beta"
    
    try {

        if(!$Id){

        write-host "No Policy Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }


$JSON = @"
{
  "assignments": [
    {
      "target": {
        "groupId": "$TargetGroupId",
        "@odata.type": "#microsoft.graph.groupAssignmentTarget"
      }
    }
  ]
}
"@

    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies('$ID')/assign"
    Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken
    
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

Function Get-EnterpriseDomain(){

<#
.SYNOPSIS
This function is used to get the initial domain created using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets the initial domain created
.EXAMPLE
Get-EnterpriseDomain
Gets the initial domain created in Azure - Format domain.onmicrosoft.com
.NOTES
NAME: Get-EnterpriseDomain
#>

    try {

    $uri = "https://graph.microsoft.com/v1.0/domains"

    $domains = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

    $EnterpriseDomain = ($domains | ? { $_.isDefault -eq $true } | select id).id

    return $EnterpriseDomain

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
Function Get-TenantName(){

<#
.SYNOPSIS
This function is used to get the initial domain created using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets the initial domain created
.EXAMPLE
Get-EnterpriseDomain
Gets the initial domain created in Azure - Format domain.onmicrosoft.com
.NOTES
NAME: Get-EnterpriseDomain
#>

    try {

    $uri = "https://graph.microsoft.com/v1.0/organization"

    $orgData = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

    $TenantName1 = $orgData.displayName

    return $TenantName1

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




############################################

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

####################################################

$JSON_macOS = @"
{
  "@odata.type": "#microsoft.graph.macOSCompliancePolicy",
  "description": "1. Require system integrity protection\n2. Minimum OS version: 10.13\n3. Require a password to unlock devices.\n4. Block Simple passwords\n5. Minimum password length: 8 Alphanumeric\n6. Number of non-alphanumeric characters in password: 1\n7. Maximum minutes of inactivity before password is required: 5 Minutes\n8. Password expiration (days): 90\n9: Number of previous passwords to prevent reuse: 5\n10. RequireEncryption of data storage on device.\n11. Enable Firewall\n12. Block Incoming connections\n13. Allow apps downloaded from these locations: Mac App Store",
  "displayName": "macOS_Compliance",
  "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
  "version": 2,
  "passwordRequired": true,
  "passwordBlockSimple": true,
  "passwordExpirationDays": 90,
  "passwordMinimumLength": 8,
  "passwordMinutesOfInactivityBeforeLock": 5,
  "passwordPreviousPasswordBlockCount": 5,
  "passwordMinimumCharacterSetCount": 1,
  "passwordRequiredType": "alphanumeric",
  "osMinimumVersion": "10.13",
  "osMaximumVersion": "Os Maximum Version value",
  "systemIntegrityProtectionEnabled": true,
  "deviceThreatProtectionEnabled": false,
  "storageRequireEncryption": true,
  "firewallEnabled": true,
  "firewallBlockAllIncoming": true,
  "firewallEnableStealthMode": false
}
"@

####################################################

$JSON_AndroidWork = @"
    {
    "@odata.type": "#microsoft.graph.androidWorkProfileCompliancePolicy",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "description": "1. Block Rooted devices\n2. Google Play Services is configured\n3. SafetyNet device attestation: Check basic integrity\n4. Require a password to unlock mobile devices.\n5. Required password type: Numeric complex\n6. Maximum minutes of inactivity before password is required: 1 Minute\n7. Minimum password length: 6 \n8. Require Encryption of data storage on device.\n9. Block apps from unknown sources\n10. Require Company Portal app runtime integrity\n11.Block USB debugging on device\n12. Minimum security patch level: 2020-01-01",
    "displayName":  "Android_Work_Device",
    "passwordRequired": true,
    "passwordMinimumLength": 6,
    "passwordRequiredType": "numericComplex",
    "passwordMinutesOfInactivityBeforeLock": 1,
    "passwordExpirationDays": null,
    "passwordPreviousPasswordBlockCount": null,
    "passwordSignInFailureCountBeforeFactoryReset": null,
    "securityPreventInstallAppsFromUnknownSources": true,
    "securityDisableUsbDebugging": true,
    "securityRequireVerifyApps": false,
    "deviceThreatProtectionEnabled": false,
    "deviceThreatProtectionRequiredSecurityLevel": "unavailable",
    "advancedThreatProtectionRequiredSecurityLevel": "unavailable",
    "securityBlockJailbrokenDevices": true,
    "osMinimumVersion": null,
    "osMaximumVersion": null,
    "minAndroidSecurityPatchLevel": "2020-01-01",
    "storageRequireEncryption": true,
    "securityRequireSafetyNetAttestationBasicIntegrity": true,
    "securityRequireSafetyNetAttestationCertifiedDevice": false,
    "securityRequireGooglePlayServices": true,
    "securityRequireUpToDateSecurityProviders": false,
    "securityRequireCompanyPortalAppIntegrity": true
    
    }
"@

####################################################

$JSON_AndroidOwner = @"
    {
    "@odata.type": "#microsoft.graph.androidDeviceOwnerCompliancePolicy",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "description": "1. SafetyNet device attestation: Check basic integrity\n2. Require a password to unlock mobile devices.\n3. Minimum password length: 6 Numeric\n4. Maximum minutes of inactivity before password is required: 1 Minute\n5. Require Encryption of data storage on device.\n",
    "displayName":  "Android_Device_Owner",
    "deviceThreatProtectionEnabled": false,
    "deviceThreatProtectionRequiredSecurityLevel": "unavailable",
    "advancedThreatProtectionRequiredSecurityLevel": "unavailable",
    "securityRequireSafetyNetAttestationBasicIntegrity": true,
    "securityRequireSafetyNetAttestationCertifiedDevice": false,
    "osMinimumVersion": null,
    "osMaximumVersion": null,
    "minAndroidSecurityPatchLevel": null,
    "passwordRequired": true,
    "passwordMinimumLength": 6,
    "passwordMinimumLetterCharacters": null,
    "passwordMinimumLowerCaseCharacters": null,
    "passwordMinimumNonLetterCharacters": null,
    "passwordMinimumNumericCharacters": null,
    "passwordMinimumSymbolCharacters": null,
    "passwordMinimumUpperCaseCharacters": null,
    "passwordRequiredType": "numeric",
    "passwordMinutesOfInactivityBeforeLock": 1,
    "passwordExpirationDays": null,
    "passwordPreviousPasswordCountToBlock": null,
    "storageRequireEncryption": true
    
    }
"@

####################################################

$JSON_iOS = @"
  {
  "@odata.type": "microsoft.graph.iosCompliancePolicy",
  "description": "1. Block Jailbroken devices\n2. Require a password to unlock mobile devices.\n3. Block Simple passwords\n4. Minimum password length: 6 Numeric\n5. Maximum minutes after screen lock before password is required: Immediately\n6. Maximum minutes of inactivity until screen locks: 1",
  "displayName": "iOS Compliance Policy",
  "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
  "passcodeBlockSimple": true,
  "passcodeExpirationDays": null,
  "passcodeMinimumLength": 6,
  "passcodeMinutesOfInactivityBeforeLock": 0,
  "passcodeMinutesOfInactivityBeforeScreenTimeout": 1,
  "passcodePreviousPasscodeBlockCount": null,
  "passcodeMinimumCharacterSetCount": null,
  "passcodeRequiredType": "numeric",
  "passcodeRequired": true,
  "securityBlockJailbrokenDevices": true,
  "deviceThreatProtectionEnabled": false,
  "deviceThreatProtectionRequiredSecurityLevel": "low"
  }
"@

###############################

$JSON_Windows = @"
  {
  "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
  "description": "1. Require BitLocker\n2. Require Secure Boot to be enabled on the device\n3. Require code integrity\n4. Require Encryption of data storage on device.\n5. Firewall, Antivirus, Antispyware",
  "displayName": "Windows 10 Compliance Policy",
  "version": 7,
  "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
  "passwordRequired": false,
  "passwordBlockSimple": false,
  "passwordRequiredToUnlockFromIdle": false,
  "passwordMinutesOfInactivityBeforeLock": null,
  "passwordExpirationDays": null,
  "passwordMinimumLength": null,
  "passwordMinimumCharacterSetCount": null,
  "passwordRequiredType": "deviceDefault",
  "passwordPreviousPasswordBlockCount": null,
  "requireHealthyDeviceReport": false,
  "osMinimumVersion": null,
  "osMaximumVersion": null,
  "mobileOsMinimumVersion": null,
  "mobileOsMaximumVersion": null,
  "earlyLaunchAntiMalwareDriverEnabled": false,
  "bitLockerEnabled": true,
  "secureBootEnabled": true,
  "codeIntegrityEnabled": true,
  "storageRequireEncryption": true,
  "activeFirewallRequired": true,
  "defenderEnabled": false,
  "defenderVersion": null,
  "signatureOutOfDate": false,
  "rtpEnabled": false,
  "antivirusRequired": true,
  "antiSpywareRequired": true,
  "deviceThreatProtectionEnabled": false,
  "deviceThreatProtectionRequiredSecurityLevel": "unavailable",
  "configurationManagerComplianceRequired": false,
  "tpmRequired": false,
   "validOperatingSystemBuildRanges": []
}
"@



$JSON = @"
{
    "@odata.type": "#microsoft.graph.termsAndConditions",
    "displayName":"Customer Terms and Conditions",
    "title":"Terms and Conditions",
    "description":"By enrolling your device, you agree to $TenantName1 terms and conditions",
    "bodyText":"I acknowledge that by enrolling my device, $TenantName1 Administrators have certain types of control. This includes visibility into corporate app inventory, email usage, and device risk. I further agree to keep company resources safe to the best of my ability and inform $TenantName1 administrators as soon as I believe my device is lost or stolen",
    "acceptanceStatement":"I accept",
    "version":1
}
"@


$JSON1 = @"
{
  "@odata.type": "#microsoft.graph.officeSuiteApp",
  "autoAcceptEula": true,
  "description": "Office 365 Business Suite - Assigned",
  "developer": "Microsoft",
  "displayName": "Office 365 Business - Assigned",
  "excludedApps": {
    "groove": true,
    "infoPath": true,
    "sharePointDesigner": true
  },
  "informationUrl": "",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "iVBORw0KGgoAAAANSUhEUgAAAF0AAAAeCAMAAAEOZNKlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJhUExURf////7z7/i9qfF1S/KCW/i+qv3q5P/9/PrQwfOMae1RG+s8AOxGDfBtQPWhhPvUx/759/zg1vWgg+9fLu5WIvKFX/rSxP728/nCr/FyR+tBBvOMaO1UH+1RHOs+AvSScP3u6f/+/v3s5vzg1+xFDO9kNPOOa/i7pvzj2/vWyes9Af76+Pzh2PrTxf/6+f7y7vOGYexHDv3t5+1SHfi8qPOIZPvb0O1NFuxDCe9hMPSVdPnFs/3q4/vaz/STcu5VIe5YJPWcfv718v/9/e1MFfF4T/F4TvF2TP3o4exECvF0SexIEPONavzn3/vZze1QGvF3Te5dK+5cKvrPwPrQwvKAWe1OGPexmexKEveulfezm/BxRfamiuxLE/apj/zf1e5YJfSXd/OHYv3r5feznPakiPze1P7x7f739f3w6+xJEfnEsvWdf/Wfge1LFPe1nu9iMvnDsfBqPOs/BPOIY/WZevJ/V/zl3fnIt/vTxuxHD+xEC+9mN+5ZJv749vBpO/KBWvBwRP/8+/SUc/etlPjArP/7+vOLZ/F7UvWae/708e1OF/aihvSWdvi8p+tABfSZefvVyPWihfSVde9lNvami+9jM/zi2fKEXvBuQvOKZvalifF5UPJ/WPSPbe9eLfrKuvvd0uxBB/7w7Pzj2vrRw/rOv+1PGfi/q/eymu5bKf3n4PnJuPBrPf3t6PWfgvWegOxCCO9nOO9oOfaskvSYePi5pPi2oPnGtO5eLPevlvKDXfrNvv739Pzd0/708O9gL+9lNfJ9VfrLu/OPbPnDsPBrPus+A/nArfarkQAAAGr5HKgAAADLdFJOU/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AvuakogAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAz5JREFUOE+tVTtu4zAQHQjppmWzwIJbEVCzpTpjbxD3grQHSOXKRXgCAT6EC7UBVAmp3KwBnmvfzNCyZTmxgeTZJsXx43B+HBHRE34ZkXgkerXFTheeiCkRrbB4UXmp4wSWz5raaQEMTM5TZwuiXoaKgV+6FsmkZQcSy0kA71yMTMGHanX+AzMMGLAQCxU1F/ZwjULPugazl82GM0NEKm/U8EqFwEkO3/EAT4grgl0nucwlk9pcpTTJ4VPA4g/Rb3yIRhhp507e9nTQmZ1OS5RO4sS7nIRPEeHXCHdkw9ZEW2yVE5oIS7peD58Avs7CN+PVCmHh21oOqBdjDzIs+FldPJ74TFESUSJEfVzy9U/dhu+AuOT6eBp6gGKyXEx8euO450ZE4CMfstMFT44broWw/itkYErWXRx+fFArt9Ca9os78TFed0LVIUsmIHrwbwaw3BEOnOk94qVpQ6Ka2HjxewJnfyd6jUtGDQLdWlzmYNYLeKbbGOucJsNabCq1Yub0o92rtR+i30V2dapxYVEePXcOjeCKPnYyit7BtKeNlZqHbr+gt7i+AChWA9RsRs03pxTQc67ouWpxyESvjK5Vs3DVSy3IpkxPm5X+wZoBi+MFHWW69/w8FRhc7VBe6HAhMB2b8Q0XqDzTNZtXUMnKMjwKVaCrB/CSUL7WSx/HsdJC86lFGXwnioTeOMPjV+szlFvrZLA5VMVK4y+41l4e1xfx7Z88o4hkilRUH/qKqwNVlgDgpvYCpH3XwAy5eMCRnezIUxffVXoDql2rTHFDO+pjWnTWzAfrYXn6BFECblUpWGrvPZvBipETjS5ydM7tdXpH41ZCEbBNy/+wFZu71QO2t9pgT+iZEf657Q1vpN94PQNDxUHeKR103LV9nPVOtDikcNKO+2naCw7yKBhOe9Hm79pe8C4/CfC2wDjXnqC94kEeBU3WwN7dt/2UScXas7zDl5GpkY+M8WKv2J7fd4Ib2rGTk+jsC2cleEM7jI9veF7B0MBJrsZqfKd/81q9pR2NZfwJK2JzsmIT1Ns8jUH0UusQBpU8d2JzsHiXg1zXGLqxfitUNTDT/nUUeqDBp2HZVr+Ocqi/Ty3Rf4Jn82xxfSNtAAAAAElFTkSuQmCC"
  },
  "localesToInstall": [
    "en-us"
  ],
  "notes": "",
  "officePlatformArchitecture": "x64",
  "owner": "Microsoft",
  "privacyInformationUrl": "",
  "productIds": [
    "o365BusinessRetail"
  ],
  "publisher": "Microsoft",
  "updateChannel": "Current",
  "useSharedComputerActivation": false
}
"@

$mac_OfficeApps = @"
{
  "@odata.type": "#microsoft.graph.macOSOfficeSuiteApp",
  "description": "MacOS Office 365 - Assigned",
  "developer": "Microsoft",
  "displayName": "Mac Office 365 - Assigned",
  "informationUrl": "",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "iVBORw0KGgoAAAANSUhEUgAAAF0AAAAeCAMAAAEOZNKlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJhUExURf////7z7/i9qfF1S/KCW/i+qv3q5P/9/PrQwfOMae1RG+s8AOxGDfBtQPWhhPvUx/759/zg1vWgg+9fLu5WIvKFX/rSxP728/nCr/FyR+tBBvOMaO1UH+1RHOs+AvSScP3u6f/+/v3s5vzg1+xFDO9kNPOOa/i7pvzj2/vWyes9Af76+Pzh2PrTxf/6+f7y7vOGYexHDv3t5+1SHfi8qPOIZPvb0O1NFuxDCe9hMPSVdPnFs/3q4/vaz/STcu5VIe5YJPWcfv718v/9/e1MFfF4T/F4TvF2TP3o4exECvF0SexIEPONavzn3/vZze1QGvF3Te5dK+5cKvrPwPrQwvKAWe1OGPexmexKEveulfezm/BxRfamiuxLE/apj/zf1e5YJfSXd/OHYv3r5feznPakiPze1P7x7f739f3w6+xJEfnEsvWdf/Wfge1LFPe1nu9iMvnDsfBqPOs/BPOIY/WZevJ/V/zl3fnIt/vTxuxHD+xEC+9mN+5ZJv749vBpO/KBWvBwRP/8+/SUc/etlPjArP/7+vOLZ/F7UvWae/708e1OF/aihvSWdvi8p+tABfSZefvVyPWihfSVde9lNvami+9jM/zi2fKEXvBuQvOKZvalifF5UPJ/WPSPbe9eLfrKuvvd0uxBB/7w7Pzj2vrRw/rOv+1PGfi/q/eymu5bKf3n4PnJuPBrPf3t6PWfgvWegOxCCO9nOO9oOfaskvSYePi5pPi2oPnGtO5eLPevlvKDXfrNvv739Pzd0/708O9gL+9lNfJ9VfrLu/OPbPnDsPBrPus+A/nArfarkQAAAGr5HKgAAADLdFJOU/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AvuakogAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAz5JREFUOE+tVTtu4zAQHQjppmWzwIJbEVCzpTpjbxD3grQHSOXKRXgCAT6EC7UBVAmp3KwBnmvfzNCyZTmxgeTZJsXx43B+HBHRE34ZkXgkerXFTheeiCkRrbB4UXmp4wSWz5raaQEMTM5TZwuiXoaKgV+6FsmkZQcSy0kA71yMTMGHanX+AzMMGLAQCxU1F/ZwjULPugazl82GM0NEKm/U8EqFwEkO3/EAT4grgl0nucwlk9pcpTTJ4VPA4g/Rb3yIRhhp507e9nTQmZ1OS5RO4sS7nIRPEeHXCHdkw9ZEW2yVE5oIS7peD58Avs7CN+PVCmHh21oOqBdjDzIs+FldPJ74TFESUSJEfVzy9U/dhu+AuOT6eBp6gGKyXEx8euO450ZE4CMfstMFT44broWw/itkYErWXRx+fFArt9Ca9os78TFed0LVIUsmIHrwbwaw3BEOnOk94qVpQ6Ka2HjxewJnfyd6jUtGDQLdWlzmYNYLeKbbGOucJsNabCq1Yub0o92rtR+i30V2dapxYVEePXcOjeCKPnYyit7BtKeNlZqHbr+gt7i+AChWA9RsRs03pxTQc67ouWpxyESvjK5Vs3DVSy3IpkxPm5X+wZoBi+MFHWW69/w8FRhc7VBe6HAhMB2b8Q0XqDzTNZtXUMnKMjwKVaCrB/CSUL7WSx/HsdJC86lFGXwnioTeOMPjV+szlFvrZLA5VMVK4y+41l4e1xfx7Z88o4hkilRUH/qKqwNVlgDgpvYCpH3XwAy5eMCRnezIUxffVXoDql2rTHFDO+pjWnTWzAfrYXn6BFECblUpWGrvPZvBipETjS5ydM7tdXpH41ZCEbBNy/+wFZu71QO2t9pgT+iZEf657Q1vpN94PQNDxUHeKR103LV9nPVOtDikcNKO+2naCw7yKBhOe9Hm79pe8C4/CfC2wDjXnqC94kEeBU3WwN7dt/2UScXas7zDl5GpkY+M8WKv2J7fd4Ib2rGTk+jsC2cleEM7jI9veF7B0MBJrsZqfKd/81q9pR2NZfwJK2JzsmIT1Ns8jUH0UusQBpU8d2JzsHiXg1zXGLqxfitUNTDT/nUUeqDBp2HZVr+Ocqi/Ty3Rf4Jn82xxfSNtAAAAAElFTkSuQmCC"
  },
  "notes": "",
  "owner": "Microsoft",
  "privacyInformationUrl": "",
  "publisher": "Microsoft"
}
"@

##################################################

$Outlook = @"
{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "Microsoft Outlook",
  "description": "Microsoft Outlook",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  largeIcon: {
    "@odata.type": "#microsoft.graph.mimeContent",
    "type": "$iconType",
    "value": "$base64icon"
  },
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.office.outlook&hl=en",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }
}
"@

##################################################

$Excel = @"
{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "Microsoft Excel",
  "description": "Microsoft Excel",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  largeIcon: {
    "@odata.type": "#microsoft.graph.mimeContent",
    "type": "$iconType",
    "value": "$base64icon"
  },
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.office.excel&hl=en",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }
}
"@

##################################################

$Teams = @"
{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "Microsoft Teams",
  "description": "Microsoft Teams",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  largeIcon: {
    "@odata.type": "#microsoft.graph.mimeContent",
    "type": "$iconType",
    "value": "$base64icon"
  },
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.teams",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }
}
"@

##################################################

$OneDrive = @"
{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "OneDrive",
  "description": "Microsoft OneDrive",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  largeIcon: {
    "@odata.type": "#microsoft.graph.mimeContent",
    "type": "$iconType",
    "value": "$base64icon"
  },
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.skydrive",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }
}
"@

##################################################

$Word = @"
{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "Microsoft Word",
  "description": "Microsoft Word",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  largeIcon: {
    "@odata.type": "#microsoft.graph.mimeContent",
    "type": "$iconType",
    "value": "$base64icon"
  },
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.office.word",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }
}
"@

##################################################

$PowerPoint = @"
{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "Microsoft PowerPoint",
  "description": "Microsoft PowerPoint",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  largeIcon: {
    "@odata.type": "#microsoft.graph.mimeContent",
    "type": "$iconType",
    "value": "$base64icon"
  },
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.office.powerpoint",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }
}
"@


$MicrosoftAuthenticator = @"
{
  "@odata.type": "#microsoft.graph.androidStoreApp",
  "displayName": "Microsoft Authenticator-Android",
  "description": "Microsoft Authenticator-Android",
  "publisher": "Microsoft Corporation",
  "isFeatured": true,
  "appStoreUrl": "https://play.google.com/store/apps/details?id=com.azure.authenticator&hl=en_US",
  "minimumSupportedOperatingSystem": {
    "@odata.type": "#microsoft.graph.androidMinimumOperatingSystem",
    "v4_0": true
  }
}
"@



$iOS = @"
{
    "@odata.type": "#microsoft.graph.iosManagedAppProtection",
    "displayName": "iOS_App_Protection Policy",
    "description": "",
    "periodOfflineBeforeAccessCheck": "PT12H",
    "periodOnlineBeforeAccessCheck": "PT30M",
    "allowedInboundDataTransferSources": "managedApps",
    "allowedOutboundDataTransferDestinations": "managedApps",
    "organizationalCredentialsRequired": false,
    "allowedOutboundClipboardSharingLevel": "managedApps",
    "dataBackupBlocked": true,
    "deviceComplianceRequired": true,
    "managedBrowserToOpenLinksRequired": false,
    "saveAsBlocked": true,
    "periodOfflineBeforeWipeIsEnforced": "P90D",
    "pinRequired": true,
    "maximumPinRetries": 5,
    "simplePinBlocked": false,
    "minimumPinLength": 4,
    "pinCharacterSet": "numeric",
    "periodBeforePinReset": "PT0S",
    "allowedDataStorageLocations": [
        "oneDriveForBusiness"
    ],
    "contactSyncBlocked": false,
    "printBlocked": true,
    "fingerprintBlocked": false,
    "disableAppPinIfDevicePinIsSet": false,
    "appActionIfDeviceComplianceRequired": "block",
    "appActionIfMaximumPinRetriesExceeded": "block",
    "allowedOutboundClipboardSharingExceptionLength": 0,
    "notificationRestriction": "allow",
    "previousPinBlockCount": 0,
    "managedBrowser": "notConfigured",
    "maximumAllowedDeviceThreatLevel": "notConfigured",
    "mobileThreatDefenseRemediationAction": "block",
    "blockDataIngestionIntoOrganizationDocuments": false,
    "allowedDataIngestionLocations": [
        "oneDriveForBusiness",
        "sharePoint",
        "camera"
    ],
    "targetedAppManagementLevels": "unmanaged",
    "appDataEncryptionType": "whenDeviceLocked",
    "deployedAppCount": 9,
    "faceIdBlocked": false,
    "appActionIfIosDeviceModelNotAllowed": "block",
    "thirdPartyKeyboardsBlocked": false,
    "filterOpenInToOnlyManagedApps": false,
    "disableProtectionOfManagedOutboundOpenInData": false,
    "protectInboundDataFromUnknownSources": false,
    "exemptedAppProtocols": [
        {
            "name": "Default",
            "value": "tel;telprompt;skype;app-settings;calshow;itms;itmss;itms-apps;itms-appss;itms-services;"
        }
    ],
    "apps": [
        {
            "id": "com.microsoft.office.outlook.ios",
            "version": "-518090279",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.iosMobileAppIdentifier",
                "bundleId": "com.microsoft.office.outlook"
            }
        },
        {
            "id": "com.microsoft.office.powerpoint.ios",
            "version": "-740777841",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.iosMobileAppIdentifier",
                "bundleId": "com.microsoft.office.powerpoint"
            }
        },
        {
            "id": "com.microsoft.office.word.ios",
            "version": "922692278",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.iosMobileAppIdentifier",
                "bundleId": "com.microsoft.office.word"
            }
        },
        {
            "id": "com.microsoft.onenote.ios",
            "version": "107156768",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.iosMobileAppIdentifier",
                "bundleId": "com.microsoft.onenote"
            }
        },
        {
            "id": "com.microsoft.plannermobile.ios",
            "version": "-175532278",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.iosMobileAppIdentifier",
                "bundleId": "com.microsoft.plannermobile"
            }
        },
        {
            "id": "com.microsoft.sharepoint.ios",
            "version": "-585639021",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.iosMobileAppIdentifier",
                "bundleId": "com.microsoft.sharepoint"
            }
        },
        {
            "id": "com.microsoft.skydrive.ios",
            "version": "-108719121",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.iosMobileAppIdentifier",
                "bundleId": "com.microsoft.skydrive"
            }
        },
        {
            "id": "com.microsoft.skype.teams.ios",
            "version": "-1040529574",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.iosMobileAppIdentifier",
                "bundleId": "com.microsoft.skype.teams"
            }
        },
        {
            "id": "com.microsoft.stream.ios",
            "version": "126860698",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.iosMobileAppIdentifier",
                "bundleId": "com.microsoft.stream"
            }
        }
    ]
}
"@

####################################################

$Android = @"
{
    "@odata.type": "#microsoft.graph.androidManagedAppProtection",
    "displayName": "Android_Protection_Policy1",
    "description": "",
    "periodOfflineBeforeAccessCheck": "PT12H",
    "periodOnlineBeforeAccessCheck": "PT30M",
    "allowedInboundDataTransferSources": "managedApps",
    "allowedOutboundDataTransferDestinations": "managedApps",
    "organizationalCredentialsRequired": false,
    "allowedOutboundClipboardSharingLevel": "managedApps",
    "dataBackupBlocked": true,
    "deviceComplianceRequired": true,
    "managedBrowserToOpenLinksRequired": false,
    "saveAsBlocked": true,
    "periodOfflineBeforeWipeIsEnforced": "P90D",
    "pinRequired": true,
    "maximumPinRetries": 5,
    "simplePinBlocked": false,
    "minimumPinLength": 4,
    "pinCharacterSet": "numeric",
    "periodBeforePinReset": "PT0S",
    "allowedDataStorageLocations": [],
    "contactSyncBlocked": false,
    "printBlocked": true,
    "fingerprintBlocked": false,
    "disableAppPinIfDevicePinIsSet": false,
    "minimumRequiredOsVersion": null,
    "minimumWarningOsVersion": null,
    "minimumRequiredAppVersion": null,
    "minimumWarningAppVersion": null,
    "minimumWipeOsVersion": null,
    "minimumWipeAppVersion": null,
    "appActionIfDeviceComplianceRequired": "block",
    "appActionIfMaximumPinRetriesExceeded": "block",
    "pinRequiredInsteadOfBiometricTimeout": "PT30M",
    "allowedOutboundClipboardSharingExceptionLength": 0,
    "notificationRestriction": "allow",
    "previousPinBlockCount": 0,
    "managedBrowser": "notConfigured",
    "maximumAllowedDeviceThreatLevel": "notConfigured",
    "mobileThreatDefenseRemediationAction": "block",
    "blockDataIngestionIntoOrganizationDocuments": false,
    "allowedDataIngestionLocations": [
        "oneDriveForBusiness",
        "sharePoint",
        "camera"
    ],
    "appActionIfUnableToAuthenticateUser": null,
    "targetedAppManagementLevels": "unmanaged",
    "screenCaptureBlocked": true,
    "disableAppEncryptionIfDeviceEncryptionIsEnabled": false,
    "encryptAppData": true,
    "deployedAppCount": 9,
    "minimumRequiredPatchVersion": "0000-00-00",
    "minimumWarningPatchVersion": "0000-00-00",
    "minimumWipePatchVersion": "0000-00-00",
    "allowedAndroidDeviceManufacturers": null,
    "appActionIfAndroidDeviceManufacturerNotAllowed": "block",
    "requiredAndroidSafetyNetDeviceAttestationType": "none",
    "appActionIfAndroidSafetyNetDeviceAttestationFailed": "block",
    "requiredAndroidSafetyNetAppsVerificationType": "none",
    "appActionIfAndroidSafetyNetAppsVerificationFailed": "block",
    "keyboardsRestricted": false,
    "allowedAndroidDeviceModels": [],
    "appActionIfAndroidDeviceModelNotAllowed": "block",
    "exemptedAppPackages": [],
    "approvedKeyboards": [],
    "apps": [
        {
            "id": "com.microsoft.office.excel.android",
            "version": "-1789826587",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.androidMobileAppIdentifier",
                "packageId": "com.microsoft.office.excel"
            }
        },
        {
            "id": "com.microsoft.office.onenote.android",
            "version": "186482170",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.androidMobileAppIdentifier",
                "packageId": "com.microsoft.office.onenote"
            }
        },
        {
            "id": "com.microsoft.office.outlook.android",
            "version": "1146701235",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.androidMobileAppIdentifier",
                "packageId": "com.microsoft.office.outlook"
            }
        },
        {
            "id": "com.microsoft.office.powerpoint.android",
            "version": "1411665537",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.androidMobileAppIdentifier",
                "packageId": "com.microsoft.office.powerpoint"
            }
        },
        {
            "id": "com.microsoft.office.word.android",
            "version": "2122351424",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.androidMobileAppIdentifier",
                "packageId": "com.microsoft.office.word"
            }
        },
        {
            "id": "com.microsoft.planner.android",
            "version": "-1658524342",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.androidMobileAppIdentifier",
                "packageId": "com.microsoft.planner"
            }
        },
        {
            "id": "com.microsoft.sharepoint.android",
            "version": "84773357",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.androidMobileAppIdentifier",
                "packageId": "com.microsoft.sharepoint"
            }
        },
        {
            "id": "com.microsoft.skydrive.android",
            "version": "1887770705",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.androidMobileAppIdentifier",
                "packageId": "com.microsoft.skydrive"
            }
        },
        {
            "id": "com.microsoft.teams.android",
            "version": "1900143244",
            "mobileAppIdentifier": {
                "@odata.type": "#microsoft.graph.androidMobileAppIdentifier",
                "packageId": "com.microsoft.teams"
            }
        }
    ]
}
"@

##################################################

$EnterpriseDomain = Get-EnterpriseDomain
$TenantName1 = Get-TenantName

####################################################

$ManagedAppPolicy_WIP = @"
{
  "description": "",
  "displayName": "Win10 WIP WE Policy - Assigned",
  "enforcementLevel": "encryptAuditAndBlock",
  "enterpriseDomain": "$EnterpriseDomain",
  "enterpriseProtectedDomainNames": [],
  "protectionUnderLockConfigRequired": false,
  "dataRecoveryCertificate": null,
  "revokeOnUnenrollDisabled": false,
  "revokeOnMdmHandoffDisabled": false,
  "rightsManagementServicesTemplateId": null,
  "azureRightsManagementServicesAllowed": false,
  "iconsVisible": true,
  "protectedApps": [
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",
      "description": "",
      "displayName": "Microsoft Teams",
      "productName": "*",
      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false,
      "binaryName": "teams.exe",
      "binaryVersionLow": "*",
      "binaryVersionHigh": "*"
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",
      "description": "",
      "displayName": "Microsoft OneDrive",
      "productName": "*",
      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false,
      "binaryName": "onedrive.exe",
      "binaryVersionLow": "*",
      "binaryVersionHigh": "*"
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Company Portal",
      "productName": "Microsoft.CompanyPortal",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "OneNote",
      "productName": "Microsoft.Office.OneNote",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "PowerPoint Mobile",
      "productName": "Microsoft.Office.PowerPoint",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Excel Mobile",
      "productName": "Microsoft.Office.Excel",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Word Mobile",
      "productName": "Microsoft.Office.Word",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    }
  ],
  "exemptApps": [],
  "protectedAppLockerFiles": [
    {
      "displayName": "Office-365-ProPlus-1708-Allowed.xml",
      "fileHash": "4107a857-0e0b-483f-8ff5-bb3ed095b434",
      "file": "PEFwcExvY2tlclBvbGljeSBWZXJzaW9uPSIxIj4NCiAgPFJ1bGVDb2xsZWN0aW9uIFR5cGU9IkV4ZSIgRW5mb3JjZW1lbnRNb2RlPSJFbmFibGVkIj4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImQ2NjMyNzZjLTU0NGUtNGRlYS1iNzVjLTc1ZmMyZDRlMDI2NiIgTmFtZT0iTFlOQy5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DLkVYRSI+DQoJCSAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KCTwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSIyMTk1NzFiNC1hMjU3LTRiNGMtYjg1Ni1lYmYwNjgxZWUwZjAiIE5hbWU9IkxZTkM5OS5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DOTkuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI1MzhkNDQzYS05ZmRiLTQ5MWUtOGJjMy1lNzhkYjljMzEwYzciIE5hbWU9Ik9ORU5PVEVNLkVYRSwgdmVyc2lvbiAxNi4wLjgyMDEuMjAyNSBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPTkVOT1RFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSJPTkVOT1RFTS5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjZlZjA3YTkyLWYxZGItNDg4MC04YjQwLWRkMzliNzQzYTQ4NSIgTmFtZT0iV0lOV09SRC5FWEUsIHZlcnNpb24gMTYuMC44MjAxLjIwMjUgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJXSU5XT1JELkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iN2Q3NGQxYWQtYTYwYi00ZWE4LWJiNjAtM2Q0MDQ4ODZkMTBiIiBOYW1lPSJPTkVOT1RFLkVYRSwgdmVyc2lvbiAxNi4wLjgyMDEuMjAyNSBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPTkVOT1RFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSJPTkVOT1RFLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iODQwOWFhNjItMWI1Mi00ODRiLTg3ODctZDU3Y2M4NTI1ZTIxIiBOYW1lPSJPQ1BVQk1HUi5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJPQ1BVQk1HUi5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43ODcwLjIwMjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImU2Y2NjY2QxLWE2MGYtNGNiNC04YjRiLTkwM2M3MDk3NmI1MCIgTmFtZT0iUE9XRVJQTlQuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iUE9XRVJQTlQuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSJlYzc5ZWJiZS0zMTY5LTRhMjYtYWY1ZS1lMDc2YzkwOTY0OTUiIE5hbWU9Ik1TT1NZTkMuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iTVNPU1lOQy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImYwYjM1MjZiLTE0ZTctNDQyOC05NzAzLTRkZmYyZWE0MDAwZCIgTmFtZT0iVUNNQVBJLkVYRSwgdmVyc2lvbiAxNi4wLjc4NzAuMjAyMCBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPRkZJQ0UgMjAxNiwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IlVDTUFQSS5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43ODcwLjIwMjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImYxYmVkY2IxLWNhMzQtNDdiNS04NmM4LTI1NjU0YjE3OGNiOSIgTmFtZT0iT1VUTE9PSy5FWEUsIHZlcnNpb24gMTYuMC44MjAxLjIwMjUgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT1VUTE9PSywgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT1VUTE9PSyIgQmluYXJ5TmFtZT0iT1VUTE9PSy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImY5NjFlODQ2LTNmZTctNDY0Yy05NTA4LTAzNTMzN2QxZTg2OCIgTmFtZT0iRVhDRUwuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iRVhDRUwuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSJkNzAzMzE5Yy0wYzllLTQ0NjctYWQwOS03MTMzMDdlMzBkZjYiIE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImRlOWYzNDYxLTY4NTYtNDA1ZC05NjI0LWE4MGNhNzAxZjZjYiIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDAzLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDAzIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImFkZTFiODI4LTcwNTUtNDdmYy05OWJjLTQzMmNmN2QxMjA5ZSIgTmFtZT0iMjAwNyBNSUNST1NPRlQgT0ZGSUNFIFNZU1RFTSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9IjIwMDcgTUlDUk9TT0ZUIE9GRklDRSBTWVNURU0iIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iYmIzODc3YjYtZjFhZC00YzgzLTk2ZTItZDZiZjc1ZTMzY2JmIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTAsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTAiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iMjM2MzVlZWYtYjFlMy00ZGEyLTg4NTktMDYzOGVjNjA3YjM4IiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTMsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTMiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iZDJkMDUyMGEtNTdkZS00YmQ1LWJjZDktYjNkNDcyMjFmODdhIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICAgIDxFeGNlcHRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IkVYQ0VMLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DOTkuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik1TT1NZTkMuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik9DUFVCTUdSLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJQT1dFUlBOVC5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iVUNNQVBJLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJXSU5XT1JELkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvRXhjZXB0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iYTMzNjVkZmYtNjA1Mi00MWE4LTgyYTYtMzQ0NDRlYzI1OTUzIiBOYW1lPSJNSUNST1NPRlQgT05FTk9URSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgICA8RXhjZXB0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9ORU5PVEUiIEJpbmFyeU5hbWU9Ik9ORU5PVEUuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT05FTk9URSIgQmluYXJ5TmFtZT0iT05FTk9URU0uRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9FeGNlcHRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSIwYmE0YzE1MC0xY2IzLTRjYjktYWIwMi0yNjUyNzQ0MTk0MDkiIE5hbWU9Ik1JQ1JPU09GVCBPVVRMT09LLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9VVExPT0siIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICAgIDxFeGNlcHRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT1VUTE9PSyIgQmluYXJ5TmFtZT0iT1VUTE9PSy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0V4Y2VwdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjY3MTRmODVmLWFkZGEtNGVjNy05NDdjLTc1NTJmN2Q5NDYyNSIgTmFtZT0iTUlDUk9TT0ZUIENMSVAgT1JHQU5JWkVSLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIENMSVAgT1JHQU5JWkVSIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4JDQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI3NGFiMzY4Zi1hMTQ3LTRjZjktODBjMy01M2ZiNjY5YzQ4MzYiIE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgSU5GT1BBVEgsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIElORk9QQVRIIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9Ijk3NjlkMjA5LTg1ZjgtNDM4OS1iZGM2LWRkY2EzMGYxYzY3MSIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSBIRUxQIFZJRVdFUiwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgSEVMUCBWSUVXRVIiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KCTwvUnVsZUNvbGxlY3Rpb24+DQo8L0FwcExvY2tlclBvbGljeT4=",
      "id": "0c5c4541-87a8-478b-b9fc-4206d0f421f9",
      "@odata.type": "#microsoft.graph.windowsInformationProtectionAppLockerFile"
    }
  ],
  "exemptAppLockerFiles": [],
  "enterpriseIPRanges": [],
  "enterpriseIPRangesAreAuthoritative": false,
  "enterpriseProxyServers": [],
  "enterpriseInternalProxyServers": [],
  "enterpriseProxyServersAreAuthoritative": false,
  "neutralDomainResources": [],
  "windowsHelloForBusinessBlocked": false,
  "pinMinimumLength": 4,
  "pinUppercaseLetters": "notAllow",
  "pinLowercaseLetters": "notAllow",
  "pinSpecialCharacters": "notAllow",
  "pinExpirationDays": 0,
  "numberOfPastPinsRemembered": 0,
  "passwordMaximumAttemptCount": 0,
  "minutesOfInactivityBeforeDeviceLock": 0,
  "mdmEnrollmentUrl": "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc",
  "@odata.type": "#microsoft.graph.windowsInformationProtectionPolicy"
}
"@

####################################################

$ManagedAppPolicy_WIP_MDM = @"
{
  "description": "",
  "displayName": "Win10 WIP MDM Policy - Assigned",
  "enforcementLevel": "encryptAuditAndBlock",
  "enterpriseDomain": "$EnterpriseDomain",
  "enterpriseProtectedDomainNames": [],
  "protectionUnderLockConfigRequired": false,
  "dataRecoveryCertificate": null,
  "revokeOnUnenrollDisabled": false,
  "rightsManagementServicesTemplateId": null,
  "azureRightsManagementServicesAllowed": false,
  "iconsVisible": true,
  "protectedApps": [
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",
      "description": "",
      "displayName": "Microsoft Teams",
      "productName": "*",
      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false,
      "binaryName": "teams.exe",
      "binaryVersionLow": "*",
      "binaryVersionHigh": "*"
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",
      "description": "",
      "displayName": "Microsoft OneDrive",
      "productName": "*",
      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false,
      "binaryName": "onedrive.exe",
      "binaryVersionLow": "*",
      "binaryVersionHigh": "*"
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Company Portal",
      "productName": "Microsoft.CompanyPortal",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "OneNote",
      "productName": "Microsoft.Office.OneNote",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "PowerPoint Mobile",
      "productName": "Microsoft.Office.PowerPoint",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Excel Mobile",
      "productName": "Microsoft.Office.Excel",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Word Mobile",
      "productName": "Microsoft.Office.Word",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    }
  ],
  "exemptApps": [],
  "protectedAppLockerFiles": [
    {
      "displayName": "Office-365-ProPlus-1708-Allowed.xml",
      "fileHash": "2eb106c8-234b-4253-af44-63f522bfe222",
      "file": "PEFwcExvY2tlclBvbGljeSBWZXJzaW9uPSIxIj4NCiAgPFJ1bGVDb2xsZWN0aW9uIFR5cGU9IkV4ZSIgRW5mb3JjZW1lbnRNb2RlPSJFbmFibGVkIj4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImQ2NjMyNzZjLTU0NGUtNGRlYS1iNzVjLTc1ZmMyZDRlMDI2NiIgTmFtZT0iTFlOQy5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DLkVYRSI+DQoJCSAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KCTwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSIyMTk1NzFiNC1hMjU3LTRiNGMtYjg1Ni1lYmYwNjgxZWUwZjAiIE5hbWU9IkxZTkM5OS5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DOTkuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI1MzhkNDQzYS05ZmRiLTQ5MWUtOGJjMy1lNzhkYjljMzEwYzciIE5hbWU9Ik9ORU5PVEVNLkVYRSwgdmVyc2lvbiAxNi4wLjgyMDEuMjAyNSBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPTkVOT1RFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSJPTkVOT1RFTS5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjZlZjA3YTkyLWYxZGItNDg4MC04YjQwLWRkMzliNzQzYTQ4NSIgTmFtZT0iV0lOV09SRC5FWEUsIHZlcnNpb24gMTYuMC44MjAxLjIwMjUgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJXSU5XT1JELkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iN2Q3NGQxYWQtYTYwYi00ZWE4LWJiNjAtM2Q0MDQ4ODZkMTBiIiBOYW1lPSJPTkVOT1RFLkVYRSwgdmVyc2lvbiAxNi4wLjgyMDEuMjAyNSBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPTkVOT1RFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSJPTkVOT1RFLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iODQwOWFhNjItMWI1Mi00ODRiLTg3ODctZDU3Y2M4NTI1ZTIxIiBOYW1lPSJPQ1BVQk1HUi5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJPQ1BVQk1HUi5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43ODcwLjIwMjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImU2Y2NjY2QxLWE2MGYtNGNiNC04YjRiLTkwM2M3MDk3NmI1MCIgTmFtZT0iUE9XRVJQTlQuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iUE9XRVJQTlQuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSJlYzc5ZWJiZS0zMTY5LTRhMjYtYWY1ZS1lMDc2YzkwOTY0OTUiIE5hbWU9Ik1TT1NZTkMuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iTVNPU1lOQy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImYwYjM1MjZiLTE0ZTctNDQyOC05NzAzLTRkZmYyZWE0MDAwZCIgTmFtZT0iVUNNQVBJLkVYRSwgdmVyc2lvbiAxNi4wLjc4NzAuMjAyMCBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPRkZJQ0UgMjAxNiwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IlVDTUFQSS5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43ODcwLjIwMjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImYxYmVkY2IxLWNhMzQtNDdiNS04NmM4LTI1NjU0YjE3OGNiOSIgTmFtZT0iT1VUTE9PSy5FWEUsIHZlcnNpb24gMTYuMC44MjAxLjIwMjUgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT1VUTE9PSywgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT1VUTE9PSyIgQmluYXJ5TmFtZT0iT1VUTE9PSy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImY5NjFlODQ2LTNmZTctNDY0Yy05NTA4LTAzNTMzN2QxZTg2OCIgTmFtZT0iRVhDRUwuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iRVhDRUwuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSJkNzAzMzE5Yy0wYzllLTQ0NjctYWQwOS03MTMzMDdlMzBkZjYiIE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImRlOWYzNDYxLTY4NTYtNDA1ZC05NjI0LWE4MGNhNzAxZjZjYiIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDAzLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDAzIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImFkZTFiODI4LTcwNTUtNDdmYy05OWJjLTQzMmNmN2QxMjA5ZSIgTmFtZT0iMjAwNyBNSUNST1NPRlQgT0ZGSUNFIFNZU1RFTSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9IjIwMDcgTUlDUk9TT0ZUIE9GRklDRSBTWVNURU0iIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iYmIzODc3YjYtZjFhZC00YzgzLTk2ZTItZDZiZjc1ZTMzY2JmIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTAsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTAiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iMjM2MzVlZWYtYjFlMy00ZGEyLTg4NTktMDYzOGVjNjA3YjM4IiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTMsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTMiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iZDJkMDUyMGEtNTdkZS00YmQ1LWJjZDktYjNkNDcyMjFmODdhIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICAgIDxFeGNlcHRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IkVYQ0VMLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DOTkuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik1TT1NZTkMuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik9DUFVCTUdSLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJQT1dFUlBOVC5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iVUNNQVBJLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJXSU5XT1JELkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvRXhjZXB0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iYTMzNjVkZmYtNjA1Mi00MWE4LTgyYTYtMzQ0NDRlYzI1OTUzIiBOYW1lPSJNSUNST1NPRlQgT05FTk9URSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgICA8RXhjZXB0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9ORU5PVEUiIEJpbmFyeU5hbWU9Ik9ORU5PVEUuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT05FTk9URSIgQmluYXJ5TmFtZT0iT05FTk9URU0uRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9FeGNlcHRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSIwYmE0YzE1MC0xY2IzLTRjYjktYWIwMi0yNjUyNzQ0MTk0MDkiIE5hbWU9Ik1JQ1JPU09GVCBPVVRMT09LLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9VVExPT0siIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICAgIDxFeGNlcHRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT1VUTE9PSyIgQmluYXJ5TmFtZT0iT1VUTE9PSy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0V4Y2VwdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjY3MTRmODVmLWFkZGEtNGVjNy05NDdjLTc1NTJmN2Q5NDYyNSIgTmFtZT0iTUlDUk9TT0ZUIENMSVAgT1JHQU5JWkVSLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIENMSVAgT1JHQU5JWkVSIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4JDQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI3NGFiMzY4Zi1hMTQ3LTRjZjktODBjMy01M2ZiNjY5YzQ4MzYiIE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgSU5GT1BBVEgsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIElORk9QQVRIIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9Ijk3NjlkMjA5LTg1ZjgtNDM4OS1iZGM2LWRkY2EzMGYxYzY3MSIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSBIRUxQIFZJRVdFUiwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgSEVMUCBWSUVXRVIiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KCTwvUnVsZUNvbGxlY3Rpb24+DQo8L0FwcExvY2tlclBvbGljeT4=",
      "id": "4e49ffae-f006-46b9-b74d-785565f7efb4",
      "@odata.type": "#microsoft.graph.windowsInformationProtectionAppLockerFile"
    }
  ],
  "exemptAppLockerFiles": [],
  "enterpriseNetworkDomainNames": [],
  "enterpriseIPRanges": [],
  "enterpriseIPRangesAreAuthoritative": false,
  "enterpriseProxyServers": [],
  "enterpriseInternalProxyServers": [],
  "enterpriseProxyServersAreAuthoritative": false,
  "neutralDomainResources": [],
  "@odata.type": "#microsoft.graph.mdmWindowsInformationProtectionPolicy"
}
"@

####################################################

$windows_endpoint = @"

{
            "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",   
            "description": "Silently configure BitLocker Encryption",
            "displayName": "Windows_Endpoint_Profile",
            "version": 1,
            "firewallBlockStatefulFTP": false,
            "firewallIdleTimeoutForSecurityAssociationInSeconds": null,
            "firewallPreSharedKeyEncodingMethod": "deviceDefault",
            "firewallIPSecExemptionsAllowNeighborDiscovery": false,
            "firewallIPSecExemptionsAllowICMP": false,
            "firewallIPSecExemptionsAllowRouterDiscovery": false,
            "firewallIPSecExemptionsAllowDHCP": false,
            "firewallCertificateRevocationListCheckMethod": "deviceDefault",
            "firewallMergeKeyingModuleSettings": false,
            "firewallPacketQueueingMethod": "deviceDefault",
            "firewallProfileDomain": null,
            "firewallProfilePublic": null,
            "firewallProfilePrivate": null,
            "defenderAttackSurfaceReductionExcludedPaths": [],
            "defenderGuardedFoldersAllowedAppPaths": [],
            "defenderAdditionalGuardedFolders": [],
            "defenderExploitProtectionXml": null,
            "defenderExploitProtectionXmlFileName": null,
            "defenderSecurityCenterBlockExploitProtectionOverride": false,
            "appLockerApplicationControl": "notConfigured",
            "smartScreenEnableInShell": false,
            "smartScreenBlockOverrideForFiles": false,
            "applicationGuardEnabled": false,
            "applicationGuardBlockFileTransfer": "notConfigured",
            "applicationGuardBlockNonEnterpriseContent": false,
            "applicationGuardAllowPersistence": false,
            "applicationGuardForceAuditing": false,
            "applicationGuardBlockClipboardSharing": "notConfigured",
            "applicationGuardAllowPrintToPDF": false,
            "applicationGuardAllowPrintToXPS": false,
            "applicationGuardAllowPrintToLocalPrinters": false,
            "applicationGuardAllowPrintToNetworkPrinters": false,
            "bitLockerDisableWarningForOtherDiskEncryption": true,
            "bitLockerEnableStorageCardEncryptionOnMobile": false,
            "bitLockerEncryptDevice": true,
            "bitLockerRemovableDrivePolicy": {
                "encryptionMethod": null,
                "requireEncryptionForWriteAccess": false,
                "blockCrossOrganizationWriteAccess": false
            }
        }
"@




####################################################

# Setting AAD Group

$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where policies will be assigned"

$TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host 
    
    
    $AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where policies will be assigned"
    $TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    }

Write-Host

##############################################################################

Write-Host
Write-Host "Adding Terms and Conditions from JSON..." -ForegroundColor Cyan
Write-Host "Creating Terms and Conditions via Graph"
$CreateResult = Add-TermsAndConditions -JSON $JSON
write-host "Terms and Conditions created with id" $CreateResult.id

Write-Host

write-host "Assigning Terms and Conditions to AAD Group '$AADGroup'" -f Yellow
$Assign_Policy = Assign-TermsAndConditions -id $CreateResult.id -TargetGroupId $TargetGroupId
Write-Host "Assigned '$AADGroup' to $($CreateResult.displayName)/$($CreateResult.id)"
Write-Host

####################################################

Write-Host "Adding macOS Compliance Policy from JSON..." -ForegroundColor Yellow

$CreateResult_macOS = Add-DeviceCompliancePolicy -JSON $JSON_macOS

Write-Host "Compliance Policy created as" $CreateResult_macOS.id
write-host
write-host "Assigning Compliance Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_macOS = Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CreateResult_macOS.id -TargetGroupId $TargetGroupId

Write-Host "Assigned '$AADGroup' to $($CreateResult_macOS.displayName)/$($CreateResult_macOS.id)"
Write-Host

####################################################

Write-Host "Adding Android Work Compliance Policy from JSON..." -ForegroundColor Yellow

$CreateResult_AndroidWork = Add-DeviceCompliancePolicy -JSON $JSON_AndroidWork

Write-Host "Compliance Policy created as" $CreateResult_AndroidWork.id
write-host
write-host "Assigning Compliance Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_Android = Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CreateResult_AndroidWork.id -TargetGroupId $TargetGroupId

Write-Host "Assigned '$AADGroup' to $($CreateResult_AndroidWork.displayName)/$($CreateResult_AndroidWork.id)"
Write-Host

####################################################

Write-Host "Adding Android Device Owner Compliance Policy from JSON..." -ForegroundColor Yellow

$CreateResult_AndroidOwner = Add-DeviceCompliancePolicy -JSON $JSON_AndroidOwner

Write-Host "Compliance Policy created as" $CreateResult_AndroidOwner.id
write-host
write-host "Assigning Compliance Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_Android = Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CreateResult_AndroidOwner.id -TargetGroupId $TargetGroupId

Write-Host "Assigned '$AADGroup' to $($CreateResult_AndroidOwner.displayName)/$($CreateResult_AndroidOwner.id)"
Write-Host

####################################################

Write-Host "Adding iOS Compliance Policy from JSON..." -ForegroundColor Yellow
Write-Host

$CreateResult_iOS = Add-DeviceCompliancePolicy -JSON $JSON_iOS

Write-Host "Compliance Policy created as" $CreateResult_iOS.id
write-host
write-host "Assigning Compliance Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_iOS = Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CreateResult_iOS.id -TargetGroupId $TargetGroupId

Write-Host "Assigned '$AADGroup' to $($CreateResult_iOS.displayName)/$($CreateResult_iOS.id)"
Write-Host

#####################################################

Write-Host "Adding Windows Compliance Policy from JSON..." -ForegroundColor Yellow

$CreateResult_Windows = Add-DeviceCompliancePolicy -JSON $JSON_Windows

Write-Host "Compliance Policy created as" $CreateResult_Windows.id
write-host
write-host "Assigning Compliance Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_Android = Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CreateResult_Windows.id -TargetGroupId $TargetGroupId

Write-Host "Assigned '$AADGroup' to $($CreateResult_Windows.displayName)/$($CreateResult_Windows.id)"
Write-Host

####################################################

Write-Host "Adding Windows 10 Endpoint Protection Profile from JSON..." -ForegroundColor Yellow

$CreateResult_Endpoint = Add-DeviceConfigurationPolicy -JSON $windows_endpoint

Write-Host "Device Restriction Policy created as" $CreateResult_Endpoint.id
write-host
write-host "Assigning Windows 10 Endpoint Protection Profile to AAD Group '$AADGroup'" -f Cyan

$Assign_Endpoint = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_Endpoint.id -TargetGroupId $TargetGroupId

Write-Host "Assigned '$AADGroup' to $($CreateResult_Endpoint.displayName)/$($CreateResult_Endpoint.id)"
Write-Host




##################################################


##################################################################################

write-host "Publishing" ($JSON1 | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_Application = Add-MDMApplication -JSON $JSON1

Write-Host "Application created as $($Create_Application.displayName)/$($create_Application.id)"

$ApplicationId = $Create_Application.id

$Assign_Application = Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent "required"
Write-Host "Assigned '$AADGroup' to $($Create_Application.displayName)/$($Create_Application.id) with" $Assign_Application.InstallIntent "install Intent"

Write-Host

# Set parameter culture for script execution
$culture = "EN-US"

# Backup current culture
$OldCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
$OldUICulture = [System.Threading.Thread]::CurrentThread.CurrentUICulture


# Set new Culture for script execution 
[System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture


##################################################

write-host "Publishing" ($mac_OfficeApps | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_macApps = Add-MDMApplication -JSON $mac_OfficeApps

Write-Host "Application created as $($Create_macApps.displayName)/$($create_macApps.id)"

$ApplicationId = $Create_macApps.id

$Assign_Application = Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent "required"
Write-Host "Assigned '$AADGroup' to $($Create_Application.displayName)/$($Create_Application.id) with" $Assign_Application.InstallIntent "install Intent"

Write-Host

####################################################

$itunesApps = Get-itunesApplication -SearchString "Microsoft" -Limit 50

#region Office Example
$Applications = 'Microsoft Outlook','Microsoft Excel','OneDrive','Microsoft Authenticator', 'Microsoft Teams', 'Microsoft Word', 'Microsoft PowerPoint'
#endregion

# If application list is specified
if($Applications) {
    
    # Looping through applications list
    foreach($Application in $Applications){

    $itunesApp = $itunesApps.results | ? { ($_.trackName).contains("$Application") }

        # if single application count is greater than 1 loop through names
        if($itunesApp.count -gt 1){

        $itunesApp.count
        write-host "More than 1 application was found in the itunes store" -f Cyan

            foreach($iapp in $itunesApp){

            $Create_App = Add-iOSApplication -itunesApp $iApp

            $ApplicationId = $Create_App.id
            
            Write-Host "Creating Application"
            Write-Host
            Write-Host

            $Assign_App = Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent "required"
            Write-Host "Assigned '$AADGroup' to $($Create_App.displayName)/$($create_App.id) with" $Assign_App.InstallIntent "install Intent"

            Write-Host

            }

        }
        
        # Single application found, adding application
        elseif($itunesApp){

        $Create_App = Add-iOSApplication -itunesApp $itunesApp

        $ApplicationId = $Create_App.id

        Write-Host "Creating Application"
        Write-Host
        Write-Host

        $Assign_App = Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent "required"
        Write-Host "Assigned '$AADGroup' to $($Create_App.displayName)/$($create_App.id) with" $Assign_App.InstallIntent "install Intent"

        Write-Host
    
        }

        # if application isn't found in itunes returning doesn't exist
        else {

        write-host
        write-host "Application '$Application' doesn't exist" -f Red
        write-host

        }

    }

}

# No Applications have been specified
else {
    
    # if there are results returned from itunes query
    if($itunesApps.results){

    write-host
    write-host "Number of iOS applications to add:" $itunesApps.results.count -f Yellow
    Write-Host
        
        # Looping through applications returned from itunes
        foreach($itunesApp in $itunesApps.results){

        $Create_App = Add-iOSApplication -itunesApp $itunesApp

        $ApplicationId = $Create_App.id

        $Assign_App = Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent "required"
        Write-Host "Assigned '$AADGroup' to $($Create_App.displayName)/$($create_App.id) with" $Assign_App.InstallIntent "install Intent"

        Write-Host

        }

    }

    # No applications returned from itunes
    else {

    write-host
    write-host "No applications found..." -f Red
    write-host

    }

}


##################################################







Write-Host "Adding App Protection Policies to Intune..." -ForegroundColor Cyan
Write-Host

Write-Host "Adding iOS Managed App Policy from JSON..." -ForegroundColor Yellow
Write-Host "Creating Policy via Graph"

$CreateResult = Add-ManagedAppPolicy -Json $iOS
write-host "Policy created with id" $CreateResult.id

$MAM_PolicyID = $CreateResult.id

$Assign_Policy = Assign-ManagedAppPolicy -Id $MAM_PolicyID -TargetGroupId $TargetGroupId -OS iOS
Write-Host "Assigned '$AADGroup' to $($CreateResult.displayName)/$($CreateResult.id)"

Write-Host

write-host "Adding Android Managed App Policy from JSON..." -f Yellow
Write-Host "Creating Policy via Graph"

$CreateResult = Add-ManagedAppPolicy -Json $Android
write-host "Policy created with id" $CreateResult.id

$MAM_PolicyID = $CreateResult.id

$Assign_Policy = Assign-ManagedAppPolicy -Id $MAM_PolicyID -TargetGroupId $TargetGroupId -OS Android
Write-Host "Assigned '$AADGroup' to $($CreateResult.displayName)/$($CreateResult.id)"

Write-Host

####################################################

Write-Host "Adding Windows Information Protection Without Enrollment Policy from JSON..." -ForegroundColor Yellow

$CreateResult = Add-WindowsInformationProtectionPolicy -JSON $ManagedAppPolicy_WIP

write-host "Policy created with id" $CreateResult.id

$WIP_PolicyID = $CreateResult.id

$Assign_Policy = Assign-WindowsInformationProtectionPolicy -Id $WIP_PolicyID -TargetGroupId $TargetGroupId
Write-Host "Assigned '$AADGroup' to $($CreateResult.displayName)/$($CreateResult.id)"

Write-Host

Write-Host "Adding Windows Information Protection MDM Policy from JSON..." -ForegroundColor Yellow

$CreateResult = Add-MDMWindowsInformationProtectionPolicy -JSON $ManagedAppPolicy_WIP_MDM

write-host "Policy created with id" $CreateResult.id

$WIP_PolicyID = $CreateResult.id

$Assign_Policy = Assign-MDMWindowsInformationProtectionPolicy -Id $WIP_PolicyID -TargetGroupId $TargetGroupId
Write-Host "Assigned '$AADGroup' to $($CreateResult.displayName)/$($CreateResult.id)"

Write-Host

##############################################################

write-host "Publishing Android" ($MicrosoftAuthenticator | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_MicrosoftAuthenticator = Add-AndroidApplication -JSON $MicrosoftAuthenticator

Write-Host "Application created as $($Create_MicrosoftAuthenticator.displayName)/$($create_MicrosoftAuthenticator.id)"
Write-Host


        $ApplicationId1 = $Create_MicrosoftAuthenticator.id

        $Assign_App1 = Add-ApplicationAssignment -ApplicationId $ApplicationId1 -TargetGroupId $TargetGroupId -InstallIntent "Required"
        Write-Host "Assigned '$AADGroup' to $($Create_App1.displayName)/$($create_App1.id) with" $Assign_App1.InstallIntent "install Intent"

        Write-Host
        Write-Host
        Write-Host
        Write-Host



##################################################

write-host "Publishing Android" ($Outlook | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_Outlook = Add-AndroidApplication -JSON $Outlook 

Write-Host "Application created as $($Create_Outlook.displayName)/$($create_Outlook.id)"
Write-Host


        $ApplicationId1 = $Create_Outlook.id

        $Assign_App1 = Add-ApplicationAssignment -ApplicationId $ApplicationId1 -TargetGroupId $TargetGroupId -InstallIntent "Required"
        Write-Host "Assigned '$AADGroup' to $($Create_Outlook.displayName)/$($create_Outlook.id) with" $Assign_App1.InstallIntent "install Intent"

        Write-Host
        Write-Host
        Write-Host
        Write-Host


##################################################

write-host "Publishing Android" ($Word| ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_Word = Add-AndroidApplication -JSON $Word

Write-Host "Application created as $($Create_Word.displayName)/$($create_Word.id)"
Write-Host

        $ApplicationId1 = $Create_Word.id

        $Assign_App1 = Add-ApplicationAssignment -ApplicationId $ApplicationId1 -TargetGroupId $TargetGroupId -InstallIntent "Required"
        Write-Host "Assigned '$AADGroup' to $($Create_App1.displayName)/$($create_App1.id) with" $Assign_App1.InstallIntent "install Intent"

        Write-Host
        Write-Host
        Write-Host
        Write-Host

##################################################

write-host "Publishing Android" ($Excel | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_Excel = Add-AndroidApplication -JSON $Excel 
Write-Host "Application created as $($Create_Excel.displayName)/$($create_Excel.id)"
Write-Host

        $ApplicationId1 = $Create_Excel.id

        $Assign_App1 = Add-ApplicationAssignment -ApplicationId $ApplicationId1 -TargetGroupId $TargetGroupId -InstallIntent "Required"
        Write-Host "Assigned '$AADGroup' to $($Create_App1.displayName)/$($create_App1.id) with" $Assign_App1.InstallIntent "install Intent"

        Write-Host
        Write-Host
        Write-Host
        Write-Host


##################################################

write-host "Publishing Android" ($Teams | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_Teams = Add-AndroidApplication -JSON $Teams 

Write-Host "Application created as $($Create_Teams.displayName)/$($create_Teams.id)"
Write-Host

        $ApplicationId1 = $Create_Teams.id

        $Assign_App1 = Add-ApplicationAssignment -ApplicationId $ApplicationId1 -TargetGroupId $TargetGroupId -InstallIntent "Required"
        Write-Host "Assigned '$AADGroup' to $($Create_App1.displayName)/$($create_App1.id) with" $Assign_App1.InstallIntent "install Intent"

        Write-Host
        Write-Host
        Write-Host
        Write-Host

##################################################

write-host "Publishing Android" ($OneDrive | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_OneDrive = Add-AndroidApplication -JSON $OneDrive 

Write-Host "Application created as $($Create_OneDrive.displayName)/$($create_OneDrive.id)"
Write-Host

        $ApplicationId1 = $Create_OneDrive.id

        $Assign_App1 = Add-ApplicationAssignment -ApplicationId $ApplicationId1 -TargetGroupId $TargetGroupId -InstallIntent "Required"
        Write-Host "Assigned '$AADGroup' to $($Create_App1.displayName)/$($create_App1.id) with" $Assign_App1.InstallIntent "install Intent"

        Write-Host
        Write-Host
        Write-Host
        Write-Host

##################################################

write-host "Publishing Android" ($PowerPoint | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_PowerPoint = Add-AndroidApplication -JSON $PowerPoint 

Write-Host "Application created as $($Create_PowerPoint.displayName)/$($create_PowerPoint.id)"
Write-Host

        $ApplicationId1 = $Create_PowerPoint.id

        $Assign_App1 = Add-ApplicationAssignment -ApplicationId $ApplicationId1 -TargetGroupId $TargetGroupId -InstallIntent "Required"
        Write-Host "Assigned '$AADGroup' to $($Create_App1.displayName)/$($create_App1.id) with" $Assign_App1.InstallIntent "install Intent"

        Write-Host
        Write-Host
        Write-Host

$block = @"
   .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  . 
  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .     
    .       .       .       .       .       .       .       .       .       .       .       .       .       .       .       .       .       .       .       .       .       .       .       .       . . 
  .   . .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .  ...::;tSXX@8X8X8XXXX%%;::... .   .::. .    . .    .  .    .  .    .  .    .  .    .  .    .  .    .  .       
    .     .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .    .:tS8XX88:8 8 888888@8X8S8@8@XSt:.:;::888t  .      .    .  .    .  .    .  .    .  .    .  .    .  .    .  . .  .
  .    .   .       .       .       .       .       .       .       .       .     .:%@88@8@@8S:8 8888;S%;:..:::t;;..:::;.:88@S@8:8:@%:. .   .       .       .       .       .       .       .            
     .   .   .  .    .  .    .  .    .  .    .  .    .  .    .  .    .  .   .;S888:8X@888S; :t;;t:            .. .        :t8@:.88.;t:8:.    .  .    .  .    .  .    .  .    .  .    .  .    .  .  . .  
  .    .      .   .   .   .   .   .   .   .   .   .   .   .   .   .   . .;8X8:X8 88S.;St:   .:  .  . .  .  .  ..   . .     t88888@.@88.X8  .   .  .   .   .   .   .   .   .   .   .   .   .   .   .    .
    .     . .   .   .   .   .   .   .   .   .   .   .   .   .   .   . :SX.;:S88;t;     .  .  ..  .             . .     .   .;: ..  t8888:           .   .   .   .  .:;tttt;:.   .   .   .   .   .    .  
  .   .           .       .       .       .       .       .       ..%8.88XS8%;.     .         .   .  . . . . . .    .    .    ...   :;;. .  .  .  .       .   .:%8@8X. ;t;@@8:@t.         .        .    
    .   . .  . .     . .     . .     . .     . .     . .     . ..S@:8 %88;:      .    . .  .   .               .. .   .    .              .      .   . .   .t88;t::;: %S88.;: ;;8;t.  .      . .  .   . 
  .         .    .       .       .       .       .       .    .%@.tt 8; :.  .  .   .        .   .  . .  .  .    .       .    .  .   . . .    . .:;t%t;:  .:8.;; S: SS8;8 . SS8;%;.X8.  . .  .       .   
     . .  .    .   . .     . .     . .     . .     . .     ..S@.t8%@;..   .      .   .  . .   .              .  .  . .    .       .        ..;8@8:8 8X@XX8S:S; ;8.S8:ttt;.%.%t8;8;8  :         . .     .
  .          .         . .     . .     . .     . .     . .:8X8 8@X;. .. .   . .    .        .   . .  . . . .   . .     .    . . .    .  . .%8 ;:t:88 t:8 :%;8 ..8;8.SS8;8.;%.%t%t%;;.X@  .  .      .  . 
    .  . . .    . .  .     .       .       .       .    .t88 :8;   .      .     .     .  .                   .    .  .   .         .     .X ;: S;.t8:8 ;%.t:%;.%t8 SS8.%t8.;%:SS8;8;t. .      .  .      
  .           .        .     . .     . .     . .     . :8.;; :.   . . .    .  .   . .   .   . .  . . .  .  .    .      .   .  .  .   . . S %t:%:8;8 t:%t;S8;8 %S8 SS8 SS8.St;S8:8.tS:888. .    .    .  .
    . .  .  .    . . .   .  .    .  .    .  .    .  .:8.%%X8t .      .  .       .     .   .                   .   . .    .         .    ;8;S8.;t t;SS8;8;8.t;SS8 SS.tt.%;SS. tt%;S%  ;  .   .     .   . 
  .       .   .           .    .   .   .   .   .   .X:t%SX..    . .       . .      .        .  . .  . .  .  .   .     .     . . .     . @X8.8:.88:8;8.%t8 SS8;%;St;t :%.SS;:SS8;8;8;8t;S   .    .   .   
     . .        .  .  . .    .   .       .       ..8:S%.; .  .      . .      . .     .  .     .         .     .   . .   .  .      .  .;%X8:tt; 8 tt%tSS8 SS8.SS8;8.:S:88;8;8;8.%t%t8.8.XX    .    .     
  .     :SXXXXXXSXXSXXS;  .    .   :%St:    . .  :8 S8;: .;XXt. . :SX%: .  .  .tXXt.  .%XX;.     ..;XXt.  . .:%@888X;:        .  .:@@8 ..%t.SS8 %S8;8;8 S% t;.tt8@8:;.8 %t8.tt8;8;8 %tt @.@:.  .     .  
    .  .8@  S S X S S %;:   .     .S8:%8X.     .%8:%@8.  ;:   %  .88:%tX.     ;   :;  t; St:.  .  ::   %   tt8   S %X8:X. .    .%@ ::t; S;S::::::;:::8 St;; S8;: ;:XX8 S.8;tt;t;tt;;;S.;   8St.  .  .  .
  .   . @ ;:;:8S 8t:;t;8..    .  .:S.X t8S .  .;88 X %;. ;;S: %  .8X  %@@ .  .;  % ;. %;  %:      ;;S :t .;   8 X%:X  88.   . .@ t;.St:S:t88888X8@;:tt8;.8 S%:;8S88:t8.t.S;8.%888888888t%%8  :%:        
    .   .:;::t:  ;S;:;:..  .      :%@%X:t8S.  %8.;SX8.;  ;:   S  .8@ X  @8;   ;   .;  tt X;: .  . ::  :t  @8 8@;..:;@%8:  .  .8.St:S:8:;S .     @8;S88.8::%;;8@888  S SS8t;;:8@88    .8;8:;%;8.X8. .  . 
  .        . ;;S ;%          . .  .% :   t@8:X.%@; ; S:  ;:S ;t ..8@ 8:@  .S. ;   :; .t;  S:      ;;% :t .X8  :@S;..  . .   .@.SS8:;%8: :S: 8;8:t@888. tt @:88 888X;%: %t88@.8 888 8;8 %t8;;:8::88:     
     . . .   ;:  ;%  . .;t;t;t;:. .S@;S%% t:: %@X%S %%: .;:   %  .8@ 8X@@  tS.;  % ;  %; St;  .   ;:  .t  :S@   8X:%@;      :8;S8.8.:;.S.88 tSS.:8@8.8%t 8S;8 8;:;;X@88;%t88.Xt: ::8X88;%t8;%tt :XX .   
  .        . ;;S ;%    @S888888;; .%  %%;; t.S@.:;t.%t.  ;;%  %  .8@.88.@%  S8t   :;  tt  S:   .  :;S :%   :8:S8S   X8;%. . %8;8:8;8;8;;..88. S%tXXt8 %S;t :%S888S8t:X@;S%  X@88888;;X SS8.8;t::  8;  . 
    .  .     ;;  ;%  . S:@SSX@X%; .S@ S%.:8@%88; tt.%%:  ;:   %. .8@ 88. :X8 X.:% :t  t; S:; .   .:    t  .   .:tS8:8  %S   %88..%%t8.8t; ;t;   8@8SX@88.t..8@88888X:t8 8;;       88:S. tt%t8;t.: X     
  .     . .  ;;S ;%    .:::::::. ..S% S% .;888t  tt.%t.. ;:S :%  .8X 8@   .88  @ S ; .;:  %X      SS St:   ;t.   .. 88 @8   %X S: 8:tt8: SS. %%8 : 8tS8 ; ..88 ;;8 8%.888;8:8.8.88 XX:S8t.8:tS.8.::t..  
    . .      ;:  ;%  .            .%S S%  :;t;   tt.%%:  ;:   %  .8@ 88.   :8@ S % ;   @X  ;@%t;S8S  %@ ..8S8:8X;;;S:S @X . :S:t:%tS;:;:%@.8.S.;8; 8.8S.;S8:XS %8 8@.:88.8t8X8 t:8X8;t88.%t%:;.8  8X.   
  .      .  .::  t%    .  . . . . .%  S%     .  .t%. %.  ;:  :%  .8X.88  .  .;t@  .t  . %.8  SXX  S8.%.  .8.8  XX@@  X%8.    t@.S%8.8;8.:X:%t  %%%S;88 % . :%  ;X8.:X88..XX8S: 8%tt%@@8:: 8 %S8.:88:  . 
     .    .  .X@S8;  .            .%@%8:  . . .  .8%XX. ..X@S8:  .%X%@t       .X@S8.    . ;@X:.:%X8t.      .:t8t:.:S8%.   .   %8@8:%t8.8:. 8 8@S%8888:.88:: 888XSS888.%8;; 8X8St8:@888.8 t;%:%;tX8t .   
  .    .        .  .    .  .  .  .               ..          .  .        .  .   .   .    .             .     ..       .    .  .;88:S8.%t8;t;;.     :%:8 ;S.8:.     t%%.tS. ;:   @88 :. tS8:;S8;X:;   .  
    .   .  . .   .    .   .        .    .  . . .     .   .    .    .   .              .    .  . .  .     .       .      .    . ..:S.t%:%t8;8;SS8.%%8  ;8t;.%t.S%8:8;t;SS;.t.St ;;8 SS8;8:tS:8X 8:  .    
  .   .        .    .   .   .  . .    .   .       .    .   .     .   .    .  .  .  .    .            . .   .  .    .  .   .   . . t :;8.8;%t.S8 SS8.8;%t8;8.;t.%;%t8tSS8;t;St:t:t;SS.8:8.8@.8@:.     .  
    .    . .      .           .     .   .    . .    .        .          .     .      .    . .  . . .     .     .    .   .   .     ...;:%8X8@:8X;%.X X8@8X:X8X %X 8@:X;X.Xt 8@::@: 8@XX888@;:.    .    . 
  .    .     .  .    . . . .     .         .    .    .  . .    .  . .     . .    .     .             .     . .   .    .        .   . . :;.;%tSS XXX %:S;t %:: X8SXS X@S %X:%Xt:@t%S.t%t:...  .  .  .    
     .    .   .    .         .  .  . .  .     .   .         .         .        .   . .   .  . .  .     . .     .   .     .  .   .    .       ..  .     .       :..       :   ...     :     .         .  
  .    .    .    .   .  .  .              .        .  .  .    .  .  .   .  .     .     .       .   . .     .     .   .  .     .   .    . . . ..     .          ..       ... .   .  . ..  .    .  . .   .
"@
 
Write-Host $block -ForegroundColor Cyan
     
     
     
                           
