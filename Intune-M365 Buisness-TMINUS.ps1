<#
.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.
#>

<#
.SYNOPSIS

This script is specific to the M365 Business Sku

After you run this script, you will have

1.	A device compliance policy for:
	 iOS (Configure line 1506)
     Android (Configure line 1481)
     Windows(Configure line 1528)
2.	A device configuration policy for Windows Devices to have BitLocker(Configure line 1553)
3.	Terms and Conditions for when users enroll(Configure line 1572)
4.	Office 365 Business pushed out as a required App to window 10 devices(Configure line 1583)
5.	Microsoft Authenticator pushed out as a required App for iOS and Android devices(Configure line 1619)

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

        $iTunesUrl = "https://itunes.apple.com/search?entity=software&term=$SearchString&attribute=softwareDeveloper&limit=$limit"
    
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

    $JSON2 = ConvertTo-Json $graphApp

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

$JSON2 = @"
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
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON2 -ContentType "application/json"

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

$graphApiVersion = "v1.0"
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

$graphApiVersion = "v1.0"
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

$JSON_Android = @"
    {
    "passwordExpirationDays": 90,
    "requireAppVerify":  true,
    "securityPreventInstallAppsFromUnknownSources":  true,
    "@odata.type":  "microsoft.graph.androidCompliancePolicy",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "passwordRequiredType":  "numeric",
    "storageRequireEncryption":  true,
    "storageRequireRemovableStorageEncryption":  true,
    "passwordMinutesOfInactivityBeforeLock":  15,
    "passwordPreviousPasswordBlockCount":  8,
    "passwordRequired":  true,
    "description":  "Android Compliance Policy",
    "passwordMinimumLength":  4,
    "displayName":  "Android Compliance Policy",
    "securityBlockJailbrokenDevices":  true,
    "deviceThreatProtectionRequiredSecurityLevel":  "Low",
    "deviceThreatProtectionEnabled":  true,
    "securityDisableUsbDebugging":  true
    }
"@

####################################################

$JSON_iOS = @"
  {
  "@odata.type": "microsoft.graph.iosCompliancePolicy",
  "description": "iOS Compliance Policy",
  "displayName": "iOS Compliance Policy",
  "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
  "passcodeBlockSimple": true,
  "passcodeExpirationDays": 90,
  "passcodeMinimumLength": 4,
  "passcodeMinutesOfInactivityBeforeLock": 15,
  "passcodePreviousPasscodeBlockCount": 8,
  "passcodeMinimumCharacterSetCount": null,
  "passcodeRequiredType": "numeric",
  "passcodeRequired": true,
  "securityBlockJailbrokenDevices": true,
  "deviceThreatProtectionEnabled": true,
  "deviceThreatProtectionRequiredSecurityLevel": "Low"
  }
"@

###############################

$JSON_Windows = @"
  {
  "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
  "description": "Windows 10 Compliance Policy",
  "displayName": "Windows 10 Compliance Policy",
  "version": 7,
  "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
  "passwordRequired": true,
  "passwordBlockSimple": true,
  "passwordRequiredToUnlockFromIdle": true,
  "passwordMinutesOfInactivityBeforeLock": 15,
  "passwordExpirationDays": 90,
  "passwordMinimumLength": 8,
  "passwordMinimumCharacterSetCount": 0,
  "passwordRequiredType": "alphanumeric",
  "passwordPreviousPasswordBlockCount": 6,
  "requireHealthyDeviceReport": false,
  "earlyLaunchAntiMalwareDriverEnabled": true,
  "bitLockerEnabled": true,
  "secureBootEnabled": false,
  "codeIntegrityEnabled": false,
  "storageRequireEncryption": true
}
"@

$Windows = @"
{
  "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
  "description": "Bitlocker1",
  "displayName": "BitLocker Device Policy",
  "version": 7,
  "omaSettings": [
    {
      "@odata.type": "microsoft.graph.omaSettingInteger",
      "displayName": "BitLocker1",
      "description": "Description value",
      "omaUri": "./Device/Vendor/MSFT/BitLocker/RequireDeviceEncryption",
      "value": 1
    }
  ]
}

"@

$JSON = @"
{
    "@odata.type": "#microsoft.graph.termsAndConditions",
    "displayName":"Customer Terms and Conditions",
    "title":"Terms and Conditions",
    "description":"By enrolling your device, you agree to <Company X> terms and conditions",
    "bodyText":"I acknowledge that by enrolling my device, <Company X> Administrators have certain types of control. This includes visibility into corporate app inventory, email usage, and device risk. I further agree to keep company resources safe to the best of my ability and inform <Company X>  administrators as soon as I believe my device is lost or stolen",
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

$JSON4 = @"
{
  "@odata.type": "#microsoft.graph.officeSuiteApp",
  "autoAcceptEula": true,
  "description": "Office 365 ProPlus - Assigned",
  "developer": "Microsoft",
  "displayName": "Office 365 ProPlus - Assigned",
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
    "o365ProPlusRetail",
    "projectProRetail",
    "visioProRetail"
  ],
  "publisher": "Microsoft",
  "updateChannel": "firstReleaseCurrent",
  "useSharedComputerActivation": false
}
"@




####################################################

# Setting application AAD Group

$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where policies will be assigned."

$TargetGroupId = (get-AADGroup -GroupName "$AADGroup").id

    if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$AADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

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

Write-Host "Adding Android Compliance Policy from JSON..." -ForegroundColor Yellow

$CreateResult_Android = Add-DeviceCompliancePolicy -JSON $JSON_Android

Write-Host "Compliance Policy created as" $CreateResult_Android.id
write-host
write-host "Assigning Compliance Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_Android = Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CreateResult_Android.id -TargetGroupId $TargetGroupId

Write-Host "Assigned '$AADGroup' to $($CreateResult_Android.displayName)/$($CreateResult_Android.id)"
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

#####################################################

Write-Host "Adding Windows Device Restriction Policy from JSON..." -ForegroundColor Yellow

$CreateResult_Windows = Add-DeviceConfigurationPolicy -JSON $Windows

Write-Host "Device Restriction Policy created as" $CreateResult_Windows.id
write-host
write-host "Assigning Device Restriction Policy to AAD Group '$AADGroup'" -f Cyan

$Assign_Windows = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_Windows.id -TargetGroupId $TargetGroupId

Write-Host "Assigned '$AADGroup' to $($CreateResult_Windows.displayName)/$($CreateResult_Windows.id)"
Write-Host



##################################################

write-host "Publishing" ($JSON4 | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_Application2 = Add-MDMApplication -JSON $JSON4

Write-Host "Application created as $($Create_Application2.displayName)/$($create_Application2.id)"

$ApplicationId2 = $Create_Application2.id

$Assign_Application2 = Add-ApplicationAssignment -ApplicationId $ApplicationId2 -TargetGroupId $TargetGroupId -InstallIntent "uninstall"
Write-Host "Assigned '$AADGroup' to $($Create_Application2.displayName)/$($Create_Application2.id) with" $Assign_Application2.InstallIntent "install Intent"

Write-Host

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

####################################################

$itunesApps = Get-itunesApplication -SearchString "Microsoft Corporation" -Limit 50

#region Office Example
$Applications = 'Microsoft Authenticator'
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

            $Assign_App = Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent "required"
            Write-Host "Assigned '$AADGroup' to $($Create_App.displayName)/$($create_App.id) with" $Assign_App.InstallIntent "install Intent"

            Write-Host

            }

        }
        
        # Single application found, adding application
        elseif($itunesApp){

        $Create_App = Add-iOSApplication -itunesApp $itunesApp

        $ApplicationId = $Create_App.id

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
#Restore culture from backup
[System.Threading.Thread]::CurrentThread.CurrentCulture = $OldCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $OldUICulture


##################################################

write-host "Publishing" ($MicrosoftAuthenticator | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_App1 = Add-AndroidApplication -JSON $MicrosoftAuthenticator

Write-Host "Application created as $($Create_MicrosoftAuthenticator.displayName)/$($create_MicrosoftAuthenticator.id)"
Write-Host


        $ApplicationId1 = $Create_App1.id

        $Assign_App1 = Add-ApplicationAssignment -ApplicationId $ApplicationId1 -TargetGroupId $TargetGroupId -InstallIntent "available"
        Write-Host "Assigned '$AADGroup' to $($Create_App1.displayName)/$($create_App1.id) with" $Assign_App1.InstallIntent "install Intent"

        Write-Host

     
     
     
                           