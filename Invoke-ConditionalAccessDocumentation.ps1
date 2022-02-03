<#PSScriptInfo

.VERSION 1.5.0

.GUID 6c861af7-d12e-4ea2-b5dc-56fee16e0107

.AUTHOR Nicola Suter

.TAGS ConditionalAccess, AzureAD, Identity

.PROJECTURI https://github.com/nicolonsky/ConditionalAccessDocumentation

.ICONURI https://raw.githubusercontent.com/microsoftgraph/g-raph/master/g-raph.png

.DESCRIPTION This script documents Azure AD Conditional Access Policies.

.SYNOPSIS This script retrieves all Conditional Access Policies and translates Azure AD Object IDs to display names for users, groups, directory roles, locations...

.EXAMPLE
    Connect-Graph -Scopes "Application.Read.All", "Group.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "User.Read.All"
    & .\Invoke-ConditionalAccessDocumentation.ps1
    Generates the documentation and exports the csv to the script directory.
.NOTES
    Author:           Nicola Suter
    Creation Date:    31.01.2022
#>

#Requires -Module @{ ModuleName = 'Microsoft.Graph.Identity.SignIns'; ModuleVersion = '1.9.2'}, @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '1.9.2'}, @{ ModuleName = 'Microsoft.Graph.Users'; ModuleVersion = '1.9.2'}, @{ ModuleName = 'Microsoft.Graph.Identity.DirectoryManagement'; ModuleVersion = '1.9.2'}, @{ ModuleName = 'Microsoft.Graph.Groups'; ModuleVersion = '1.9.2'}, @{ ModuleName = 'Microsoft.Graph.Applications'; ModuleVersion = '1.9.2'}


[CmdletBinding()]
param (
    # Sanitize potentially long list of included/excluded directory roles to either "all" or individual roles
    [Parameter(Mandatory = $false)]
    [switch]
    $SanitizeDirectoryRoles
)

function Test-Guid {
    <#
    .SYNOPSIS
    Validates a given input string and checks string is a valid GUID
    .DESCRIPTION
    Validates a given input string and checks string is a valid GUID by using the .NET method Guid.TryParse
    .EXAMPLE
    Test-Guid -InputObject "3363e9e1-00d8-45a1-9c0c-b93ee03f8c13"
    .NOTES
    Uses .NET method [guid]::TryParse()
    #>
    [Cmdletbinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyString()]
        [string]$InputObject
    )
    process {
        return [guid]::TryParse($InputObject, $([ref][guid]::Empty))
    }
}

if (-not $(Get-MgContext)) {
    Throw "Authentication needed, call 'Connect-Graph -Scopes `"Application.Read.All`", `"Group.Read.All`", `"Policy.Read.All`", `"RoleManagement.Read.Directory`", `"User.Read.All`""
}

# Get Conditional Access Policies
$conditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
#Get Conditional Access Named / Trusted Locations
$namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop
# Get Azure AD Directory Role Templates
$directoryRoleTemplates = Get-MgDirectoryRoleTemplate -ErrorAction Stop
# Get Azure AD Service Principals
$servicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop
# Init report
$conditionalAccessDocumentation = [System.Collections.ArrayList]::new()

if ($SanitizeDirectoryRoles.IsPresent) {
    # Get-MgDirectoryRole only returns enabled admin roles in tenant
    $assignedAdminRoles = Get-MgDirectoryRole -All  
}

# Process all Conditional Access Policies
foreach ($policy in $conditionalAccessPolicies) {

    # Display some progress (based on policy count)
    $currentIndex = $conditionalAccessPolicies.indexOf($policy)
    Write-Progress -Activity "Generating Conditional Access Documentation..." -PercentComplete (($currentIndex + 1) / $conditionalAccessPolicies.Count * 100) `
        -CurrentOperation "Processing Policy '$($policy.DisplayName)' ($currentIndex/$($conditionalAccessPolicies.Count))"

    try {
        # Resolve object IDs of included users
        $includeUsers = [System.Collections.ArrayList]::new()
        $policy.Conditions.Users.IncludeUsers | ForEach-Object {
            if (Test-Guid $PSItem) {
                $includeUsers.Add( $(Get-MgUser -userId $PSItem | Select-Object -ExpandProperty DisplayName -ErrorAction Stop)) | Out-Null
            }
            else {
                $includeUsers.Add($PSItem) | Out-Null
            }
        }
        # Resolve object IDs of excluded users
        $excludeUsers = [System.Collections.ArrayList]::new()
        $policy.Conditions.Users.ExcludeUsers | ForEach-Object {
            if (Test-Guid $PSItem) {
                $excludeUsers.Add($(Get-MgUser -userId $PSItem | Select-Object -ExpandProperty DisplayName -ErrorAction Stop)) | Out-Null
            }
            else {
                $excludeUsers.Add($PSItem) | Out-Null
            }
        }
        # Resolve object IDs of included groups
        $includeGroups = [System.Collections.ArrayList]::new()
        $policy.Conditions.Users.IncludeGroups | ForEach-Object {
            $includeGroups.Add($(Get-MgGroup -GroupId $PSItem | Select-Object -ExpandProperty DisplayName)) | Out-Null
        }
        # Resolve object IDs of excluded groups
        $excludeGroups = [System.Collections.ArrayList]::new()
        $policy.Conditions.Users.ExcludeGroups | ForEach-Object {
            $excludeGroups.Add( $(Get-MgGroup -GroupId $PSItem | Select-Object -ExpandProperty DisplayName)) | Out-Null
        }
        # Resolve object IDs of included roles
        $includeRoles = [System.Collections.ArrayList]::new()
        $policy.Conditions.Users.IncludeRoles | ForEach-Object {
            $roleId = $PSItem
            $includeRoles.Add( $($directoryRoleTemplates | Where-Object { $PSItem.Id -eq $roleId } | Select-Object -ExpandProperty DisplayName)) | Out-Null
        }

        if ($policy.Conditions.Users.IncludeRoles.Length -gt 0 -and $SanitizeDirectoryRoles.IsPresent) {

            [array]$missingRoles = @($assignedAdminRoles | Where-Object { $policy.Conditions.Users.IncludeRoles -notcontains $_.RoleTemplateId } | Select-Object -ExpandProperty DisplayName)
            
            $includeRoles.Clear() | Out-Null

            if (-not $missingRoles) {
                $includeRoles.Add("All assigned directory roles covered") | Out-Null
            }
            else {
                $includeRoles.Add("All except: ") | Out-Null
                $includeRoles.AddRange($missingRoles) | Out-Null
            }
        }

        # Resolve object IDs of excluded roles
        $excludeRoles = [System.Collections.ArrayList]::new()
        $policy.Conditions.Users.ExcludeRoles | ForEach-Object {
            $roleId = $PSItem
            $excludeRoles.Add( $($directoryRoleTemplates | Where-Object { $PSItem.Id -eq $roleId } | Select-Object -ExpandProperty DisplayName )) | Out-Null
        }

        if ($policy.Conditions.Users.ExcludeRoles.Length -gt 0 -and $SanitizeDirectoryRoles.IsPresent) {

            [array]$missingRoles = @($assignedAdminRoles | Where-Object { $policy.Conditions.Users.ExcludeRoles -notcontains $_.RoleTemplateId } | Select-Object -ExpandProperty DisplayName)
            
            $excludeRoles.Clear() | Out-Null

            if (-not $missingRoles) {
                $excludeRoles.Add("All assigned directory roles covered") | Out-Null
            }
            else {
                $excludeRoles.Add("All except: ") | Out-Null
                $excludeRoles.AddRange($missingRoles) | Out-Null
            }
        }
        # Resolve object IDs of included apps
        $includeApps = [System.Collections.ArrayList]::new()
        $policy.Conditions.Applications.IncludeApplications | ForEach-Object {
            $servicePrincipalId = $PSItem
            if (Test-Guid $PSItem) {
                $res = $servicePrincipals | Where-Object { $PSItem.AppId -eq $servicePrincipalId } | Select-Object -ExpandProperty DisplayName
                if ($null -ne $res) {
                    $includeApps.Add($res) | Out-Null
                }
                else {
                    $includeApps.Add($servicePrincipalId) | Out-Null
                }
            }
            else {
                $includeApps.Add($servicePrincipalId) | Out-Null
            }
        }
        # Resolve object IDs of excluded apps
        $excludeApps = [System.Collections.ArrayList]::new()
        $policy.Conditions.Applications.ExcludeApplications | ForEach-Object {
            $servicePrincipalId = $PSItem
            if (Test-Guid $PSItem) {
                $res = $servicePrincipals | Where-Object { $PSItem.AppId -eq $servicePrincipalId } | Select-Object -ExpandProperty DisplayName
                if ($null -ne $res) {
                    $excludeApps.Add($res) | Out-Null
                }
                else {
                    $excludeApps.Add($servicePrincipalId) | Out-Null
                }
            }
            else {
                $excludeApps.Add($servicePrincipalId) | Out-Null
            }
        }
        # Resolve object IDs of included locations
        $includeLocations = [System.Collections.ArrayList]::new()
        $policy.Conditions.Locations.IncludeLocations | ForEach-Object {
            $locationId = $PSItem
            if (Test-Guid $PSItem) {
                $includeLocations.Add( $($namedLocations | Where-Object { $PSItem.Id -eq $locationId } | Select-Object -ExpandProperty DisplayName)) | Out-Null
            }
            else {
                $includeLocations.Add($locationId) | Out-Null
            }
        }
        # Resolve object IDs of excluded locations
        $excludeLocations = [System.Collections.ArrayList]::new()
        $policy.Conditions.Locations.ExcludeLocations | ForEach-Object {
            $locationId = $PSItem
            if (Test-Guid $PSItem) {
                $excludeLocations.Add( $($namedLocations | Where-Object { $PSItem.Id -eq $locationId } | Select-Object -ExpandProperty DisplayName)) | Out-Null
            }
            else {
                $excludeLocations.Add($locationId) | Out-Null
            }
        }

        # Check for TOUs
        if ($policy.GrantControls.TermsOfUse) { $policy.GrantControls.BuiltInControls += "TermsOfUse" }

        # delimiter for arrays in csv report
        $separator = "`r`n"
        $conditionalAccessDocumentation.Add(
            [PSCustomObject]@{
                Name                            = $policy.DisplayName
                State                           = $policy.State

                IncludeUsers                    = $includeUsers -join $separator
                IncludeGroups                   = $includeGroups -join $separator
                IncludeRoles                    = $includeRoles -join $separator

                ExcludeUsers                    = $excludeUsers -join $separator
                ExcludeGroups                   = $excludeGroups -join $separator
                ExcludeRoles                    = $excludeRoles -join $separator

                IncludeApps                     = $includeApps -join $separator
                ExcludeApps                     = $excludeApps -join $separator

                IncludeUserActions              = $policy.Conditions.Applications.IncludeUserActions -join $separator
                ClientAppTypes                  = $policy.Conditions.ClientAppTypes -join $separator

                IncludePlatforms                = $policy.Conditions.Platforms.IncludePlatforms -join $separator
                ExcludePlatforms                = $policy.Conditions.Platforms.ExcludePlatforms -join $separator

                IncludeLocations                = $includeLocations -join $separator
                ExcludeLocations                = $excludeLocations -join $separator

                IncludeDeviceStates             = $policy.Conditions.Devices.IncludeDeviceStates -join $separator
                ExcludeDeviceStates             = $policy.Conditions.Devices.ExcludeDeviceStates -join $separator

                GrantControls                   = $policy.GrantControls.BuiltInControls -join $separator
                GrantControlsOperator           = $policy.GrantControls.Operator

                SignInRiskLevels                = $policy.Conditions.SignInRiskLevels -join $separator
                UserRiskLevels                  = $policy.Conditions.UserRiskLevels -join $separator

                ApplicationEnforcedRestrictions = $policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
                CloudAppSecurity                = $policy.SessionControls.CloudAppSecurity.IsEnabled
                PersistentBrowser               = $policy.SessionControls.PersistentBrowser.Mode
                SignInFrequency                 = "$($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type)"
            }
        ) | Out-Null
    }
    catch {
        Write-Error $PSItem
    }
}

# Build export path (script directory)
$exportPath = Join-Path $PSScriptRoot "ConditionalAccessDocumentation.csv"
# Export report as csv
$conditionalAccessDocumentation | Export-Csv -Path $exportPath -NoTypeInformation

Write-Output "Exported Documentation to '$($exportPath)'"
