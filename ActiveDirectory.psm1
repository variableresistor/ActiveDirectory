using namespace System.Collections.Generic
using namespace System.Text

class ADUser
{
    [string]$DistinguishedName # distinguishedname
    [System.Nullable[boolean]]$Enabled
    [string]$GivenName # givenname
    [string]$Name # name
    [string[]]$ObjectClass # objectclass
    [string]$SamAccountName # samaccountname
    [string]$Surname # sn
    [string]$UserPrincipalName # userprincipalname

    # Optional properties
    [string]$DisplayName # displayname
    [datetime]$Modified # whenchanged
    [datetime]$LastLogonDate # [Int64]lastlogon
    [string]$Manager # manager
    [string]$EmployeeID # employeeid
    [string]$adspath
    [int]$BadLogonCount # badpwdcount
    [string]$Info
    [datetime]$LastBadPasswordAttempt # [uint64]$badpasswordtime
    [string]$EmailAddress # mail
    [datetime]$Created # [datetime]whencreated
    [string]$State # st
    [string]$CountryCode
    [datetime]$PasswordLastSet # [UInt64]pwdlastset
    [System.Nullable[bool]]$LockedOut
    [System.Nullable[int]]$lockouttime
    [string]$Department # department
    [string]$StreetAddress # streetaddress
    [datetime]$AccountExpirationDate # [Int64]accountexpires
    [string[]]$MemberOf # memberof
    [string]$targetaddress
    [string]$Description # description
    [string]$Company # company
    [string]$Title # title
    [string]$proxyaddresses
    [string]$ObjectCategory # objectcategory
    [string]$CN # cn
    [string]$City # l
    [string]$Office # physicaldeliveryofficename
    [string]$PostalCode # postalcode
}

# Just add the most common properties. This isn't an exhaustive list.
enum ADUserEnum
{
    DisplayName
    Modified
    LastLogonDate
    Manager
    EmployeeID
    adspath
    BadLogonCount
    Info
    LastBadPasswordAttempt
    EmailAddress
    Created
    State
    CountryCode
    PasswordLastSet
    LockedOut
    lockouttime
    Department
    StreetAddress
    AccountExpirationDate
    MemberOf
    targetaddress
    Description
    Company
    Title
    proxyaddresses
    ObjectCategory
    CN
    City
    Office
    PostalCode
    GivenName
    Surname
}

class ADGroup
{
    [string]$DistinguishedName # distinguishedname
    [string]$Name # name
    [string]$SamAccountName # samaccountname

    # Optional
    [string]$ManagedBy # managedby
    [string]$Info
    [string[]]$Members # member
    [string]$Description # description
    [datetime]$Created # whencreated
    [datetime]$Modified # whenchanged
}

#region Lookup tables
$UserToLDAPUserLookup = @{
    AccountExpirationDate = "accountexpires","whenchanged"
    adspath = "adspath"
    BadLogonCount = "badpwdcount"
    City = "l"
    CN = "cn"
    Company = "company"
    CountryCode = "countrycode"
    Created = "whencreated"
    Department = "department"
    Description = "description"
    DisplayName = "displayname"
    DistinguishedName = "distinguishedname"
    EmailAddress = "mail"
    EmployeeID = "employeeid"
    Enabled = "useraccountcontrol"
    GivenName = "givenname"
    Info = "info"
    LastBadPasswordAttempt = "lastlogon"
    LastLogonDate = "lastlogon"
    LockedOut = "lockouttime"
    Manager = "manager"
    MemberOf = "memberof"
    Modified = "whenchanged"
    Name = "name"
    ObjectCategory = "objectcategory"
    ObjectClass = "objectclass"
    Office = "physicaldeliveryofficename"
    PasswordLastSet = "pwdlastset","whenchanged"
    PostalCode = "postalcode"
    proxyaddresses = "proxyaddresses"
    SamAccountName = "samaccountname"
    State = "st"
    StreetAddress = "streetaddress"
    Surname = "sn"
    targetaddress = "targetaddress"
    Title = "title"
    UserPrincipalName = "userprincipalname"
}
$UserAccountControlLookup = @{
    ADS_UF_ACCOUNT_DISABLE = 2
    ADS_UF_HOMEDIR_REQUIRED = 8
    ADS_UF_LOCKOUT = 16
    ADS_UF_PASSWD_NOTREQD = 32
    ADS_UF_PASSWD_CANT_CHANGE = 64
    ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128
    ADS_UF_NORMAL_ACCOUNT = 512
    ADS_UF_DONT_EXPIRE_PASSWD = 65536
    ADS_UF_PASSWORD_EXPIRED = 8388608
}
$GroupToLDAPGroupLookup = @{
    DistinguishedName = "distinguishedname"
    Name = "name"
    SamAccountName = "samaccountname"
    ManagedBy = "managedby"
    Info = "info"
    Members = "member"
    Description = "description"
    Created = "whencreated"
    Modified = "whenchanged"
}
#endregion

filter Get-ADUser
{
    <#
    .SYNOPSIS
        Acts as a replacement for querying users in AD using the AD module using Get-ADUser.
        Much faster than loading the ActiveDirectory Module. Use syntax in example.
    .EXAMPLE
        Get-ADUser -Filter @{
            givenname="Neil"
            sn="White"
        }
    .EXAMPLE
        Get-ADUser $env:USERNAME
    .EXAMPLE
        Get-ADUser -Filter @{
            GivenName="Neil"
            Surname="White"
        }
    .LINK
        https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher
    .LINK
        https://www.codemag.com/article/1312041/Using-Active-Directory-in-.NET
    .NOTES
        Due to implementation restrictions, the SearchResultCollection class cannot release all of its unmanaged resources when it is garbage collected.
        To prevent a memory leak, you must call the Dispose method when the SearchResultCollection object is no longer needed.
    #>
    [CmdletBinding(DefaultParameterSetName="Username parameter set")]
    [OutputType([ADUser])]
    param (
        # Username of the user
        [Parameter(Mandatory,ParameterSetName="Username parameter set",Position=0)]
        [string]$Name,

        # Key-value pair for the AD user object being returned. Use the user-friendly values as returned by Get-ADUser.
        [Parameter(Mandatory,ParameterSetName="Filter parameter set",Position=1)]
        [Hashtable]$Filter,

        # The set of properties to retrieve during the search.
        [ADUserEnum[]]$Properties,

        # You can set the Username and Password in order to specify alternate credentials with which to access the information in Active Directory Domain Services.
        [pscredential]$Credential,

        # Domain to search within
        [string]$DomainName = $env:USERDNSDOMAIN,

        # Number of search results to return by default
        [uint]$SizeLimit = 100
    )
    $StringBuilder = [StringBuilder]::new()
    $StringBuilder.Append("(&(objectClass=user)") | Out-Null # Out-Null is much faster in v7
    if ($Name) { $Filter = @{SamAccountName=$Name} }

    foreach ($PropertyName in $Filter.Keys)
    {
        $QueryPropertyName = $PropertyName
        if (-not $UserToLDAPUserLookup.ContainsValue($PropertyName))
        {
            $QueryPropertyName = $UserToLDAPUserLookup.Item($PropertyName) # Might be faster than calling Convert-UserToLDAPUser
        }

        [string]$FilterString = "({0}={1})" -f $QueryPropertyName,$($Filter.$PropertyName)
        Write-Verbose $FilterString
        $StringBuilder.Append($FilterString) | Out-Null
    }
    $StringBuilder.Append(")") | Out-Null

    Write-Verbose "Add properties required by other properties"
    # Create a generic list and append items because it's faster
    [List[string]]$PropertyList = "DistinguishedName","Enabled","GivenName","Name","ObjectClass","SamAccountName","Surname","UserPrincipalName"

    foreach ($Property in $Properties)
    {
        if ($Property -notin $PropertyList) { $PropertyList.Add($Property) }
    }
    # Check for properties that depend on other properties
    $LDAPPropertyList =  $PropertyList | Convert-UserToLDAPUser

    foreach ($ADResult in (Find-DirectoryObject -SearchString $StringBuilder.ToString() -PropertyList $LDAPPropertyList -DomainName $DomainName -SizeLimit $SizeLimit -Credential $Credential))
    {
        $ADUser = [ADUser]::new()
        $ADUser.AccountExpirationDate = $null -ne ${ADResult}?.accountexpires ? $ADResult.accountexpires : $ADUser.AccountExpirationDate
        $ADUser.adspath = ${ADResult}?.adspath
        $ADUser.BadLogonCount = ${ADResult}?.badpwdcount | Select-Object -First 1
        $ADUser.City = ${ADResult}?.l
        $ADUser.CN = ${ADResult}?.cn
        $ADUser.Company = ${ADResult}?.company
        $ADUser.countrycode = ${ADResult}?.countrycode
        $ADUser.Created = $null -ne ${ADResult}?.whencreated ? $ADResult.whencreated : $ADUser.Created
        $ADUser.Department = ${ADResult}?.department
        $ADUser.Description = ${ADResult}?.description
        $ADUser.DisplayName = ${ADResult}?.displayname
        $ADUser.DistinguishedName = $ADResult.distinguishedname
        $ADUser.EmailAddress = ${ADResult}?.mail
        $ADUser.EmployeeID = ${ADResult}?.employeeid ? $ADResult.employeeid : $ADUser.EmployeeID
        $ADUser.Enabled = $null -ne ${ADResult}?.useraccountcontrol ? (($ADResult.useraccountcontrol[0] -band $UserAccountControlLookup.Item("ADS_UF_ACCOUNT_DISABLE")) -eq 0) : $false
        $ADUser.GivenName = ${ADResult}?.givenname
        $ADUser.Info = ${ADResult}?.info
        $ADUser.LastBadPasswordAttempt = $null -ne ${ADResult}?.badpasswordtime ? $ADResult.badpasswordtime[0] : $ADUser.LastBadPasswordAttempt
        $ADUser.LastLogonDate = $null -ne ${ADResult}?.lastlogon ? $ADResult.lastlogon[0] : $ADUser.LastLogonDate
        $ADUser.LockedOut = $null -ne ${ADResult}?.lockouttime ? ${ADResult}?.lockouttime[0] -ne 0 : $false
        $ADUser.Manager = ${ADResult}?.manager
        $ADUser.MemberOf = ${ADResult}?.memberof
        $ADUser.Modified = $null -ne ${ADResult}?.whenchanged ? $ADResult.whenchanged : $ADUser.Modified
        $ADUser.Name = ${ADResult}?.name
        $ADUser.ObjectCategory = ${ADResult}?.objectcategory
        $ADUser.ObjectClass = ${ADResult}?.objectclass
        $ADUser.Office = ${ADResult}?.physicaldeliveryofficename
        $ADUser.PasswordLastSet = $null -ne ${ADResult}?.pwdlastset ? $ADResult.pwdlastset : $ADUser.PasswordLastSet
        $ADUser.PostalCode = ${ADResult}?.postalcode
        $ADUser.proxyaddresses = ${ADResult}?.proxyaddresses
        $ADUser.SamAccountName = ${ADResult}?.samaccountname
        $ADUser.State = ${ADResult}?.st
        $ADUser.StreetAddress = ${ADResult}?.streetaddress
        $ADUser.Surname = ${ADResult}?.sn
        $ADUser.targetaddress = ${ADResult}?.targetaddress
        $ADUser.Title = ${ADResult}?.title
        $ADUser.UserPrincipalName = ${ADResult}?.userprincipalname
        Write-Output $ADUser | Select-Object -Property $PropertyList
    }
}

function Get-ADGroup
{
    <#
    .SYNOPSIS
        Retrieves Active Diretory group with the group name passed in. Replacement for Get-ADGroup.
    .LINK
        https://stackoverflow.com/questions/46000885/search-ad-with-powershell-without-using-ad-module-rsat
    .NOTES
        Thanks to BenH on Stack Overflow for the code snippet
    .EXAMPLE
        Get-ADGroup -Name G_WM_BuildRelease
    .EXAMPLE
        "Group1","Group2" | Get-ADGroup
    .EXAMPLE
        Get-ADGroup -Name Group1 -Properties MemberOf
    .NOTES
        Due to implementation restrictions, the SearchResultCollection class cannot release all of its unmanaged resources when it is garbage collected.
        To prevent a memory leak, you must call the Dispose method when the SearchResultCollection object is no longer needed.
    #>
    [CmdletBinding()]
    [OutputType([ADGroup])]
    param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string[]]$Name,

        # The set of properties to retrieve during the search.
        [ValidateSet("ManagedBy","Info","Members","Description","Created","Modified")]
        [string[]]$Properties,

        # You can set the Username and Password in order to specify alternate credentials with which to access the information in Active Directory Domain Services.
        [pscredential]$Credential,

        # Domain to search within
        [string]$DomainName = $env:USERDNSDOMAIN
    )
    begin
    {
        $StringBuilder = [StringBuilder]::new()
        $StringBuilder.Append("(&(objectCategory=group)(|") | Out-Null
    }
    process
    {
        foreach ($GroupName in $Name)
        {
            $StringBuilder.Append("(name=$GroupName)") | Out-Null
        }
    }
    end
    {
        # Create a generic list and append items because it's faster
        [List[string]]$PropertyList = "Name","DistinguishedName","SamAccountName"

        foreach ($Property in $Properties)
        {
            if ($Property -notin $PropertyList) { $PropertyList.Add($Property) }
        }
        # Check for properties that depend on other properties
        $LDAPPropertyList = Convert-GroupToLDAPGroup -ADGroupProperties $PropertyList
        $StringBuilder.Append("))") | Out-Null

        foreach ($ADResult in (Find-DirectoryObject -SearchString $StringBuilder.ToString() -PropertyList $LDAPPropertyList -DomainName $DomainName -SizeLimit $SizeLimit -Credential $Credential))
        {
            $ADGroup = [ADGroup]::new()
            $ADGroup.DistinguishedName = $ADResult['distinguishedname']
            $ADGroup.Name = $ADResult['name']
            $ADGroup.SamAccountName = ${ADResult}?.samaccountname
            $ADGroup.ManagedBy = ${ADResult}?.managedby
            $ADGroup.Info = ${ADResult}?.info
            $ADGroup.Members = ${ADResult}?.member
            $ADGroup.Description = ${ADResult}?.description
            $ADGroup.Created = $null -ne ${ADResult}?.whencreated ? $ADResult['whencreated'][0] : $ADGroup.Created
            $ADGroup.Modified = $null -ne ${ADResult}?.whenchanged ? $ADResult['whenchanged'][0] : $ADGroup.Modified
            Write-Output $ADGroup | Select-Object -Property $PropertyList
        }
    }
}

filter Get-ADGroupMember
{
    <#
    .SYNOPSIS
        Retreives the members of the specified group. Replacement for Get-ADGroupMember.
    .EXAMPLE
        Get-ADGroupMember ADGroup1
    #>
    [CmdletBinding()]
    [OutputType([ADUser])]
    param (
        # Name of the group
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$Name,

        # You can set the Username and Password in order to specify alternate credentials with which to access the information in Active Directory Domain Services.
        [pscredential]$Credential,

        # Domain to search within
        [string]$DomainName = $env:USERDNSDOMAIN
    )
    foreach ($ADGroup in (Get-ADGroup -Name $Name -Properties Members -Credential $Credential -DomainName $DomainName))
    {
        $ADGroup.Members | ForEach-Object -Process {
            Get-ADUser -Filter @{
                CN=($_ | Convert-ADCnToGroupName)
            }
        }
    }
}

filter Get-ADPrincipalGroupMembership
{
    <#
    .SYNOPSIS
        Retreives group the user is a member of. Replacement for Get-ADPrincipalGroupMembership.
    .EXAMPLE
        Get-ADPrincipalGroupMembership -Name $env:USERNAME
    #>
    [CmdletBinding()]
    [OutputType([ADGroup])]
    param (
        # Username
        [Parameter(Mandatory)]
        [string]$Name,

        # You can set the Username and Password in order to specify alternate credentials with which to access the information in Active Directory Domain Services.
        [pscredential]$Credential,

        # Domain to search within
        [string]$DomainName = $env:USERDNSDOMAIN
    )
    $Splat = @{
        Credential = $Credential
        DomainName = $DomainName
    }
    Get-ADUser -Filter @{ SamAccountName=$Name } -Properties memberOf @Splat | Select-Object -ExpandProperty MemberOf | Convert-ADCnToGroupName |
    Get-ADGroup @Splat
}

filter Convert-ADCnToGroupName
{
    <#
    .SYNOPSIS
        Converts a Canoical Name in LDAP format to it's equiv. name that's easily readable. Internal implementation.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string[]]$CN
    )
    foreach ($Name in $CN)
    {
        [regex]::Unescape(($Name -replace ",OU=.*","" -replace "CN=",""))
    }
}

function Convert-UserToLDAPUser
{
    <#
    .SYNOPSIS
        Returns the equiv. list of LDAP properties given a list of user-friendly properties from the ADUser class.
        Internal implementation.
    #>
    [CmdletBinding()]
    param(
        # List of properties from the ADUser class
        [Parameter(Mandatory,ValueFromPipeline)]
        [string[]]$ADUserProperties
    )
    begin { $LDAPPropertyList = [List[string]]::new() }
    process
    {
        # Faster than ForEach-Object
        foreach ($ADUserProperty in $ADUserProperties)
        {
            foreach ($SubProperty in ($UserToLDAPUserLookup.Item($ADUserProperty)))
            {
                $LDAPPropertyList.Add($SubProperty)
            }
        }
    }
    end { $LDAPPropertyList | Get-Unique }
}

function Convert-GroupToLDAPGroup
{
    <#
    .SYNOPSIS
        Returns the equiv. list of LDAP properties given a list of user-friendly properties from the ADUser class.
        Internal implementation.
    #>
    [CmdletBinding()]
    param(
        # List of properties from the ADUser class
        [Parameter(Mandatory,ValueFromPipeline)]
        [string[]]$ADGroupProperties
    )
    begin { $LDAPPropertyList = [List[string]]::new() }
    process
    {
        # Faster than ForEach-Object
        foreach ($ADGroupProperty in $ADGroupProperties)
        {
            foreach ($SubProperty in ($GroupToLDAPGroupLookup.Item($ADGroupProperty)))
            {
                $LDAPPropertyList.Add($SubProperty)
            }
        }
    }
    end { $LDAPPropertyList | Get-Unique }
}

filter Find-DirectoryObject
{
    <#
    .SYNOPSIS
        Wrapper for creating and manipulating the directory searcher. Helps consolidate functionality and assist in
        unit testing.
    .LINK
        https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher.-ctor?view=windowsdesktop-7.0#system-directoryservices-directorysearcher-ctor(system-directoryservices-directoryentry-system-string-system-string())
    #>
    [CmdletBinding()]
    param (
        # Query to submit to the LDAP client
        [Parameter(Mandatory)]
        [string]$SearchString,

        # LDAP properties to return from the query
        [Parameter(Mandatory)]
        [string[]]$PropertyList,

        # Domain to search within
        [string]$DomainName = $env:USERDNSDOMAIN,

        # Number of search results to return by default
        [uint]$SizeLimit = 100,

        # You can set the Username and Password in order to specify alternate credentials with which to access the information in Active Directory Domain Services.
        [pscredential]$Credential
    )
    Write-Verbose $SearchString
    Write-Verbose "Properties to return: $PropertyList"
    if ($Credential -and $DomainName)
    {
        $SearchRoot = [DirectoryServices.DirectoryEntry]::new("LDAP://$DomainName",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        $Script:Searcher = [DirectoryServices.DirectorySearcher]::new($SearchRoot,$SearchString,$PropertyList)
    }
    else
    {
        $Script:Searcher = [DirectoryServices.DirectorySearcher]::new($SearchString,$PropertyList)
    }
    # Faster than New-Object DirectoryServices.DirectorySearcher
    $Searcher.SizeLimit = $SizeLimit
    try { $Searcher.FindAll() | Select-Object -ExpandProperty Properties }
    catch { throw $_ }
    finally { $Searcher.Dispose() <# Has to be disposed. #> }
}
