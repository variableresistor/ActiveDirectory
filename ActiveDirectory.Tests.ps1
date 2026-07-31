[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
    Justification='Suppress false positives in Pester code blocks')]
param (
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path (Import-Clixml (Join-Path ($env:AGENT_TEMPDIRECTORY ?? $env:TEMP)) "Credential.xml")}
        ,ErrorMessage="You must output your credentials to the temp directoryn in a file called Credentials.xml")]
    [pscredential]$Credential = (Import-Clixml (Join-Path ($env:AGENT_TEMPDIRECTORY ?? $env:TEMP)) "Credential.xml")
)
BeforeAll {
    Get-ChildItem $PSScriptRoot -Filter "*.psm1" | ForEach-Object {
        Import-Module $_.FullName
    } # Not all functions are public
    $UserName = $Credential.UserName -split "\\" | Select-Object -Last 1
}

Describe "Get-ADUser" {
    BeforeAll {
        $UserName = $Credential.UserName -split "\\" | Select-Object -Last 1
        $SearchRoot = [DirectoryServices.DirectoryEntry]::new("LDAP://CONTOSO.CORP.NET",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        $Properties = "distinguishedname","enabled","givenname","name","samaccountname","userprincipalname"
        $Searcher = New-Object DirectoryServices.DirectorySearcher $SearchRoot,"(&(objectClass=user)(SamAccountName=$UserName))"
        $ThisADUser = $Searcher.FindOne() | Select-Object -ExpandProperty Properties
    }
    It "Returns a single user given a unique username property" {
        $Result = Get-ADUser -Filter @{ SamAccountName=$UserName } -Properties GivenName,Surname -Credential $Credential
        $Result | Should -Not -BeNullOrEmpty
        $Result | Should -HaveCount 1
        $Result.DistinguishedName | Should -Be $ThisADUser.distinguishedname
        $Result.Enabled | Should -Be $true
        $Result.GivenName | Should -Be $ThisADUser.givenname
        $Result.Name | Should -Be $ThisADUser.name
        $Result.Surname | Should -Be $ThisADUser.sn
        for ([int]$i = 0; $i -lt $Result.ObjectClass.Count; $i++)
        {
            $Result.ObjectClass[$i] | Should -Be $ThisADUser.objectclass[$i]
        }
        $Result.SamAccountName | Should -Be $ThisADUser.samaccountname
        $Result.UserPrincipalName | Should -Be $ThisADUser.userprincipalname
    }
    It "Returns a single user when passing a first and last name" {
        $Result = Get-ADUser -Filter @{
            givenname=$ThisADUser.givenname
            sn=$ThisADUser.sn
        } -Credential $Credential
        $Result | Should -Not -BeNullOrEmpty -Because "It should return at least 1 result"
        $Result | Should -HaveCount 1
        $Result.GivenName | Should -Be $ThisADUser.givenname
        $Result.Surname | Should -Be $ThisADUser.sn
    }
    It "Returns a user if they pass in a username as the first parameter" {
        $Result = Get-ADUser -Name "APP_DevOps_SVC" -Credential $Credential
        $Result | Should -Not -BeNullOrEmpty -Because "It should return at least 1 result"
        $Result.SamAccountName | Should -Be "APP_DevOps_SVC"
    }
    It "Allows them to pass in a string as the first parameter without the parameter name" {
        $Result = Get-ADUser APP_DevOps_SVC -Credential $Credential
        $Result | Should -Not -BeNullOrEmpty
        $Result.Name | Should -Be "APP_DevOps_SVC"
    }
    It "Returns the correct default properties, LockedOut" {
        $Result = Get-ADUser -Filter @{ SamAccountName=$UserName } -Properties LockedOut -Credential $Credential
        $Result.LockedOut | Should -Be $false
    }
}

Describe "Get-ADGroup" {
    It "Returns a single group when passing in a single name" {
        $Result = Get-ADGroup -Name DevOps -Credential $Credential
        $Result | Should -Not -BeNullOrEmpty
        $Result | Should -HaveCount 1
        $Result.Name | Should -Be "DevOps"
    }
    It "Returns 2 groups when passing in 2 group names via the pipeline" {
        $Result = "DevOps","Devs" | Get-ADGroup -Credential $Credential | Sort-Object -Property Name
        $Result | Should -Not -BeNullOrEmpty
        $Result | Should -HaveCount 2
        $Result[0].Name | Should -Be "DevOps"
        $Result[1].Name | Should -Be "Devs"
    }
    It "Returns the properties requested" {
        $Result = Get-ADGroup -Name DevOps -Properties Modified,Created,Description,Info,ManagedBy -Credential $Credential
        $Result | Should -Not -BeNullOrEmpty
        $Result.Modified | Should -Not -BeNullOrEmpty
        $Result.Created | Should -Not -BeNullOrEmpty
        $Result.Description | Should -Not -BeNullOrEmpty
        $Result.Info | Should -Not -BeNullOrEmpty
        $Result.ManagedBy | Should -Not -BeNullOrEmpty
    }
}

Describe "Convert-ADCnToGroupName" {
    It "Filters things properly" {
        $Result = "CN=DevOps,OU=Users,DC=contoso,DC=Corp,DC=net" | Convert-ADCnToGroupName
        $Result | Should -Be "DevOps"
    }
}

Describe "Get-ADPrincipalGroupMembership" {
    It "Retrieves the group membership of the current user" {
        $ADGroups = Get-ADPrincipalGroupMembership -Name $UserName -Credential $Credential
        $ADGroups | Should -Not -BeNullOrEmpty
        "DevOps" | Should -BeIn $ADGroups.Name
    }
}

Describe "Get-ADGroupMember" {
    It "Returns at least 1 group" {
        Get-ADGroupMember -Name DevOps -Credential $Credential | Should -Not -BeNullOrEmpty
    }
}

AfterAll {
    $Searcher.Dispose()
}
