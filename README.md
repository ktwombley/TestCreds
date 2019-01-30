TestCreds is a PowerShell module with commands to help compare lists of leaked
usernames and passwords to your Active Directory users.

Installation
============

Place the folder somewhere in your PowerShell module path 
`%USERPROFILE%\Documents\WindowsPowerShell\Modules` should work. Put the whole
folder in there; not just the files. You will end up with a folder like 

  `%USERPROFILE%\Documents\WindowsPowerShell\Modules\TestCreds`

You may have to customize a few commands for your environment. There currently
is no clean way to do this aside from editing the source.

This module requires the ActiveDirectory module. Either install this module on
a server with the ActiveDirectory module, or install RSAT. Please don't make a 
habit of downloading crap from github to run directly on your DCs.

Usage
=====

    PS C:> Import-Module TestCreds
    PS C:> get-command -Module TestCreds
    PS C:> get-help Test-CredentialsFile
    etc.

Creds File Checking
-------------------

Save the username/password dump as a file with email:password lines or as a CSV
with username and password fields. You do NOT need to look up the tokens first to
find valid AD accounts; we will do that for you. See the note at the end of this
section about the format. Let's say we have a file named c:\dumps.txt with 
the correct format.

    PS C:> Import-Module TestCreds
    PS C:> Test-CredentialsFile -Path c:\dumps.txt -OutCSV c:\results.csv

results.csv will now be a CSV with these headers:
* EmailAddress:     obtained from the input file
* SamAccountName:   Account name from AD, if found
* DisplayName:      DisplayName from AD, if found
* PasswordChecked:  True/False if we actually checked the password
* FoundInAD:        True/False did we find the account in AD?
* Notes:            Diagnostic info about the results
* PasswordWorks:    True/False if True, then the Password works!
* Password:        obtained from the input file

If FoundInAD is TRUE, then `Test-CredentialsFile` found a corresponding user for 
the EmailAddress. If PasswordWorks is TRUE, then the supplied password IS VALID.
That is bad.

*`Test-CredentialsFile` tries to authenticate to AD with the given credentials.*
This is the only sane way to tell if they're valid. If you have particularly 
crazy account lockout rules and your users are unlucky, you may lock them out;
Suppose you lock-out on 3 failed attempts. If the user recently had 2 failed
login attempts and `Test-CredentialsFile` causes the third, the account will
lockout. When a zillion failed login attempts to AD originate from your
workstation you might run into trouble from user behaviour analytic systems.

You may find multiple search results per input line. `Test-CredentialsFile` uses
`Search-ADUser` to find the SamAccountName, so its possible that there will be
more than one search result. For example, your users might have an admin account
and both their regular account and admin account have the same email address in
AD. `Test-CredentialsFile` will find them both.

Note on format: The 'email' portion of the email:password lines can actually be
anything. Behind the scenes, `Test-CredentialsFile` uses `Search-ADUser` to find
the corresponding user(s) for each line. So these are totally valid and might 
work (if these people exist in your AD, that is):

    John.Doe@contoso.com:password1
    Smith, John:123456
    rumplestiltskin:mustang67
    frank:Changeme123!

Notice that last line. You may have several users whose names include 'frank'
somewhere. 

Search for accounts in AD
-------------------------

`Search-ADUser` is included in the TestCreds module. You can use it similarly to 
`Get-ADUser`, except you don't have to bother writing a filter statement to
search for users yourself.

`Search-ADUser` searches Active Directory for a user account matching your input
by first trying likely matches (for instance, trying the username, email
address, or real names) and then trying increasingly less-likely techniques
until matches are found. Depending on how well populated your Active Directory
fields are, you can find your users by business unit, phone number, title, etc.

Query All Domain Controllers
----------------------------
`Get-ADUserFromAllDCs` works like Get-ADUser except that it, well, gets them
from all DCs. It will aggregate the fields you specify with whatever aggregation
you wish. This is useful for object properties which aren't replicated such as
lastBadPasswordAttempt; you can query each DC for the lastBadPasswordAttempt and
return the largest (e.g. latest) one. But don't do that because you also have
`Get-RealLastBadPasswordAttempt` in this module too.

Utilities
---------

* `Test-ADAuthentication` is a quick method to verify that a Credential object
contains a valid username and password.
* `Test-PasswordValidates` checks to see if Active Directory will allow a given
password. It does not actually check if the password is valid for the user.



Known Issues
============
* This module probably requires PowerShell Version 5.
* `Search-ADUser` might use a very slow method to search for users due to
unpredictable errors when used via PSRemoting.
