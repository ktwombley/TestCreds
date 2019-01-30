<#
.Synopsis
   Quickly check a data breach file to see if emails and passwords are concerning
.DESCRIPTION
   Test-CredentialsFile checks whether that userinfo corresponds to a valid user
   in AD, and then whether or not the supplied password works. It does this by 
   actually trying the password. (See the notes below)

   

.NOTES
   Extremely common or short userinfo values are likely to match many many many
   user accounts. You may not like that.
   
   Test-CredentialsFile actually tries to authenticate using the passwords in
   the dump file. This is the only way to reliably check. It does try very hard 
   not to lock out user accounts. Here are the safeguards in place:
   * A password is only tried when a corresponding user account is found (it
      does not spray passwords across all accounts)
   * If too many user accounts are found for a line, it assumes they are false-
      positives and declines to check them.
   * The password is checked against the Domain password policy. If it couldn't
      possibly be a valid password, it is not checked.
   * If the user account has had a failed login within the the lockout review
      window, the password is not tried.
   * After the passwords are checked, Test-CredentialsFile periodically monitors
      all accounts until the lockout review window is over and alerts you if
      any accounts lock out.

.EXAMPLE
   Get-Content c:\creds.txt | Test-CredentialsFile

   Checks each line in c:\creds.txt.
.EXAMPLE
   Get-ChildItem C:\* -Include "cred*" | Test-CredentialsFile

   Finds all files in the root of the C:\ drive that start with "cred" and checks each line thereof.
.EXAMPLE
   Test-CredentialsFile -Path c:\creds1.txt,c:\creds2.txt

   Checks each line of c:\creds1.txt and c:\creds2.txt.
.EXAMPLE
   "user:foo123" | Test-CredentialsFile

   Searches AD for users matching the term "user" and then checks each of them.
   
.INPUTS
   Credential dumps can be handled in one of three ways. You can supply a few
   credentials on the commandline (or via a pipe). You can supply a path to a
   colon-separated dump file. Or you can supply a path to a CSV.
   
   The colon-separated format looks like this:

        userinfo:password

   The CSV format can have any number of columns as long as there is a userinfo 
   field and a password field. The userinfo field can be named name, username, 
   logon, user, accountname, account, email, mail, or samaccountname. The 
   password field can be named password, pass, pw, passwd, clear, cleartext, or
   cracked.

   Regardless of what the CSV column is named, 'userinfo' can be any information
   about the account such as their email address, username, real name, etc.
   Test-CredentialsFile tries to match on a lot of possible user info fields,
   see the help for Search-ADUser for more details.

.OUTPUTS
   Test-CredentialsFile outputs objects with these properties:
   * EmailAddress:     obtained from the input file
   * SamAccountName:   Account name from AD, if found
   * DisplayName:      DisplayName from AD, if found
   * PasswordChecked:  True/False if we actually checked the password
   * FoundInAD:        True/False did we find the account in AD?
   * Notes:            Diagnostic info about the results
   * PasswordWorks:    True/False if True, then the Password works!
   * Password:        obtained from the input file
   
   If FoundInAD is TRUE, then Test-CredentialsFile found a corresponding user 
   for the EmailAddress. If PasswordWorks is TRUE, then the supplied password IS
   VALID. That is bad.
#>
function Test-CredentialsFile
{
    [CmdletBinding(
        SupportsShouldProcess=$true,
		ConfirmImpact="Medium"
    )]
    param(
        #Path of credentials file
        [Parameter(Mandatory=$true,
            Position=0,
            ParameterSetName="FromFile")]
        [Alias("Pathname","Dump")]
        [string[]]$Path,

        #Write results to CSV file. Automatically determined if you don't specify -DestPath.
        [Parameter(Mandatory=$false)]
        [Alias("AutoDestPath")]
        [switch]$OutCSV,

        #Path of results file
        [Parameter(Mandatory=$false,
            Position=1)]
        [Alias("ResultsPath","Dest")]
        [string]$DestPath,

        #Overwrite $DestPath mercilessly.
        [Parameter(Mandatory=$false)]
        [Alias("Clobber")]
        [switch]$AllowClobber,

        #Series of strings of the form username:password
        [Parameter(Mandatory=$false,
            ParameterSetName="TuplesFromPipe",
            ValueFromPipeline=$true)]
        [Alias('Line')]
        [String[]]$Tuple,

        #Character which separates usernames from passwords. Default is ":"
        [Parameter(Mandatory=$false,
            ParameterSetName="TuplesFromPipe")]
        [Char]$Separator=":",
        
        #Pipe in objects with a Name and Password attribute
        [Parameter(Mandatory=$false,
            ParameterSetName="FromPipe",
            ValueFromPipelinebyPropertyName=$true)]
        [Alias('username', 'logon', 'user', 'accountname', 'account', 'email', 'mail', 'samaccountname')]
        [String[]]$Name,

        #Pipe in objects with a Name and Password attribute
        [Parameter(Mandatory=$false,
            ParameterSetName="FromPipe",
            ValueFromPipelinebyPropertyName=$true)]
        [Alias('pass', 'pw', 'passwd', 'clear', 'cleartext', 'cracked')]
        [String[]]$Password,
        
        #Should Test-CredentialsFile tries again with just the username if it detects an email address. This turns that off.
        [Parameter(Mandatory=$false)]
        [switch]$NoSplitEmail=$false,

        #Some searches erroneously find a large number of users. If more than this many are found, assume they are all false-positive.
        [Parameter(Mandatory=$false)]
        [int]$MaxHits=5,

        #Disable enhanced (slower) user health checks
        [Parameter(Mandatory=$false)]
        [switch]$NoHealthChecks,

        #Test-CredentialsFile will wait to recheck all users and alert you if any lock out afterwards. This parameter turns that off.
        [Parameter(Mandatory=$false)]
        [switch]$NoLockoutWait,

        #Id to pass to Write-Progress
        [parameter()]
        [int]$ProgressID = 0,
    
        #Id to pass to Write-Progress
        [parameter()]
        [int]$ParentProgressID = -1



    )
    Begin {
        $DefaultADPwPolicy = Get-ADDefaultDomainPasswordPolicy

        if ($OutCSV -and -not $DestPath) {
            if ($Path) {
                $x = get-childitem -Path $Path
                $DestPath = Join-Path -Path $x.Directory -ChildPath "$($x.Basename)_results.csv"
            } else {
                $DestPath = Join-Path -Path "." -ChildPath "test-credentials_result.csv"
            }
        }

        if ($DestPath) {
            # Thank you https://stackoverflow.com/a/3040982
            $DestPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestPath)

            if (Test-Path -Path $DestPath) {
                if (-not $AllowClobber) {
                    throw [System.Management.Automation.ErrorRecord]::new(
                        [System.IO.IOException]::new("Cannot overwrite $DestPath"),
                        "Test-CredentialsFile cannot overwrite $DestPath because you did not specify -AllowClobber on the command-line.",
                        [System.Management.Automation.ErrorCategory]::ResourceExists,
                        $DestPath
                    )
                } else {
                    #Ensure we can write to $DestPath
                    try {
                        #if DestPath doesn't exist, this will create it.
                        [io.file]::OpenWrite($DestPath).close()
                    }
                    catch {
                        if ($_.Exception.InnerException -is [System.UnauthorizedAccessException]) {
                            $cat = [System.Management.Automation.ErrorCategory]::PermissionDenied
                        } elseif ($_.Exception.InnerException -is [System.IO.DirectoryNotFoundException]) {
                            $cat = [System.Management.Automation.ErrorCategory]::ObjectNotFound
                        } else {
                            $cat = [System.Management.Automation.ErrorCategory]::NotSpecified
                        }
                        throw [System.Management.Automation.ErrorRecord]::new(([System.IO.IOException]::New("Cannot write to $DestPath.")),"Test-CredentialsFile cannot write to $DestPath.",$cat,$DestPath)
                    }


                }
            } else {
                #DestPath does not exist.
                try {
                    #this will create DestPath. Need to remove it before the Export-CSV below.
                    [io.file]::OpenWrite($DestPath).close()
                }
                catch {
                    if ($_.Exception.InnerException -is [System.UnauthorizedAccessException]) {
                        $cat = [System.Management.Automation.ErrorCategory]::PermissionDenied
                    } elseif ($_.Exception.InnerException -is [System.IO.DirectoryNotFoundException]) {
                        $cat = [System.Management.Automation.ErrorCategory]::ObjectNotFound
                    } else {
                        $cat = [System.Management.Automation.ErrorCategory]::NotSpecified
                    }
                    throw [System.Management.Automation.ErrorRecord]::new(([System.IO.IOException]::New("Cannot write to $DestPath.")),"Test-CredentialsFile cannot write to $DestPath.",$cat,$DestPath)
                }
                try {
                    Remove-Item -Path $DestPath -ErrorAction stop
                } catch [System.Management.Automation.ItemNotFoundException] {
                    #We wanted to remove it, and its gone. So what?
                    pass
                }
            }
        }

        function test-acred($email, $passwd, $progid, $pprogid)
        {
            $found = $null
            $did_try = $false
            $overall_notes = ""
            try {
                $found = Search-ADUser $email -Properties SamAccountName,DisplayName,AccountExpirationDate,Enabled,LockedOut,LastBadPasswordAttempt,PasswordExpired -ErrorAction Stop -ProgressID $progid -ParentProgressID $pprogid
            }
            catch {
                $msg = "$($email): Error while searching AD. Results Suspicious."
                $overall_notes = Merge-StringList $overall_notes $msg
                Write-Warning $msg
            }
            if ( -not $NoSplitEmail -and $found -eq $null ) {
                ($user, $dom) = $email.Split('@')
                if ($user -ne $email) {
                    Write-Verbose "$($email): Search found 0 results. Trying with $($user)"
                    try {
                        $found = Search-ADUser $user -Thorough -Properties SamAccountName,DisplayName,AccountExpirationDate,Enabled,LockedOut,LastBadPasswordAttempt,PasswordExpired -ErrorAction Stop -ProgressID ($progid+1) -ParentProgressID $pprogid
                    }
                    catch {
                        $msg = "$($email) -> $($user): Error while searching AD. Results Suspicious."
                        $overall_notes = Merge-StringList $overall_notes $msg
                        Write-Warning $msg
                    }
                }
            }
            $res = @()
            if ($found -ne $null) {
                
                if ($found -is [system.array]) {
                    $msg = "$($email): Search found $($found.Count) results."
                    $overall_notes = Merge-StringList $overall_notes $msg
                    Write-Warning $msg
                }
                if ($found -is [system.array] -and $found.Count -gt $MaxHits) {
                    $msg = "$($email): $($found.Count) is greater than MaxHits ($($MaxHits)). Assuming false positive."
                    $overall_notes = Merge-StringList $overall_notes $msg
                    Write-Warning $msg
                    $notes = $overall_notes

                    $res += New-Object -TypeName psobject -Property @{
                        EmailAddress = $email
                        FoundInAD = $false
                        SamAccountName = $null
                        DisplayName = $null
                        PasswordChecked = $did_try
                        PasswordWorks = $false
                        Password = $passwd
                        Notes = $notes
                    }
                } else {
                    foreach ($afound in @($found)) {
                        $notes = $overall_notes
                        $did_try = $false

                        Write-Verbose "Found account name: $($afound.SamAccountName)"

                        $passwordfail=$false
                        if ($passwd -and $passwd -ne '') {
                            $isvalid = Test-PasswordValidates -SamAccountName $afound.SamAccountName -ClearPassword $passwd -AsString
                            if ($isvalid -ne 'NERR_Success') {
                                Write-Verbose "Invalid password ($($isvalid)) for $($afound.SamAccountName)."
                                $notes = Merge-StringList $notes "Password was not valid: $isvalid."
                                $passwordfail=$true
                            }
                        } else {
                            Write-Verbose "Empty password for $($afound.SamAccountName)."
                            $notes = Merge-StringList $notes "Password was empty."
                            $passwordfail=$true
                        }

                        $healthfail = $false
                        if(-not $NoHealthChecks) {
                            if($afound.AccountExpirationDate -gt 0 -and $afound.AccountExpirationDate -lt (get-date)) {
                                $healthfail = $true
                                $notes = Merge-StringList $notes "Account is expired."
                                write-warning "$($email): Account $($afound.SamAccountName) is expired."
                            }
                            if($afound.Enabled -ne $true) {
                                $healthfail = $true
                                $notes = Merge-StringList $notes "Account is disabled."
                                write-warning "$($email): Account $($afound.SamAccountName) is disabled."
                            }
                            if($afound.LockedOut -eq $true) {
                                $healthfail = $true
                                $notes = Merge-StringList $notes "Account is locked out."
                                write-warning "$($email): Account $($afound.SamAccountName) is locked out."
                            }
                            if($afound.PasswordExpired -eq $true) {
                                $healthfail = $true
                                $notes = Merge-StringList $notes "Account password is expired."
                                write-warning "$($email): Account $($afound.SamAccountName) password is expired."
                            }
                            #This call is expensive so we skip it when we aren't going to check the password.
                            if (-not $passwordfail -and -not $healthfail) {
                                $lastbadpw = (Get-RealLastBadPasswordAttempt -Identity $afound.SamAccountName -Verbose:$false -ProgressID ($progid+1) -ParentProgressID $progid).LastBadPasswordAttempt_Maximum
                                if ($lastbadpw -ge (get-date).Subtract($DefaultADPwPolicy.LockoutObservationWindow)) {
                                    $healthfail = $true
                                    $notes += "Account recently failed to login."
                                    write-warning "$($email): Account $($afound.SamAccountName) has recently failed to login."
                                }
                            } else {
                                Write-Verbose "Skipping expensive Get-RealLastBadPasswordAttempt because we aren't going to check the password anyhow."
                            }
                        }

                        if (-not $healthfail -and -not $passwordfail) {
                            If ($PSCmdlet.ShouldProcess("Test Credential for user $($afound.SamAccountName)")) { 
                                $did_try = $true
                                try {
                                    $cred = New-Object System.Management.Automation.PSCredential($afound.SamAccountName, ($passwd | ConvertTo-SecureString -AsPlainText -Force))
                                    $testresult = Test-ADAuthentication -Credential $cred                        
                                } catch [System.Management.Automation.MethodInvocationException] {
                                    #If something is wrong with the passwd, I hope the result is a methodinvocationexception.
                                    $testresult = $false
                                }
                            } else {
                                $did_try = $false
                                $notes = Merge-StringList $notes "User declined check."
                                $testresult = $false
                            }

                            if ($testresult) {
                                Write-Warning "$($email): Credentials are valid!"
                                $notes = Merge-StringList $notes "Credentials are valid!"
                            }
                            $res += New-Object -TypeName psobject -Property @{
                                EmailAddress = $email
                                FoundInAD = $true
                                SamAccountName = $afound.SamAccountName
                                DisplayName = $afound.DisplayName
                                PasswordChecked = $did_try
                                PasswordWorks = $testresult
                                Password = $passwd
                                Notes = $notes
                            }
                        } else {
                            Write-Verbose "Account $($afound.SamAccountName) failed health/password checks. Cannot check password."
                            $res += New-Object -TypeName psobject -Property @{
                                EmailAddress = $email
                                FoundInAD = $true
                                SamAccountName = $afound.SamAccountName
                                DisplayName = $afound.DisplayName
                                PasswordChecked = $did_try
                                PasswordWorks = $false
                                Password = $passwd
                                Notes = $notes
                            }
                        }
                    }
                }
            } else {
                $notes = $overall_notes

                $res += New-Object -TypeName psobject -Property @{
                    EmailAddress = $email
                    FoundInAD = $false
                    SamAccountName = $null
                    DisplayName = $null
                    PasswordChecked = $did_try
                    PasswordWorks = $false
                    Password = $passwd
                    Notes = $notes
                }
            }

            $res
        }

        function fail_line($line, $notes) {
            New-Object -TypeName psobject -Property @{
                    EmailAddress = ([string]$line)
                    FoundInAD = $false
                    SamAccountName = $null
                    DisplayName = $null
                    PasswordChecked = $false
                    PasswordWorks = $false
                    Password = $null
                    Notes = ([string]$notes)
                }
        }

        function get_fields($obj) {
            $x = Get-Member -InputObject $headercheck -MemberType NoteProperty
            $u = $x | Where-Object -Property Name -In @('name', 'username', 'logon', 'user', 'accountname', 'account', 'email', 'mail', 'samaccountname')
            $p = $x | Where-Object -Property Name -In @('password', 'pass', 'pw', 'passwd', 'clear', 'cleartext', 'cracked')
            if ($u) {
                $u = $obj.($u[0].Name)
            } else {
                $u = $false
            }
            if ($p) {
                $p = $obj.($p[0].Name)
            } else {
                $p = $false
            }

            $u,$p
        }

        #Replaced with Test-PasswordValidates
        function pw_meets_criteria($passwd, $SamAccountName) {
            $req = Get-ADUserResultantPasswordPolicy -Identity $SamAccountName
            if (-not $req) {
                $req = Get-ADDefaultDomainPasswordPolicy
            }
            if ($passwd.Length -lt $req.MinPasswordLength) {
                Write-Verbose "Password for $SamAccountName is too short."
                return $false
            }
            if ($req.ComplexityEnabled) {
                $complex_level = 0;
                $complex_level += $passwd -cmatch '[A-Z]'
                $complex_level += $passwd -cmatch '[a-z]'
                $complex_level += $passwd -cmatch '[0-9]'
                $complex_level += $passwd -cmatch '[~!@#$%^&*_\-+=`|\(){}[\]:;"''<>,.?/]'
                $complex_level += ($passwd -creplace '[A-Za-z0-9~!@#$%^&*_\-+=`|\(){}[\]:;"''<>,.?/]','').Length -gt 0

                if ($complex_level -lt 3) {
                    Write-Verbose "Password for $SamAccountName has $complex_level character classes, needs at least 3."
                    return $false
                }

                $displayname = (get-aduser -Identity $SamAccountName -Properties DisplayName | Select-Object -ExpandProperty DisplayName).ToLower()

                if ($passwd.ToLower().Contains($displayname)) {
                    Write-Verbose "Password for $SamAccountName contains DisplayName ($displayname)"
                    return $false
                }
                if ($passwd.ToLower().Contains($SamAccountName.ToLower())) {
                    Write-Verbose "Password for $SamAccountName contains SamAccountName ($SamAccountName)"
                    return $false
                }

            }

            return $true
        }
    }

    Process {

        [System.Collections.ArrayList]$results = @()

        if ($Path) {
            $filecount = 0
            foreach ($inpath in $Path) {
                if ($Path.Count -gt 1) {
                    Write-Progress -Id $ProgressID -ParentId $ParentProgressID -Activity "Checking File" -Status "Checking $inpath" -PercentComplete (100*$filecount++ / $Path.Count)
                }
                #Sniff whether this is a csv or not
                try {
                    $headercheck = get-content $inpath -TotalCount 2 | ConvertFrom-Csv -ErrorAction Stop
                    $u,$p = get_fields $headercheck
                    if ($u -and $p) {
                        $csv = $true
                    } else {
                        $csv = $false
                    }
                } catch {
                    $csv = $false
                }
                if ($csv) {
                    $lines = import-csv -path $inpath
                    $countlines = @($lines).Count
                    $linecount = 0
                    $lines | ForEach-Object {
                        $u,$p = get_fields $PSItem
                        Write-Progress -Id ($ProgressID+1) -ParentId $ProgressID -Activity "Checking Creds" -Status "Checking $($u)" -PercentComplete (100*$linecount++ / $countlines)
                        if ($u) {
                            $x = test-acred $u $p ($ProgressID+101) ($ProgressID+1)
                            $results.AddRange(@($x)) | Out-Null
                            $x
                        } else {
                            $x = fail_line $PSItem "Could not find a username from the line: $($linecount):[$($PSItem)]"
                            $results.AddRange(@($x)) | Out-Null
                            $x
                            write-warning "Could not find a username from the line: $($linecount):[$($PSItem)]"
                        }
                    }
                    Write-Progress -Id ($ProgressID+1) -ParentId $ProgressID -Activity "Checking Creds" -Status "Checking $($u)" -Completed

                } else {
                    $lines = get-content $inpath
                    $countlines = ( $lines| Measure-Object -Line).Lines
                    $linecount = 0
                    $lines | ForEach-Object {
                        Write-Progress -Id ($ProgressID+2) -ParentId $ProgressID -Activity "Checking Creds" -Status "Checking $PSItem" -PercentComplete (100*$linecount++ / $countlines)
                        if ($PSItem.Contains($Separator)) {
                            $u,$p = $PSItem -split $Separator
                            $x = test-acred $u $p ($ProgressID+201) ($ProgressID+2)
                            $results.AddRange(@($x)) | Out-Null
                            $x
                        } else {
                            $x = fail_line $PSItem "Could not split this line with sep '$($Separator)'. $($linecount):[$($PSItem)]"
                            $results.AddRange(@($x)) | Out-Null
                            $x
                            write-warning "Could not split this line with sep '$($Separator)'. $($linecount):[$($PSItem)]"
                        }
                    }
                    Write-Progress -Id ($ProgressID+2) -ParentId $ProgressID -Activity "Checking Creds" -Status "Checking $PSItem" -Completed
                }
            }
            if ($Path.Count -gt 1) {
                Write-Progress -Id $ProgressID -ParentId $ParentProgressID -Activity "Checking File" -Status "Done with all files" -Completed
            }

        } elseif($Tuple) {
            $i = 0
            foreach ($aval in $Values) {
                Write-Progress -Id $ProgressID -ParentId $ParentProgressID -Activity "Checking Creds" -Status "Checking $aval" -PercentComplete (100*$i++ / $Values.Count)
                ($u, $p) = $aval -split $Separator
                $x = test-acred $u $p ($ProgressID+101) ($ProgressID)
                $results.AddRange(@($x)) | Out-Null
                $x
            }
            Write-Progress -Id $ProgressID -ParentId $ParentProgressID -Activity "Checking Creds" -Status "Done with values" -Completed
        } elseif($Name -and $Password) {
            Write-Progress -Activity "Checking Creds" -Status "Checking $Name" -Id $ProgressID -ParentId $ParentProgressID
            $x = test-acred $Name $Password ($ProgressID+101) ($ProgressID)
            $results.AddRange(@($x)) | Out-Null
            $x
            Write-Progress -Activity "Checking Creds" -Status "Checking $Name" -Id $ProgressID -ParentId $ParentProgressID -Completed
        }

    }
    End {
        if ($DestPath) {
            $results | Export-Csv -Path $DestPath -NoTypeInformation -NoClobber:(-not $AllowClobber)
        }
        if (-not $NoLockoutWait) {
            [System.Collections.ArrayList]$tocheck = @($results | Where-Object { $_.PasswordChecked -eq $true })
            $results.Clear()

            if ($tocheck.Count -gt 0) {
                $waitstarted = get-date
                $tocheck | ForEach-Object {
                    try {
                        $req = Get-ADUserResultantPasswordPolicy -Identity $_.SamAccountName -ErrorAction Stop
                    } catch {
						$req = $false
					}
                    if (-not $req) {
                        $req = Get-ADDefaultDomainPasswordPolicy
                    }
                    Add-Member -InputObject $_ -MemberType NoteProperty -Name "SafeTime" -Value ($waitstarted.Add($req.LockoutObservationWindow))
                }
                $waituntil = ($tocheck | measure-object -Property SafeTime -Maximum).Maximum
                Write-Verbose "Checking for user lockouts until $waituntil."
                [System.Collections.ArrayList]$toremove = @()
                if (-not (Test-Path variable:global:psISE)) {
                    $save_ccinput = [console]::TreatControlCAsInput
                    [console]::TreatControlCAsInput = $true
                } else {
                    Write-Warning "You are running inside PowerShell ISE. For more interactive functionality, run this cmdlet from regular powershell.exe. Pressing Ctrl+C will immediately exit this command, be careful."
                }
                while ($tocheck.Count -gt 0 -and (get-date) -le $waituntil) {
                    Write-Progress -SecondsRemaining (($waituntil.Subtract((get-date))).TotalSeconds) -Activity "Checking for Lockouts" -Status "Checking" -Id ($ProgressID+10) -ParentId $ParentProgressID
                    if ($VerbosePreference -notlike "*silently*") {
                        write-verbose "Checking $($tocheck.Count) accounts for lockout..."
                    } else {
                        write-Host "Checking $($tocheck.Count) accounts for lockout..."
                    }
                    $i = 0
                    $tocheck | ForEach-Object {
                        Write-Progress -PercentComplete ([int](100*($i++/($tocheck.Count)))) -Activity "Checking for Lockouts" -CurrentOperation "Checking $($_.SamAccountName)" -Status "Checking" -Id ($ProgressID+11) -ParentId ($ProgressID+10)
                        $u = get-aduser -Identity $_.SamAccountName -Properties LockedOut,Name,OfficePhone -Verbose:$false
                        if ($u.LockedOut) {
                            Write-Warning "User has been locked out!`nSamAccountName: $($u.SamAccountName)`nName: $($u.Name)`nPhone: $($u.OfficePhone)"
                            $toremove.Add($_) | Out-Null
                        }
                        $lastbadpw = (Get-RealLastBadPasswordAttempt -Identity $_.SamAccountName -Verbose:$false -ProgressId ($ProgressID+111) -ParentProgressId ($ProgressID+11)).LastBadPasswordAttempt_Maximum
                        if ($lastbadpw -gt $waitstarted) {
                            Write-Verbose "FYI: user failed to login after test completed.`nSamAccountName: $($u.SamAccountName)`nName: $($u.Name)`nPhone: $($u.OfficePhone)"
                        }
                        if ((get-date) -gt $_.SafeTime) {
                            $toremove.Add($_) | Out-Null
                        }
                    }
                    Write-Progress  -Activity "Checking for Lockouts" -CurrentOperation "Done Checking" -Status "Checking" -Completed -Id ($ProgressID+11) -ParentId ($ProgressID+10)

                    foreach ($r in $toremove) {
                        $tocheck.Remove($_)
                    }
                    $toremove.Clear()

                    if ($VerbosePreference -notlike "*silently*") {
                        Write-Verbose "Sleeping for 1 minute"
                    } else {
                        Write-Host "Sleeping for 1 minute"
                    }
                    $keep_going = $true
                    $count = 0
                    
                    
                    :sleepwhile While ($count -le 60) {
                        if (-not (Test-Path variable:global:psISE)) {
                            if ([console]::KeyAvailable) {
                                $key = [system.console]::readkey($true)
                                if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")) {
                                    $message  = 'You have not waited nearly long enough.'
                                    $question = 'Really quit?'

                                    $choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
                                    $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
                                    $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

                                    $decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)

                                    if ($decision -eq 0) {
                                        write-warning "Ending early due to user input."
                                        $tocheck.Clear()
                                        break sleepwhile
                                    }
                                } else {
                                    Write-Host "Press Ctrl+C to quit."
                                }
                            }
                        } else {
                            Write-Warning "Pressing Ctrl+C will immediately exit this command, be careful."                        }
                        $count++
                        Write-Progress -SecondsRemaining (($waituntil.Subtract((get-date))).TotalSeconds) -Activity "Checking for Lockouts" -Status "Sleeping" -Id ($ProgressID+10) -ParentId $ParentProgressID
                        Start-Sleep -m 1000    
                    }

                    
                    Write-Progress -SecondsRemaining (($waituntil.Subtract((get-date))).TotalSeconds) -Activity "Checking for Lockouts" -Status "Sleeping" -Id ($ProgressID+10) -ParentId $ParentProgressID

                }
                if (-not (Test-Path variable:global:psISE)) {
                    [console]::TreatControlCAsInput = $save_ccinput
                }
                            
                Write-Progress -Activity "Checking for Lockouts" -Id ($ProgressID+10) -ParentId $ParentProgressID -Completed
                
                if ($VerbosePreference -notlike "*silently*") {
                    Write-Verbose "Done Checking for Lockouts."
                } else {
                    Write-Host "Done Checking for Lockouts."
                }
            } else {
                Write-Verbose "No passwords were checked, no need to wait."
            }
        }
    
    
    
    }
}

