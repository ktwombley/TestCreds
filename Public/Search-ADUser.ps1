<#
.Synopsis
   Search for a user in AD by a portion of their name, employee ID, phone 
   number, address, etc.
.DESCRIPTION
   Searches Active Directory for a user account by matching against a large 
   variety of attributes. This search is much slower than simply using 
   Get-ADUser, so if you know the username (LanID) and are concerned about 
   speed, use Get-ADUser instead.

   The search is via wildcard, i.e. "*$Find*". For example, Search-ADUser "wombl" 
   will match a user whose Surname is "Twombley" but not a user whose Surname 
   is "Twamly".

   If you do not specify any Properties to return, a standard set which 
   Get-ADUser might give you are returned. In addition, any attributes which 
   match the Find string are also returned.
   
   These attributes are searched:
   * CN
   * Description
   * DisplayName
   * mail
   * EmployeeID
   * EmployeeNumber
   * GivenName
   * mailNickname
   * msRTCSIP-PrimaryUserAddress
   * Name
   * objectSid
   * physicalDeliveryOfficeName (Office)
   * telephoneNumber (OfficePhone)
   * pager
   * physicalDeliveryOfficeName
   * sAMAccountName
   * ServicePrincipalNames
   * sn (Surname)
   * telephoneNumber
   * uid
   * UserPrincipalName

.EXAMPLE
   PS C:\> Search-ADUser "wombl"

   Returns details about users who match "wombl".
.EXAMPLE
   PS C:\> Search-ADUser "wombl" -ServiceNow

   Returns details about users who match "wombl". Also looks through ServiceNow 
   gather.exe on each result.
.EXAMPLE
   PS C:\> Search-ADUser "wombl" -Properties MemberOf

   Returns details about users who match "wombl", including the groups the 
   matching users are members of.
#>
function Search-ADUser {
    param(
        #Text to find in users' AD attributes
        [parameter(Mandatory=$true,
            ValueFromPipeline=$true)]
        [Object[]]$Find,
        
        #Extra AD attributes to return
        [parameter()]
        [string[]]$Properties,

        #Care to give me a hint about what you're searching for?
        [parameter()]
        [ValidateSet("Auto","Email", "Number", "Freetext", "Thorough", "Name")]
        [string]$Hint = "Auto",

        #Be Thorough; Keep searching after we get a match.
        [parameter()]
        [switch]$Thorough,

        #Split up input into substrings and find any matches. This may give you a ton of false positives.
        #    If your search gets results by any other method, substrings will still be skipped. You can force
        #    Search-ADUser to do a substrings search by specifying both -Thorough and -TrySubstrings.
        [parameter()]
        [switch]$TrySubstrings,

        #When splitting text, discard portions shorter than this length.
        [parameter()]
        [int]$UsefulStrLen = 3,

        #Control recursion
        [parameter()]
        [bool]$Recurse = $true,

        #Specify current depth of recursion
        [parameter()]
        [int]$RecurseDepth = 0,

        #Id to pass to Write-Progress
        [parameter()]
        [int]$ProgressID = $RecurseDepth,
    
        #Id to pass to Write-Progress
        [parameter()]
        [int]$ParentProgressID = -1



    )
    Begin {
        if((Get-PSCallStack)[1].Command -eq (Get-PSCallStack)[0].Command) {
            Write-Verbose "I was called recursively. I promise to behave."
            $AmChildCall = $true
        } else {
            $AmChildCall = $false
        }

        $Pad = " " * $RecurseDepth

        if(-not $Properties) {
            $Properties = "DisplayName", "mail", "DistinguishedName", "Enabled", "LockedOut", "GivenName", "Name", "sAMAccountName","SID"
            Write-Verbose "$($Pad)Using default properties: $Properties"
        } else {
            Write-Verbose "$($Pad)Using supplied properties: $Properties"
        }
        #this array is sorted by quality; more specific stuff up front, more generic in the rear. This helps while guessing search criteria later.
        #$searches = "CN", "DisplayName", "mail", "EmployeeNumber", "mail", "mailNickname", "Name", "sAMAccountName", "sn", "ServicePrincipalNames", "Description", "objectSID", "physicalDeliveryOfficeName", "telephoneNumber", "pager", "physicalDeliveryOfficeName", "telephoneNumber", "uid", "UserPrincipalName", "GivenName", "EmployeeID" 
        #$searches = "CN", "DisplayName", "DistinguishedName", "mail", "EmployeeNumber", "GivenName", "HomeDirectory", "mail", "mailNickname", "mobile", "ipPhone", "Name", "telephoneNumber", "proxyAddresses", "sAMAccountName", "objectSID", "sn", "telephoneNumber", "UserPrincipalName", "Description", "st", "StreetAddress", "Title", "facsimileTelephoneNumber", "userWorkstations", "departmentNumber", "Division", "homeMDB", "physicalDeliveryOfficeName", "physicalDeliveryOfficeName", "l", "department", "o", "Company", "msExchDelegateListBL", "msExchHomeServerName"

$searches = @{
    Freetext = [System.Collections.ArrayList]@("cn", "displayName", "distinguishedName", "mail", "employeeNumber", "givenName", "homeDirectory", "mailNickname", "mobile", "ipPhone", "Name", "telephoneNumber", "proxyAddresses", "sAMAccountName", "objectSID", "sn", "userPrincipalName", "description", "st", "StreetAddress", "title", "facsimileTelephoneNumber", "userWorkstations", "departmentNumber", "division", "physicalDeliveryOfficeName", "l", "department", "o", "company", "msExchDelegateListBL")
    Email = [System.Collections.ArrayList]@("mail", "proxyAddresses", "userPrincipalName", "description", "mailNickname")
    Number = [System.Collections.ArrayList]@("employeeNumber", "homeDirectory", "mailNickname", "mobile", "ipPhone", "telephoneNumber", "proxyAddresses", "sAMAccountName", "objectSID", "UserPrincipalName", "description", "streetAddress", "facsimileTelephoneNumber", "physicalDeliveryOfficeName", "msExchDelegateListBL")
    Name = [System.Collections.ArrayList]@("displayName", "givenName", "cn", "sn")
}

        #Probe AD schema and remove any search attributes which don't exist here.
        if (-not $AmChildCall) {
            [System.Collections.ArrayList]$allowed_attribs = @()
            [System.Collections.Stack]$classes=@()
            $classes.Push('User') | Out-Null
            while($classes.Count -gt 0) {
                $c = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter "ldapDisplayName -eq '$($classes.Pop())'" -Properties 'AuxiliaryClass','SystemAuxiliaryClass','mayContain','mustContain','systemMayContain','systemMustContain','subClassOf','ldapDisplayName'
                Write-Debug "getting class $($c.Name)"
                if ($c.ldapDisplayName -ne $c.subClassOf) {
                    $classes.Push($c.subClassOf) | Out-Null
                    Write-Debug "pushing $($c.subClassOf)"
                }
                $allowed_attribs.AddRange($c.mayContain)
                $allowed_attribs.AddRange($c.mustContain)
                $allowed_attribs.AddRange($c.systemMaycontain)
                $allowed_attribs.AddRange($c.systemMustContain)
                foreach ($ax in $c.auxiliaryClass) {
                    $classes.Push($ax) | Out-Null
                    Write-Debug "pushing $($ax)"
                }
                foreach ($sax in $c.systemAuxiliaryClass) {
                    $classes.Push($sax) | Out-Null
                    Write-Debug "pushing $($sax)"
                }
            }
            $allowed_attribs = $allowed_attribs.GetEnumerator() | Sort-Object -Unique
            If ($allowed_attribs.Count -gt 0) {
                Write-Debug "Culling attribs down to this list: $($allowed_attribs)"

                foreach ($k in $searches.Keys) {
                    [System.Collections.ArrayList]$rm_me = @()
                    foreach ($i in $searches[$k]) {
                        if ($i -notin $allowed_attribs) {
                            $rm_me.Add($i) | Out-Null
                        }
                    }
                    foreach ($r in $rm_me) {
                        Write-Verbose "Removing $($r) from searches because it is not in your AD schema."
                        $searches[$k].Remove($r) | Out-Null
                    }
                }
                Write-Debug "Left with these searches: $($searches)"
            }
        }

        function _get_searches($findme) {
            if ($Hint -eq 'Thorough') {
                Write-Verbose "$($Pad)Trying thorough search for $findme"
                $ret = $searches['Freetext'] + $searches['Email'] + $searches['Number']
            } elseif ($Hint -ne 'Auto') {
                Write-Verbose "$($Pad)Trying user-specified search $Hint for $findme"
                $ret = $searches[$Hint]
            } else {
                #Auto mode!
                if ($findme -match '^[0-9]+$') {
                    Write-Verbose "$($Pad)Auto: Trying number search for $findme"
                    $ret = $searches['Number']
                } elseif ($findme -match '@') {
                    Write-Verbose "$($Pad)Auto: Trying email search for $findme"
                    $ret = $searches['Email'] 
                } else {
                    Write-Verbose "$($Pad)Auto: Trying Freetext search for $findme"
                    $ret = $searches['Freetext']
                }
            }

            return ($ret | Select-Unique)
        }

        function _fix_FilterProps($result, $tofind) {
            foreach ($aprop in $result.PSObject.Properties) {
                if($aprop.Value -like "*$tofind*") {
                    #Since subsearch matches might not match the main search, fix-up the FilterProperties so they get kept.
                    try {
                        $FilterProperties.Remove($aprop.Name)
                    } catch {
                        #we weren't going to filter it anyway.
                    }
                }
            }
        }


    }

    Process {
        Foreach ($afind in $Find) {

            Write-Progress -Activity "Searching for $afind" -Id $ProgressID -PercentComplete 0 -ParentId $ParentProgressID
            if ($TrySubstrings) {
                $MaxSearchSteps = 6
            } else {
                $MaxSearchSteps = 5
            }
    
            if ($afind.GetType() -ne [String]) {
                $found_search = ($searches.count)+1
                $Find_criteria = $false
                foreach ($p in $afind.PSObject.Properties) {
                    for ($i=0;$i -lt $searches.count;$i++) {
                        if ($p.Name -eq $searches[$i]) {
                            if ($i -lt $found_search) {
                                $found_search = $i
                                $Find_criteria = $p.Value
                            }
                            break
                        }
                    }

                }

                if ($found_search -lt $searches.Count) {
                    Write-Verbose "$($Pad)Searching for $Find_criteria found in attribute $($searches[$found_search]) of object"
                    $Find = $Find_criteria
                } else {
                    $afind = $afind.ToString()
                    Write-Warning "$($Pad)Object did not have any suitable attributes, used ToString() to generate search term '$afind'"
                }
            } else {
                Write-Verbose "$($Pad)Searching for '$afind', supplied as a String variable."
            }
            $Searches_to_Perform = _get_searches($afind)
            if($Properties -ne "*") {
                $FindProperties = $Properties + $Searches_to_Perform | Select-Unique
                $FilterProperties = $Searches_to_Perform | ForEach-Object {if($Properties -notcontains $PSItem) { $PSItem } }
            } else {
                $FindProperties = "*"
                $FilterProperties = @()
            }
            Write-Verbose "$($Pad)User wants these properties: $($Properties)"
            Write-Verbose "$($Pad)Searching for these properties: $($FindProperties)"
            Write-Verbose "$($Pad)Planning on removing these properties: $($FilterProperties)"
            [System.Collections.ArrayList]$Search_Results = @()

            ###
            #
            # Try 1: Basic search for namey-stuff
            #
            ###
            # We can just skip this if we are going to do a thorough search anyhow.
            if (-not $Thorough) {
                Write-Progress -Activity "Searching for $afind" -Id $ProgressID -PercentComplete (100*(1/$MaxSearchSteps)) -CurrentOperation "Basic search"  -ParentId $ParentProgressID
                try {
                    #This search sufficient for lots of inputs.
                    $Search_Results.AddRange(@(Get-ADUser -Filter "sAMAccountName -like `"*$afind*`" -or mail -like `"*$afind*`" -or DisplayName -like `"*$afind*`"" -Properties $FindProperties))
                    Write-Verbose "$($Pad)  Basic search found $($Search_Results.Count) results."
                } catch {
                    #I guess there's no results?
                }        
            }

            ###
            #
            # Try 2: Thorough search through all $Searches_to_Perform
            #
            ###
            $oldcount = $Search_Results.Count
            if ($oldcount -eq 0 -or $Thorough) {
                Write-Progress -Activity "Searching for $afind" -Id $ProgressID -PercentComplete (100*(2/$MaxSearchSteps)) -CurrentOperation "Thorough search"  -ParentId $ParentProgressID
                Write-Verbose "$($Pad)  Trying thorough search."
                $i = 0
                $Search_Results.AddRange(@($Searches_to_Perform | ForEach-Object {
                    Write-Progress -Activity "Searching for $afind" -Status "Thorough Search" -CurrentOperation "$PSItem" -PercentComplete (100*$i++/$Searches_to_Perform.Count) -ParentId $ProgressID -Id ($ProgressID+2)
                    Get-ADUser -Filter "$($PSItem) -like `"*$afind*`"" -Properties $FindProperties
                }))
                Write-Progress -Activity "Searching for $afind" -Status "Thorough Search Done" -Completed -ParentId $ProgressID -Id ($ProgressID+2)
                Write-Verbose "$($Pad)  Thorough search found $($Search_Results.Count-$oldcount) results."
            }

            ###
            #
            # Try 3: Scramble names in case they are reversed. Doe, John -> John Doe
            #
            ###
            $oldcount = $Search_Results.Count
            if ($Recurse -and ($oldcount -eq 0 -or $Thorough)) {
                Write-Progress -Activity "Searching for $afind" -Id $ProgressID -PercentComplete (100*(3/$MaxSearchSteps)) -CurrentOperation "Name reverse search"  -ParentId $ParentProgressID
                Write-Verbose "$($Pad)  Trying name reverse search: Doe, John -> John Doe; John Doe -> Doe, John."

                $fname = $null
                $mname = $null
                $minit = $null
                $lname = $null
                $suffix = $null

                $searchparts =  $afind -split '\s+'
                if ($searchparts.Count -eq 1) {
                    #Doe
                    $lname = $searchparts[0].TrimEnd(',')        
                }
                if ($searchparts.Count -eq 2) {
                    if ($searchparts[0][-1] -eq ',') {
                        #Doe, John becomes:
                        #Doe John
                        #John Doe
                        #John, Doe
                        $fname = $searchparts[1].TrimEnd(',')
                        $lname = $searchparts[0].TrimEnd(',')
                    } else {
                        $fname = $searchparts[0].TrimEnd(',')
                        $lname = $searchparts[1].TrimEnd(',')
                    }         
                }
                if ($searchparts.Count -eq 3) {
                    if ($searchparts[0][-1] -eq ',') {
                        #Doe, Jane Q.
                        #Smith, John Quincy
                        $fname = $searchparts[1]
                        if ($searchparts[2].TrimEnd('.').Length -eq 1) {
                            $minit = $searchparts[2]
                        } else {
                            $mname = $searchparts[2]
                            $minit = $mname[1]
                        }
                        $lname = $searchparts[0].TrimEnd(',')
                    } else {
                        #Jane Quincy Smith
                        #Jane Q. Doe
                        #John Smith, Jr.
                        $fname = $searchparts[0].TrimEnd(',')
                        if ($searchparts[2].TrimEnd('.') -in @('Jr', 'Junior', 'II', 'III', 'IV')) {
                            #John Smith, Jr.
                            $mname = $null
                            $lname = $searchparts[1].TrimEnd(',')
                            $suffix = $searchparts[2].TrimEnd('.')
                        } else {
                            #John Quincy Smith
                            #Jane Q. Smith
                            if ($searchparts[1].TrimEnd('.').Length -eq 1) {
                                $minit = $searchparts[1]
                            } else {
                                $mname = $searchparts[1]
                                $minit = $mname[1]
                            }
                            $lname = $searchparts[2].TrimEnd(',')                    
                        }
                    }
                }

                [System.Collections.ArrayList]$namesearch = @()

                if ($lname) {
                    $namesearch.Add($lname) | Out-Null
                }
                if ($fname) {
                    $namesearch.AddRange(@(
                        "$($lname) $($fname)",
                        "$($lname), $($fname)",
                        "$($fname) $($lname)",
                        "$($fname), $($lname)"
                    )) | Out-Null
                }
                if ($mname) {
                    $namesearch.AddRange(@(
                        "$($fname) $($mname) $($lname)",
                        "$($fname) $($mname) $($lname)",
                        "$($lname) $($fname) $($mname)",
                        "$($lname), $($fname) $($mname)"
                    )) | Out-Null
                }
               if ($minit) {
                    #since the searches are wrapped in wildcards, there's no need to add a period at the end for Smith, John Q.
                    $namesearch.AddRange(@(
                        "$($fname) $($minit) $($lname)",
                        "$($fname) $($minit). $($lname)",
                        "$($lname) $($fname) $($minit)",
                        "$($lname), $($fname) $($minit)"
                    )) | Out-Null
                }

               if ($suffix) {
                    #since the searches are wrapped in wildcards, there's no need to add a period at the end for John Smith, Jr.
                    $namesearch.AddRange(@(
                        "$($fname) $($lname) $($suffix)",
                        "$($fname) $($lname), $($suffix)",
                        "$($lname) $($fname) $($suffix)",
                        "$($lname), $($fname), $($suffix)"
                    )) | Out-Null
                }

                #Sort by length, descending.
                #filter out original text, whatever it was.
                $namesearch = @(($namesearch | Sort-Object -Property Length -Descending)) -ne $afind

                $i = 0
 
                $results_agg = @{}
                Write-Verbose "$($Pad)  Doing $($namesearch.Count) name reverse subsearches."

                foreach ($anamesearch in $namesearch) {
                    Write-Progress -Activity "Searching for $afind" -Id ($ProgressID+3) -PercentComplete (100*($i++/$namesearch.Count)) -CurrentOperation $anamesearch -ParentId $ProgressID

                    $subres = Search-ADUser -Find $anamesearch -Properties $FindProperties -Hint Name -UsefulStrLen $UsefulStrLen -Recurse $false -RecurseDepth ($RecurseDepth+1) -ProgressID ($ProgressID+30) -ParentProgressID ($ProgressID+3)
                    foreach ($r in $subres) {
                        $results_agg.Add($r.DistinguishedName, $r)
                        _fix_FilterProps $r $anamesearch
                    }
                    if (-not $Thorough -and $results_agg.Count -gt 0) {
                        #If we are not Thorough, and we got some results, we are done.
                        #This prevents a search for "Jane Smith" from polluting the search results with
                        #every single 'smith' in your organization.
                        Write-Progress -Activity "Searching for $afind" -Id ($ProgressID+3) -Complete  -ParentId $ProgressID
                        break
                    }
                    Write-Progress -Activity "Searching for $afind" -Id ($ProgressID+3) -Complete  -ParentId $ProgressID
                }

                $Search_Results.AddRange(@($results_agg.Values))
                Write-Verbose "$($Pad)  Name reverse search found $($Search_Results.Count-$oldcount) results."
            }

            ###
            #
            # Try 4: Search for user names in an email address
            #
            ###
            $oldcount = $Search_Results.Count
            if ($Recurse -and ($oldcount -eq 0 -or $Thorough)) {
                Write-Progress -Activity "Searching for $afind" -Id $ProgressID -PercentComplete (100*(4/$MaxSearchSteps)) -CurrentOperation "Email chunk search"  -ParentId $ParentProgressID
                 Write-Verbose "$($Pad)  Trying email address search: jane.smith@example.com -> 'jane smith'"
                
                ($un, $dom) = $afind.Split('@')
                $searchparts =  @($un -split '\.|\s+' | Where-Object Length -ge $UsefulStrLen) -ne $afind
                if ($searchparts) {
                    $emailchunks = @($searchparts) -join " "
                    if ($emailchunks -ne $afind) {
                        Write-Verbose "$($Pad)  Doing subsearch for $($emailchunks) from email address: $afind."
                        #Original search was an email address, so this recursion is OK; we will not get caught in a loop. ...I think.
                        $subres = Search-ADUser -Find $emailchunks -Properties $FindProperties -Hint Name -UsefulStrLen $UsefulStrLen -Recurse $True -RecurseDepth ($RecurseDepth+1) -ProgressID ($ProgressID+40)  -ParentProgressID $ProgressID
                        foreach ($r in $subres) {
                            $results_agg.Add($r.DistinguishedName, $r)
                            _fix_FilterProps $r $emailchunks
                        }
                        $Search_Results.AddRange(@($results_agg.Values))
                    }
                }
                Write-Verbose "$($Pad)  Email search found $($Search_Results.Count-$oldcount) results."
            }


            ###
            #
            # Try 5: Not enabled by default! tokenize string on non-letter boundaries, search for them all.
            #
            ###
            $oldcount = $Search_Results.Count
            if ($TrySubstrings -and ($oldcount -eq 0 -or $Thorough)) {
                Write-Progress -Activity "Searching for $afind" -Id $ProgressID -PercentComplete (100*(5/$MaxSearchSteps)) -CurrentOperation "Substrings search"  -ParentId $ParentProgressID
                Write-Warning "$($Pad)  Trying substrings: jane.smith@example.com -> 'jane', 'smith', 'example', 'com'"
                Write-Warning "$($Pad)      You may get false positives."
                # We have found nothing so far. Proceed grasping at straws by exploding the text and looking for substrings."
                $searchparts =  $afind -split '\W+' | Where-Object Length -ge $UsefulStrLen
                Write-Verbose "$($Pad)  Substrings found $($searchparts.Count) strings from query: $afind."
                if ($searchparts.Count -gt 0) {
                    $results_agg = @{}
                    $i=0
                    foreach ($sp in $searchparts) {
                        Write-Progress -Activity "Searching for $afind" -Id ($ProgressID+5) -ParentId $ProgressID -PercentComplete (100*($i++/$searchparts.Count)) -CurrentOperation "Substrings search"
                        $subres = Search-ADUser -Find $sp -Properties $FindProperties -Hint Name -UsefulStrLen $UsefulStrLen -RecurseDepth ($RecurseDepth+1) -ProgressID ($ProgressID+50) -ParentProgressID ($ProgressID+5)
                        foreach ($r in $subres) {
                            $results_agg[$r.DistinguishedName] = $r
                            _fix_FilterProps $r $sp
                        }
                        Write-Progress -Activity "Searching for $afind" -Id ($ProgressID+5) -ParentId $ProgressID -Complete -CurrentOperation "Substrings search"
                    }
                    $Search_Results.AddRange(@($results_agg.Values))
                }
                Write-Verbose "$($Pad)  Substrings search found $($Search_Results.Count-$oldcount) results. Good luck!"
            }
            Write-Progress -Status "Done" -Activity "Searching for $afind" -Complete -Id $ProgressID  -ParentId $ParentProgressID
        }
        $Search_Results | Sort-Object -Property DistinguishedName -Unique | ForEach-Object {
            $a_result = $PSItem
            if(-not $AmChildCall) {
                foreach ($a_search in $FilterProperties) {
                    $a_prop_val = $a_result | Select-Object -ExpandProperty $a_search -ErrorAction SilentlyContinue
                    if((-not $a_prop_val) -or $a_prop_val -notlike "*$afind*") {
                        #Write-Verbose "$($Pad)Culling $a_search since its value is $a_prop_val"
                        $a_result = $a_result | Select-Object -Property * -ExcludeProperty $a_search
                        #$a_result.PropertyNames = $a_result.PropertyNames | ForEach-Object {if($a_search -ne $PSItem) { $PSItem } }
                    }
                    else {
                        #Write-Verbose "$($Pad)Keeping $a_search since its value is $a_prop_val"
                    }
                }
            }
            $a_result | Write-Output
        }
        Write-Progress -Status "Done" -Activity "Searching for $afind" -Complete -Id $ProgressID  -ParentId $ParentProgressID
    }
}
