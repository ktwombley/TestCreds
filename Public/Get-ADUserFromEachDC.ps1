<#
.Synopsis
   Gets properties of an Active Directory user by asking every domain controller.
.DESCRIPTION
   This cmdlet asks every domain controller it can find for the
   user and properties you specify. It aggregates the answers with the
   aggregation methods you specify, or returns all of the answers if you want.

.EXAMPLE
   $a = Get-ADUserFromAllDCs jsmith LastBadPasswordAttempt -Aggregation Maximum
   $a.LastBadPasswordAttempt_Maximum

   This returns the latest LastBadPasswordAttempt for the user jsmith. To
   find the answer, examine the LastBadPasswordAttempt_Maximum property. To
   find the DC which reported the maximum value, examine the
   LastBadPasswordAttempt_Maximum_DC property.
.EXAMPLE
   Get-ADUserFromAllDCs jsmith LastBadPasswordAttempt -All

   This returns the LastBadPasswordAttempt from each Domain Controller for the 
   user jsmith. Each object will have an additional property named
   AccordingToDomainController which contains the name of the DC which gave
   this object.
.EXAMPLE
   $a = Get-ADUserFromAllDCs jsmith LastLogon,WhenChanged -Aggregation Maximum,Minimum
   $a.psobject.Properties | where-object {$_.Name -like "*_M*"} | Select-Object Name, Value

   Name                                                                      Value
   ----                                                                      -----
   LastLogon_Maximum                                            130880975027006259
   LastLogon_Maximum_DC                                            DC1.contoso.com
   LastLogon_Minimum                                            130850882425322816
   LastLogon_Minimum_DC                                            DC7.contoso.com
   WhenChanged_Maximum                                        1/24/2014 9:00:42 AM
   WhenChanged_Maximum_DC                       {DC1.contoso.com, DC2.contoso.com}
   WhenChanged_Minimum                                        1/24/2014 8:59:45 AM
   WhenChanged_Minimum_DC                                          DC7.contoso.com

   This returns the maximum and minimum of each of the LastLogon and 
   WhenChanged properties. Each is separate.
.EXAMPLE
   Get-ADUserFromAllDCs jsmith LastLogon,WhenChanged -Aggregation Count 
   -Server DC1.contoso.com,DC7.contoso.com

   This returns the count of LastLogon and WhenChanged properties from only
   DC1.contoso.com and DC7.contoso.com.

.OUTPUTS
    Microsoft.ActiveDirectory.Management.ADUser
    Returns one or more user objects.

    This cmdlet adds additional properties to the objects based on the 
    arguments supplied.
    * -All: AccordingToDomainController added; contains the DC which gave 
    this object.
    * -Aggregate: PropertyName_Maximum, etc. added; contains the aggregate
    value for that Property.

#>
function Get-ADUserFromAllDCs
{
    [CmdletBinding(DefaultParameterSetName="Aggregate")]

    Param
    (
        # Specifies an Active Directory user object. See "Get-Help Get-ADUser 
        # -Parameter Identity" for help.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Identity,
        # Specifies the properties of the output object to retrieve from the
        # server. The values will be aggregated (if applicable) by the methods
        # you choose in the Aggregation parameter.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
            Position=1)]
        [String[]]$Properties,
        # Specifies the methods by which the Properties will be aggregated.
        #
        # Aggregation methods are:
        #   Maximum - Finds the largest value of the given Properties.
        #   Minimum - Finds the smallest value of the given Properties.
        #   Count   - Count the results.
        #   Median  - Sorts the results, then returns the middle value of the
        # given Properties.
        #   Mode    - Finds the most common value of the given Properties.
        #   Mean    - Finds the arithmetic mean (sum the values, then divide by
        # the count) of the given Properties.
        #   Average - Finds the Mean of the given Properties.
        #   Sum     - Finds the sum of the given Properties.
        #
        # Get-ADUserFromAllDCs will return a single Get-ADUser object in this
        # case. It will have all of the usual properties, but will also have
        # additional properties based on which Aggregation parameters you
        # specified. The additional properties will be named with the form 
        # "<Property Name>_<Aggregation>". So if you specify "LastLogon" as the
        # property, and "Maximum" as the aggregation, the additional property
        # will be named "LastLogon_Maximum".
        #
        # When it makes sense, Get-ADUserFromAllDCs will also include the name
        # of the domain controller it fetched the value from. This will be
        # named with the form "<Property Name>_<Aggregation>_DC", so if you 
        # specify "LastLogon" and "Maximum", then LastLogon_Maximum_DC will
        # contain the name of the domain controller where Get-ADUserFromAllDCs
        # found the maximum value of the LastLogon property.
        #
        # Note that the returned object is copied from one of the responses so
        # its properties have no special relation to the aggregate properties
        # you asked for. In other words, LastLogon does not neccessarily equal
        # LastLogon_Maximum, etc.
        #
        # When dealing with DateTime objects, Get-ADUserFromAllDCs will try to
        # turn the aggregate values back into DateTime objects when it makes
        # sense. This works well for Maximum, Minimum, Median, Mode, Mean, and
        # Average. It doesn't make sense for Count, you'll just get a number.
        # It's easy to Sum up a number larger than DateTime can hold, so do
        # not rely on a Sum being a valid DateTime. Get-ADUserFromAllDCs will
        # emit a warning when a Sum is too big for a DateTime.
        #
        # Get-ADUserFromAllDCs only works on the properties which have values.
        # This is helpful when you are dealing with properties which may be
        # null in some domain controllers, but have valid values in others.
        # This behavior is so this will return what you expect:
        #
        # PS C:\> Get-ADUserFromAllDCs username LastLogon -Aggregation Minimum
        #
        # Do not be surprised when the count of your results is not equal to
        # the number of domain controllers you have.
        [Parameter(Mandatory=$true,
            ParameterSetName="Aggregate",
            Position=2)]
        [ValidateSet("Maximum","Minimum","Count","Median","Mode","Mean","Average","Sum")]
        [String[]]$Aggregation,
        # Instead of aggregating the results, return all of them.
        # 
        # This will include an additional property in the resulting objects
        # named AccordingToDomainController.
        [Parameter(Mandatory=$true,ParameterSetName="All")]
        [switch]$All,
        # Instead of querying all domain controllers, query only these specific
        # servers. Must be a list of domain controller names suitable for the 
        # -Server parameter of Get-ADUser. See "Get-Help Get-ADUser -Parameter
        # Server" for more help. Note that Get-ADUserFromAllDCs allows an 
        # array whereas Get-ADUser allows a single value.
        [Parameter(Mandatory=$false)]
        [String[]]$Server = "*",

        #Id to pass to Write-Progress
        [parameter()]
        [int]$ProgressID = 0,
    
        #Id to pass to Write-Progress
        [parameter()]
        [int]$ParentProgressID = -1
        
    )
    Begin {
        if($Server -eq "*") {
            $Server = get-addomaincontroller -Filter * | select-object -ExpandProperty HostName
        }
        if($Aggregation -contains "Average") {
            Write-Verbose "Replacing 'Average' with 'Mean'"
            $Aggregation = $Aggregation | Where-Object {$PSItem -ne "Average"}
            if($Aggregation -notcontains "Mean") {
                $Aggregation += "Mean"
            } else {
                Write-Verbose "Found 'Mean' already, no need to add it."
            }
        }
    }
    Process
    {
        $progress_servers = $Server.Count
        $progress_total = $progress_servers
        if(-not $All) {
            $progress_total_props = $Properties.Count
            $progress_total_aggs = $Aggregation.Count
            $progress_total_props_agg = $progress_total_props * $progress_total_aggs
            $progress_total += $progress_total_props_agg  
        }

        Write-Progress -Activity "Getting $Identity from $progress_servers." -PercentComplete 0 -Id $ProgressID -ParentId $ParentProgressID

        $all_results =  $Server | foreach-object -Begin { $i=0 } -Process { 
            $dcname=$PSItem
            Write-Progress -Activity "Getting $Identity from $progress_servers."-CurrentOperation "Querying $dcname" -PercentComplete ([int](100 * $i / $progress_total)) -Id $ProgressID -ParentId $ParentProgressID
            Write-Progress -Activity "Querying DCs" -CurrentOperation "Querying $dcname" -PercentComplete ([int](100 * $i / $progress_servers))  -Id ($ProgressID+1) -ParentId $ProgressID
            get-aduser $Identity -Server $dcname -Properties $Properties | Add-Member -MemberType NoteProperty -Name "AccordingToDomainController" -Value $dcname -PassThru -Force
            Write-Verbose "Got answer from DC $dcname"
            $i++
        }
        Write-Progress -Activity "Querying DCs" -CurrentOperation "Querying $dcname" -Completed -Id ($ProgressID+1) -ParentId $ProgressID
        if($All) {
            $all_results
        } else {
            $out_obj = $all_results | Select-Object -First 1 -Property * -ExcludeProperty "AccordingToDomainController"
            $Properties | Foreach-Object -Begin { $i_props=0 } -Process {
                $Property_name = $PSItem
                $i_props++
                $props = $all_results | Select-Object -ExpandProperty $Property_name -ErrorAction "SilentlyContinue"
                Write-Verbose "Working on $Property_name, $($props.Count) results"

                Write-Progress -Activity "Getting $Identity from $progress_servers." -CurrentOperation "Examining $Property_name" -PercentComplete ([int](100 * ($i+($i_props-1)*$progress_total_aggs) / $progress_total)) -Id $ProgressID -ParentId $ParentProgressID
                Write-Progress -Activity "Examining Properties" -CurrentOperation "Examining $Property_name" -PercentComplete ([int](100 * $i_props / $progress_total_props))  -Id ($ProgressID+2) -ParentId $ProgressID

                $Aggregation | ForEach-Object -Begin { $i_aggs=0 } -Process {
                    $Aggregation_method = $PSItem
                    $i_aggs++
                    $prog_val = [int](100 * ($i+($i_props-1)*$progress_total_aggs+$i_aggs) / $progress_total)
                    $prog_val = [int](100 * ($i_aggs) / $progress_total_aggs)
                    switch ($Aggregation_method) {
                        "Maximum" {
                            $agg = ($props | Sort-Object -Descending | Select-Object -First 1)
                            $New_Property_Name = "$($Property_name)_Maximum"

                        }
                        "Minimum" {
                            $agg = ($props | Sort-Object | Select-Object -First 1)
                            $New_Property_Name = "$($Property_name)_Minimum"
                        }
                        "Count" {
                            $agg = $props.Count
                            $New_Property_Name = "$($Property_name)_Count"
                        }
                        "Median" {
                            $agg = $props | Sort-Object | Select-Object -Index ([Math]::floor($props.Count/2))
                            $New_Property_Name = "$($Property_name)_Median"
                        }
                        "Mode" {
                            $mode_info = ($props | Group-Object | Sort-Object Count -Descending | Select-Object -First 1)
                            $agg = $mode_info.Name
                            $New_Property_Name = "$($Property_name)_Mode"
                            #Also add a special "ModeCount" property containing the count of the mode we found.
                            Add-Member -InputObject $out_obj -MemberType NoteProperty -Name "$($Property_name)_ModeCount" -Value $mode_info.Count -Force
                        }
                        "Sum" {
                            $agg = $props | Foreach-Object -Begin { $result=0 } -Process { $result += if($_.Ticks){$_.Ticks} else {$_} } -End { if($props[0].Ticks) {if($result -le [DateTime]::MaxValue.Ticks){[DateTime][Int64]$result} else {Write-Warning "Sum of DateTimes is too big to store in a DateTime. Returning Ticks instead"; $result} } else {$result} }
                            $New_Property_Name = "$($Property_name)_Sum"

                        }
                        "Mean" {
                            $agg = ($props | Foreach-Object -Begin { $result=0 } -Process { $result += if($_.Ticks){$_.Ticks} else {$_} } -End { if($props[0].Ticks){[DateTime][Int64]($result/$props.Count)} else {$result/$props.Count} })
                            $New_Property_Name = "$($Property_name)_Mean"
                        }
                        default { write-error "Aggregation not understood. Shouldn't get here." }
                    }
                    Write-Verbose "    $New_Property_Name = $agg"
                    Add-Member -InputObject $out_obj -MemberType NoteProperty -Name $New_Property_Name -Value $agg -Force
                    if($matching_DC = $all_results | Where-Object {($PSItem | Select-Object -ExpandProperty $Property_name -ErrorAction "SilentlyContinue") -eq $agg} | Select-Object -ExpandProperty AccordingToDomainController) {
                        Write-Verbose "      $($new_Property_Name)_DC = $matching_DC"
                        Add-Member -InputObject $out_obj -MemberType NoteProperty -Name "$($new_Property_Name)_DC" -Value $matching_DC -Force
                    }
                }
            
            }
            Write-Progress -Activity "Getting $Identity from $progress_servers." -CurrentOperation "Examining $Property_name" -PercentComplete ([int](100 * ($i+($i_props-1)*$progress_total_aggs) / $progress_total)) -Id $ProgressID -ParentId $ParentProgressID
            Write-Progress -Activity "Examining Properties" -CurrentOperation "Done" -Completed -Id ($ProgressID+2) -ParentId $ProgressID

            $out_obj
        }
        Write-Progress -Activity "Getting $Identity from $progress_servers." -CurrentOperation "Done." -Completed -Id $ProgressID -ParentId $ParentProgressID
    }
}
