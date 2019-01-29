<#
.Synopsis
   Gets the most recent LastBadPasswordAttempt by asking every domain controller.
.DESCRIPTION
   The value of LastBadPasswordAttempt you receive from Get-ADUser is only the 
   last bad password attempt that the domain controller you are querying has
   seen. This Cmdlet gets around this by asking every single domain controller.
.EXAMPLE
   Get-RealLastBadPasswordAttempt jsmith

   This returns the latest LastBadPasswordAttempt for the user jsmith
.EXAMPLE
   Get-RealLastBadPasswordAttempt jsmith -All

   This returns the LastBadPasswordAttempt from each Domain Controller for the user jsmith.
#>
function Get-RealLastBadPasswordAttempt
{
    [CmdletBinding()]
    Param
    (
        # The user whose bad password attempts you care about.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Identity,
        # Return all LastBadPasswordAttempts found
        [switch]$All,

        
        #Id to pass to Write-Progress
        [parameter()]
        [int]$ProgressID = 0,
    
        #Id to pass to Write-Progress
        [parameter()]
        [int]$ParentProgressID = -1


    )

    Process
    {
        if($All) {
            Get-ADUserFromAllDCs $Identity LastBadPasswordAttempt -All -ProgressID $ProgressID -ParentProgressID $ParentProgressID
        } else {
            Get-ADUserFromAllDCs $Identity LastBadPasswordAttempt -Aggregation Maximum -ProgressID $ProgressID -ParentProgressID $ParentProgressID
        }
    }

}