<#
.Synopsis
   Output unique items without sorting first.
.DESCRIPTION
   Select-Unique outputs only the unique items supplied as input.

   It can use more memory than other methods (such as sorting and using Get-Unique) because it uses a hashtable to remember which items it has seen.

   It has the advantage of preserving the order of input items if that's important to you.


.EXAMPLE
   'foo','bar','foo' | Select-Unique    # results in 'foo','bar'
.INPUTS
   Anything
.OUTPUTS
   Anything, minus duplicates.
.NOTES
   In order to work correctly with objects, it serializes them into json. So, according to Select-Unique, two objects are identical if ($a | ConvertTo-Json) -eq ($b | ConvertTo-Json)
#>
function Select-Unique {
    [CmdletBinding()]
    Param (
		#Input Items from Pipeline
		[Parameter(Mandatory=$false,ValueFromPipeline=$true)]
		[PSObject[]]$Input
	)
	
	Begin {
		[hashtable]$seen = @{}
	}
	
	Process {
		foreach ($inp in $Input) {
			if ($inp -ne $null) {
                $k = $inp | ConvertTo-Json
                if ($seen.ContainsKey($k)) {
				    Write-Debug "Select-Unique Omitting $inp"
			    } else {
				    $seen[$k] = $true
				    $inp
			    }
            }
		}
	}
	
	End {
	}
}
