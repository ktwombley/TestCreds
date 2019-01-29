<#
.Synopsis
   Joins two strings with a separator
.DESCRIPTION
   Joins First and Second with Separator, but ensures it looks nice even if one string is empty.

   The default separator is a single space, but it can be any string you want. Even multiple characters. WE TRULY LIVE IN THE FUTURE!
.EXAMPLE
   Merge-StringList -First "hello" -Second "World"

   Hello World
.EXAMPLE
   $hello = ""
   $world = "world"
   Merge-StringList -First $hello -Second $World

   world

   Note there is no leading space. Merge-StringList won't ever let you down.
.EXAMPLE
   "hello","world" | Merge-StringList -Sep "x"

   "helloxworld"

   If you pipe a list in, Merge-StringList joins them all. Also you can specify the separator.
#>
function Merge-StringList
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # First string.
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0)]
        [object[]]$First,

        # Second string. 
        [Parameter(Mandatory=$false,
            Position=1)]
        [object[]]$Second,

        # String to use to join them together
        [Parameter(Mandatory=$false,
                   Position=2)]
        [string]$Sep = " "

    )

    Begin
    {
        $out = [System.Text.StringBuilder]::new()
    }
    Process
    {
        foreach ($s in $First) {
            [string]$s = [string]$s
            if($s -and $s -ne '' -and $s -ne [String]::Empty) {
                if ($out.Length -ne 0) {
                    $out.Append($Sep) | Out-Null
                }
                $out.Append($s) | Out-Null
            }
        }
       foreach ($s in $Second) {
            [string]$s = [string]$s
            if($s -and $s -ne '' -and $s -ne [String]::Empty) {
                if ($out.Length -ne 0) {
                    $out.Append($Sep) | Out-Null
                }
                $out.Append($s) | Out-Null
            }
        }
    }
    End
    {
        $out.ToString()
    }
}