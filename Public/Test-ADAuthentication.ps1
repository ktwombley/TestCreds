<#
.Synopsis
   Test a user's credentials.
.DESCRIPTION
   Returns $true if the username and password are valid. $false otherwise.

   You can pass it a username, password, or credentials (from get-credentials). If it doesn't have enough information, it will prompt for the rest.

   From here with modifications:
   http://serverfault.com/questions/410240/is-there-a-windows-command-line-utility-to-verify-user-credentials
#>
Function Test-ADAuthentication {
    param(
        [Parameter(Mandatory=$false)]
        $Username=$null,
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential=(Get-Credential -Credential $Username)
    )
    
    if($Credential -eq $null) {
        $Credential = Get-Credential -Credential $Username
    }

    Try {
        $dummy = Get-ADDomain -Credential $Credential -ErrorAction "Stop"
        $true
    }
    Catch [System.Security.Authentication.AuthenticationException] {
        $false
    }
    Catch [System.Management.Automation.RemoteException] {
        if ($_.CategoryInfo.Reason -eq "AuthenticationException"){

            $false
        }
        else{
            Write-Warning "Caught unexpected remote exception. Results suspicious."
            Write-Warning (Resolve-Error $_ | Out-String)
            $false
        }
    }
    Catch {
        Write-Warning "Caught unexpected exception. Results suspicious."
        Write-Warning (Resolve-Error $_ | Out-String)
        #Hey man I got stuff to do. I'm not dealing with this.
        $false
    }

}