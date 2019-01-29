
if (-not ([System.Management.Automation.PSTypeName]'TestCreds.NetPWChk').Type) {
$defs = @"

[DllImport("Netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern NET_API_STATUS NetValidatePasswordPolicy(
    [MarshalAs(UnmanagedType.LPWStr)]
    string ServerName,
    IntPtr Qualifier,
    NET_VALIDATE_PASSWORD_TYPE ValidationType,
    IntPtr InputArg,
    ref IntPtr OutputArg);

[DllImport("Netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern NET_API_STATUS NetValidatePasswordPolicyFree(ref IntPtr OutputArg);

	
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NET_VALIDATE_OUTPUT_ARG
{
    public NET_VALIDATE_PERSISTED_FIELDS ChangedPersistedFields;
    public NET_API_STATUS ValidationStatus;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NET_VALIDATE_PASSWORD_HASH
{
    public uint Length;
    public IntPtr Hash;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NET_VALIDATE_AUTHENTICATION_INPUT_ARG
{
    public NET_VALIDATE_PERSISTED_FIELDS InputPersistedFields;

    [MarshalAs(UnmanagedType.I1)]
    public bool PasswordMatched;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NET_VALIDATE_PASSWORD_CHANGE_INPUT_ARG
{
    public NET_VALIDATE_PERSISTED_FIELDS InputPersistedFields;

     // Don't use a managed string, you can't securely clean that up.
     // Use Marshal.SecureStringToBSTR() and Marshal.ZeroFreeBSTR() to get and clean up a native string pointer.
    public IntPtr ClearPassword;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string UserAccountName;

    public NET_VALIDATE_PASSWORD_HASH HashedPassword;

    [MarshalAs(UnmanagedType.I1)]
    public bool PasswordMatched;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NET_VALIDATE_PASSWORD_RESET_INPUT_ARG
{
    public NET_VALIDATE_PERSISTED_FIELDS InputPersistedFields;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string ClearPassword;

    [MarshalAs(UnmanagedType.LPWStr)]
    public string UserAccountName;

    public NET_VALIDATE_PASSWORD_HASH HashedPassword;

    [MarshalAs(UnmanagedType.I1)]
    public bool PasswordMustChangeAtNextLogon;

    [MarshalAs(UnmanagedType.I1)]
    public bool ClearLockout;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NET_VALIDATE_PERSISTED_FIELDS
{
    public uint PresentFields;
    public System.Runtime.InteropServices.ComTypes.FILETIME PasswordLastSet;
    public System.Runtime.InteropServices.ComTypes.FILETIME BadPasswordTime;
    public System.Runtime.InteropServices.ComTypes.FILETIME LockoutTime;
    public uint BadPasswordCount;
    public uint PasswordHistoryLength;
    public IntPtr PasswordHistory;
}

public enum NET_API_STATUS : uint
{
    ERROR_ACCESS_DENIED = 5,
    ERROR_NOT_ENOUGH_MEMORY = 8,
    ERROR_INVALID_PARAMETER = 87,
    ERROR_INVALID_NAME = 123,
    ERROR_INVALID_LEVEL = 124,
    ERROR_SESSION_CREDENTIAL_CONFLICT = 1219,
    NERR_Success = 0,
    NERR_InvalidComputer = 2351,
    NERR_BadPassword = 2203,
    NERR_UserNotFound = 2221,
    NERR_AccountLockedOut = 2702,
    NERR_PasswordTooRecent = 2246,
    NERR_PasswordHistConflict = 2244,
    NERR_PasswordTooShort = 2245,
    NERR_PasswordTooLong = 2703,
    NERR_PasswordNotComplexEnough = 2704,
    NERR_PasswordFilterError = 2705,
    NERR_PasswordMustChange = 2701,
    NERR_PasswordExpired = 2242
}

public enum NET_VALIDATE_PASSWORD_TYPE
{
    NetValidateAuthentication = 1,
    NetValidatePasswordChange,
    NetValidatePasswordReset
}

"@

Add-Type -MemberDefinition $defs -Language CSharp -Name NetPWChk -Namespace TestCreds | Out-Null
}

<#
.Synopsis
   Test if a password would pass AD's password validation checks
.DESCRIPTION
   DOES NOT ACTUALLY CHECK IF THE PASSWORD IS CORRECT
.EXAMPLE
   PS> Test-PasswordValidates "jsmith" "password"

   Password not complex enough

.EXAMPLE
   Another example of how to use this cmdlet
.NOTES
   See also Test-ADAuthentication if you'd like to validate that a password is correct.
#>
function Test-PasswordValidates
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Whose password are we checking
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [String]$SamAccountName,

        # Password to check complexity for
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [String]$ClearPassword,

        # Domain Controller to try
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [String]$ServerName = ((Get-ADDomainController).Name),


        # Return a simple $true/$false?
        [Parameter(Mandatory=$false,
                   ParameterSetName="AsBoolean"
                    )]
        [switch]$AsBoolean,

        # Throw an exception when validation fails?
        [Parameter(Mandatory=$true,
                   ParameterSetName="AsException"
                    )]
        [switch]$AsException,

        # Return a string with details
        [Parameter(Mandatory=$true,
                   ParameterSetName="AsString"
                    )]
        [switch]$AsString

    )

    Begin
    {
    }
    Process
    {
        $retval = $false
        $InputArg = new-object -TypeName TestCreds.NetPwChk+NET_VALIDATE_PASSWORD_CHANGE_INPUT_ARG
        $InputArg.ClearPassword = [Runtime.InteropServices.Marshal]::StringToBSTR($ClearPassword)
        $InputArg.UserAccountName = $SamAccountName
        $InputArg.PasswordMatched = $true

        $InputArgPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($InputArg))
        [Runtime.InteropServices.Marshal]::StructureToPtr($InputArg, $InputArgPtr, $false)        

        $outputArg = new-object -TypeName TestCreds.NetPwChk+NET_VALIDATE_OUTPUT_ARG
        $OutputArgPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($outputArg))   

        $ret = [TestCreds.NetPWChk]::NetValidatePasswordPolicy($ServerName, 0, [TestCreds.NetPWChk+NET_VALIDATE_PASSWORD_TYPE]::NetValidatePasswordChange, $InputArgPtr, [ref]$OutputArgPtr) 

        if ($ret -eq [TestCreds.NetPWChk+NET_API_STATUS]::NERR_Success) {
            $OutputArg = [Runtime.InteropServices.Marshal]::PtrToStructure($OutputArgPtr, [System.Type][TestCreds.NetPwChk+NET_VALIDATE_OUTPUT_ARG])    

            write-verbose ($outputArg.ValidationStatus | Out-String)
            if ($AsString) {
                $retval = [string]($outputArg.ValidationStatus)
            } elseif ($AsException) {
                $retval = $true
                if ($OutputArg.ValidationStatus -ne [TestCreds.NetPWChk+NET_API_STATUS]::NERR_Success) {
                    throw [string]($outputArg.ValidationStatus)
                }
            } else {
                # AsBoolean
                $retval = ($OutputArg.ValidationStatus -eq [TestCreds.NetPWChk+NET_API_STATUS]::NERR_Success)
            }

        } else {
            write-error "Received an error when calling NetValidatePasswordPolicy: $($ret)"
            $retval = $false
        }
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($InputArg.ClearPassword)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($InputArgPtr)

        $ret = [TestCreds.NetPwChk]::NetValidatePasswordPolicyFree([ref]$outputArgPtr)
        if ($ret -ne [TestCreds.NetPWChk+NET_API_STATUS]::NERR_Success) {
            write-error "I may have just leaked some memory. Received an error when calling NetValidatePasswordPolicyFree: $($ret)"
        }
        [Runtime.InteropServices.Marshal]::FreeHGlobal($OutputArgPtr)

        return $retval
    }
    End
    {
    }
}

