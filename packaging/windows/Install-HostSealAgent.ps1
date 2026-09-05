<#
.SYNOPSIS
    Installs or upgrades the HostSeal agent on a Windows Server host.

.DESCRIPTION
    This script is the Windows counterpart of the .deb's postinst, and it is the only PowerShell in
    HostSeal. That is a distinction worth stating plainly, because "HostSeal does not use PowerShell" is
    otherwise a sentence somebody will find this file and dispute.

    PowerShell is refused as an EXECUTION mechanism: nothing the agent does at run time invokes it,
    powershell.exe is in the interpreter deny-lists that internal/run and internal/intent both check, and
    docs/SECURITY.md §12 explains why Constrained Language Mode is not the boundary people take it for —
    about_Language_Modes states that under it "all cmdlets in Windows modules are fully functional and
    have complete access to system resources", and every act HostSeal's guarantee prevents is a cmdlet.

    PowerShell as an INSTALLER is a different question with a different answer. This runs once, from an
    administrator's own session, before there is an agent to constrain — exactly as postinst.sh runs as
    root and calls systemctl. An administrator who runs this already holds every privilege it uses.

    What it does:
      * copies the three binaries into %ProgramFiles%\HostSeal
      * registers the service as NT SERVICE\hostseal-agent, with no privileges beyond SeChangeNotify
      * adds that account to BUILTIN\Users, which is what Windows Update requires for a scan
      * sets explicit ACLs, rather than relying on what either directory inherits
      * creates an empty trusted-signers file, and never overwrites one that exists

.PARAMETER Source
    Directory holding hostseal-agent.exe, hostseal-update-scan.exe and hostseal.exe. Defaults to this
    script's own directory, which is where the release archive puts them.

.PARAMETER Uninstall
    Remove the service and the binaries. State, policy and the trust anchor are deliberately left
    behind; see the note where that happens.

.EXAMPLE
    .\Install-HostSealAgent.ps1
    Install or upgrade, then enrol this host with `hostseal.exe enroll` in the same elevated session.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $Source = $PSScriptRoot,
    [switch] $Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The service name and the account are one decision, not two: registering a service under this name is
# what causes NT SERVICE\hostseal-agent to exist. Changing one without the other produces a service that
# cannot start, with an error naming a logon failure rather than a name mismatch.
$ServiceName  = 'hostseal-agent'
$ServiceAccount = "NT SERVICE\$ServiceName"

# Program Files holds what bounds the agent; ProgramData holds what the agent owns. The split is the
# whole of local policy sovereignty on this platform. On Linux the policy file is protected by ownership
# — root:root, and the agent runs as somebody else — and Windows has no equivalent that comes for free.
$InstallDir = Join-Path $env:ProgramFiles 'HostSeal'
$StateDir   = Join-Path $env:ProgramData 'HostSeal'

# hostseal.exe is here because `hostseal enroll` runs on the host. It writes the private key and
# agent.json into the local state directory, so it cannot be run from somewhere else — a host installed
# without it would idle unenrolled for ever, reporting nothing and looking like a service that started.
$Binaries = @('hostseal-agent.exe', 'hostseal-update-scan.exe', 'hostseal.exe')

function Assert-Administrator {
    <#
        .SYNOPSIS
            Stops unless this session can actually do what follows.
        .DESCRIPTION
            Checked up front rather than discovered half way. A partial install — binaries copied, ACLs
            not set — leaves a policy file the agent's own account can rewrite, which is the one failure
            mode of this script that is worse than not running it.
    #>
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Install-HostSealAgent must run in an elevated session.'
    }
}

function Set-DirectoryAcl {
    <#
        .SYNOPSIS
            Replaces a directory's ACL with an explicit one.
        .DESCRIPTION
            Inheritance is disabled rather than relied on, and that is the point of this function
            existing at all. %ProgramData%'s inherited ACL grants CREATOR OWNER full control on new files
            and lets ordinary accounts create them; %ProgramFiles% inherits something stricter, but "the
            default is currently strict enough" is a property of a machine rather than of an
            installation. An inherited permission is one somebody can change without meaning to.
    #>
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [ValidateSet('Read', 'Modify')] [string] $AgentAccess
    )

    $acl = Get-Acl -Path $Path
    # $true, $false: protect from inheritance, and do not copy the inherited entries down first.
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void] $acl.RemoveAccessRule($rule) }

    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none    = [Security.AccessControl.PropagationFlags]::None
    $allow   = [Security.AccessControl.AccessControlType]::Allow

    foreach ($who in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $who, 'FullControl', $inherit, $none, $allow)))
    }

    $rights = if ($AgentAccess -eq 'Modify') { 'Modify' } else { 'ReadAndExecute' }
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $ServiceAccount, $rights, $inherit, $none, $allow)))

    Set-Acl -Path $Path -AclObject $acl
}

function Remove-HostSealService {
    <#
        .SYNOPSIS
            Stops and removes the service, if it is there.
        .DESCRIPTION
            Separated so that install and uninstall share one path. A service left running holds the
            binaries open and makes the copy below fail with a message about a file in use, which reads
            as a permissions problem and is not one.
    #>
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $existing) { return }

    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        # Waited for rather than assumed. The agent fsyncs a pending job result before an operation that
        # may not return, and removing the service while that was in flight is the one case where the
        # spool exists and does not help.
        $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    Remove-Service -Name $ServiceName
}

if ($Uninstall) {
    Assert-Administrator
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Remove the HostSeal agent')) {
        Remove-HostSealService

        # The binaries by name, never the directory. $InstallDir also holds policy.toml,
        # trusted-signers and server-ca.crt — files an administrator wrote — and a recursive remove
        # would take them with it while the message below promised it had not. Uninstalling removes the
        # software; it does not decide that this host should forget its policy or its trust anchor.
        # Deleting trusted-signers would silently re-open every destructive operation somebody had
        # closed, and the symptom appears only later, as a signature that should verify and does not.
        foreach ($name in $Binaries) {
            Remove-Item -Path (Join-Path $InstallDir $name) -Force -ErrorAction SilentlyContinue
        }

        Write-Host @"
Removed the HostSeal agent. Left in place, on purpose:

  $StateDir      enrolment state, the credential and any undelivered results
  $InstallDir    policy.toml, trusted-signers and server-ca.crt

Delete them by hand if this host is being decommissioned. A reinstall picks them up, which is what
makes an upgrade an upgrade rather than a fresh host with an empty trust anchor.
"@
    }
    return
}

Assert-Administrator

foreach ($name in $Binaries) {
    if (-not (Test-Path -Path (Join-Path $Source $name) -PathType Leaf)) {
        throw "$name is not in $Source. Point -Source at the directory holding the release binaries."
    }
}

if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Install the HostSeal agent')) { return }

Remove-HostSealService

foreach ($dir in @($InstallDir, $StateDir)) {
    if (-not (Test-Path -Path $dir)) { [void] (New-Item -Path $dir -ItemType Directory -Force) }
}
foreach ($name in $Binaries) {
    Copy-Item -Path (Join-Path $Source $name) -Destination (Join-Path $InstallDir $name) -Force
}

# The trust anchor ships empty and is never overwritten. That is the same promise the .deb makes through
# dpkg's conffile handling, kept here by hand because MSI has no equivalent and neither does a script:
# an installer that wrote this file unconditionally would silently disarm every host it upgraded.
$TrustedSigners = Join-Path $InstallDir 'trusted-signers'
if (-not (Test-Path -Path $TrustedSigners)) {
    Set-Content -Path $TrustedSigners -Value '' -NoNewline -Encoding ascii
}

# Likewise the policy file. A fresh host gets the shipped default; an upgraded one keeps what its
# administrator wrote.
$PolicyFile = Join-Path $InstallDir 'policy.toml'
if (-not (Test-Path -Path $PolicyFile)) {
    Copy-Item -Path (Join-Path $PSScriptRoot 'policy.toml') -Destination $PolicyFile
}

$binPath = '"{0}" run' -f (Join-Path $InstallDir 'hostseal-agent.exe')
New-Service -Name $ServiceName `
    -BinaryPathName $binPath `
    -DisplayName 'HostSeal agent' `
    -Description 'Reports this host to a HostSeal control plane. Outbound only; it has no listening port.' `
    -StartupType Automatic `
    -Credential (New-Object System.Management.Automation.PSCredential(
        $ServiceAccount, (New-Object System.Security.SecureString))) | Out-Null

# Delayed auto-start. A fleet agent has nothing to offer during boot and everything to gain from not
# competing with the services that do.
& "$env:SystemRoot\System32\sc.exe" config $ServiceName start= delayed-auto | Out-Null

# An empty required-privileges list. The SCM removes every privilege not named here, and never removes
# SeChangeNotifyPrivilege — so the token this service runs with holds exactly that and nothing else.
# SeShutdownPrivilege is therefore absent, which means this agent cannot restart its host even if its
# code tried to: docs/SECURITY.md §12.5 refuses host.reboot on Windows, and this is that refusal made
# structural rather than conditional.
#
# Note the direction. RequiredPrivileges can only ever REMOVE privileges. Naming one the account does not
# already hold does not grant it — the SCM refuses to start the service at all, with an error about the
# account rather than about the list.
& "$env:SystemRoot\System32\sc.exe" privs $ServiceName "" | Out-Null

# A restricted per-service SID. The service's own SID becomes a restricting SID on its token, so the
# process can write only where that SID is granted access — which is the nearest Windows equivalent of
# systemd's ProtectSystem, and it is why the ACLs above name the service account explicitly.
#
# It takes effect at the next start, not now. Setting it after the service is already running would look
# like it had worked and would not have.
& "$env:SystemRoot\System32\sc.exe" sidtype $ServiceName restricted | Out-Null

# BUILTIN\Users, and this is the one grant that is not least privilege for its own sake. Microsoft
# documents IUpdateSearcher as available to the Administrator, User and Power User groups; a virtual
# service account is not a member of any of them by default, so without this the update scan fails with
# E_ACCESSDENIED and the host reports its updates as unmeasurable for ever. Users is the weakest of the
# three that works.
$usersGroup = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')).Translate(
    [Security.Principal.NTAccount]).Value
& "$env:SystemRoot\System32\net.exe" localgroup ($usersGroup -replace '^BUILTIN\\', '') $ServiceAccount /add 2>$null | Out-Null

Set-DirectoryAcl -Path $InstallDir -AgentAccess Read
Set-DirectoryAcl -Path $StateDir   -AgentAccess Modify

Start-Service -Name $ServiceName

Write-Host @"
The HostSeal agent is installed and running as $ServiceAccount.

  Program files   $InstallDir      (the agent's account can read, not write)
  State           $StateDir        (the agent's account can write)
  Policy          $PolicyFile
  Trust anchor    $TrustedSigners  (empty: this host will accept no signed job until you add a key)

This host is not enrolled yet. Enrol it here, in this elevated session:

  & '$InstallDir\hostseal.exe' enroll --server https://your-control-plane --token TOKEN

Enrolment runs on the host rather than from your workstation: it generates the private key and writes
it into $StateDir, and that key is never transmitted.

A Windows host executes read-only intents: inventory, services, pending updates and reboot state. It
applies no updates and reboots nothing, and that is by design rather than by omission — see
docs/SECURITY.md section 12.
"@
