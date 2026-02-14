function LandOnTatooine() {
        try {
            # Enable Windows Firewall for all profiles
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled true

            # Set default inbound policy to Block
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block

            # Enable logging for packets
            Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed true -LogBlocked true

            # Disallow Configuration Changes
            Set-NetFirewallProfile -Profile Domain,Public,Private -AllowLocalPolicyMerge false -AllowLocalIPsecPolicyMerge false -AllowLocalFirewallRules false -AllowLocalIPsecRules false

            Write-Host "No Errors in 1st Stage, Continue" 
        }
        catch {
            Write-Host "1st Stage Failed"
        }
        try {
            # Begin Allowing Inbound Scoring
            New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Profile Domain,Public,Private -Enabled true
            New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Profile Domain,Public,Private -Enabled true

            # Remove Preexisting Inbound Rules
            Get-NetFirewallRule -Direction Inbound | Remove-NetFirewallRule

            Write-Host "No Errors in 2nd Stage, Continue"
        }
        catch {
           Write-Host "2nd Stage Failed"
        }
        try{
           # Allow Communication with DNS and AD
            New-NetFirewallRule -DisplayName "Allow DNS" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -Profile Domain,Public,Private -Enabled true
            New-NetFirewallRule -DisplayName "Allow LDAP" -Direction Outbound -Protocol TCP -RemotePort 389,636,3268,3269 -Action Allow -Profile Domain,Public,Private -Enabled true
            New-NetFirewallRule -DisplayName "Allow Kerberos" -Direction Outbound -Protocol TCP -RemotePort 88 -Action Allow -Profile Domain,Public,Private -Enabled true
            
            Write-Host "No Errors in 3rd Stage, Continue"
        }  
        catch {
            Write-Host "3rd Stage Failed"
        }
        try {
            # Allow Necessary Connections
            Enable-NetFirewallRule -DisplayGroup "Core Networking"
            New-NetFirewallRule -DisplayName "Allow NTP" -Direction Outbound -Protocol UDP -RemotePort 123 -Action Allow -Profile Domain,Public,Private -Enabled true
            New-NetFirewallRule -DisplayName "Allow SMB" -Direction Outbound -Protocol TCP -RemotePort 445 -Action Allow -Profile Domain,Public,Private -Enabled true
            }
        catch {
            Write-Host "4th Stage Failed"
        }
    }



LandOnTat

