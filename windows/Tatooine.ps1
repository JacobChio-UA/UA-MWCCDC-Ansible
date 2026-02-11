function LandOnTat() {
        try {
            # Enable Windows Firewall for all profiles
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $true

            # Set default inbound policy to Block
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

            # Enable logging for dropped packets
            Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed $true -LogBlocked $true
        
            # Remove any existing inbound rules (optional - uncomment if needed)
            Get-NetFirewallRule -Direction Inbound | Remove-NetFirewallRule

            Write-Host "No Errors in 1st Stage, Continue" 
        }
        catch {
            Write-Host "1st Stage Failed"
        }
        try {
            # Begin Allowing Inbound Scoring
            New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Profile Domain,Public,Private -Enabled $true
            New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Profile Domain,Public,Private -Enabled $true

            # Block Outbound WinRM
            New-NetFirewallRule -DisplayName "Block WinRM Outbound" -Direction Outbound -Protocol TCP -LocalPort 5985,5986 -Action Block -Profile Domain,Public,Private -Enabled $true

            Write-Host "No Errors in 2nd Stage, Continue"
        }
        catch {
           Write-Host "2nd Stage Failed"
        }
    }


LandOnTat

