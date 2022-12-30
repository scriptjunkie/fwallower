# fwallower.ps1
# By Matt Weeks <scriptjunkie@scriptjunkie.us>
# (c) 2022 License: GPLv3
# Firewall Allower - to run when you're trying to make something work but want to be selective with
# what you allow out of your outbound Windows firewall.
$lastdesc = ''
while($true){
  $events = Get-WinEvent -LogName Security -MaxEvents 100 | where ID -eq 5157
  if($events){
    $events | %{
      $curdesc = ($events[0].Properties | %{$_.Value}) -join ";"
      if($curdesc -ne $lastdesc){
        $lastdesc = $curdesc
        $lwe = $events[0]
        $ip = $lwe.Properties[5].Value
        $spid = $lwe.Properties[0].Value
        $cmdline = (gwmi win32_process | where ProcessId -eq $spid).CommandLine
        $svcs = ''
        $svc = ''
        gwmi win32_service | %{
          if($_.ProcessId -eq $spid){
            $svcs = ("$svcs "+$_.Name)
            $svc = (" "+$_.DisplayName+" "+$_.Description)
          }
        }
        
        echo $cmdline
        $dnsc=ipconfig /displaydns
        $proc=$lwe.Properties[1].Value
        $curquery='';
        $origquery='';
        $lastline='';
        $dnsc | %{
          if($_.Contains("---------------")){$curquery=$lastline}
          if($_.Contains($ip)){$origquery=$curquery}
          $lastline = $_.Trim()
        }
        $res=Read-Host "Allow $ip ($origquery) ($spid $proc$svcs$svc)? y for yes, n or empty for no, t for /24"
        if($res -eq "y"){
          New-NetFirewallRule -Action Allow -Name "fwauto_$origquery$ip" -Direction Outbound -RemoteAddress $ip -DisplayName "auto $origquery $ip $svcs"
        }
        if($res -eq "t"){
          New-NetFirewallRule -Action Allow -Name "fwauto_$origquery$ip" -Direction Outbound -RemoteAddress $ip/24 -DisplayName "auto $origquery $ip $svcs"
        }
      }
    }
    Read-Host "Hit enter to requery"
  }else{
    Read-Host "No recent connection block events. Make sure you have run `nauditpol.exe /set /subcategory:"Filtering Platform Connection" /failure:enable`nand`nSet-NetFirewallProfile -All -DefaultOutboundAction Block`nand that the Windows Firewall is on`nand that something is trying to connect to the internet.`n`nPress enter to retry."
  }
}
