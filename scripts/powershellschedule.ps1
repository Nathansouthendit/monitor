$trigger = New-JobTrigger -Daily -At 5:00am

Register-ScheduledJob `
    -Name "General dashboard3" `
    -FilePath "C:\monitor\generaldashboard.ps1" `
    -Trigger $trigger 

$trigger = New-JobTrigger -Daily -At 12:00pm

Register-ScheduledJob `
    -Name "General dashboard4" `
    -FilePath "C:\monitor\generaldashboard.ps1" `
    -Trigger $trigger 


$trigger = New-JobTrigger -Daily -At 3:00pm

Register-ScheduledJob `
    -Name "General dashboard5" `
    -FilePath "C:\monitor\generaldashboard.ps1" `
    -Trigger $trigger 

