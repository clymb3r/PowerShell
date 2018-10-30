# HackSql PowerShell Module by Cody Konior

There is no logo yet.

[![Build status](https://ci.appveyor.com/api/projects/status/8qb0c2fv1m1bsmb8?svg=true)](https://ci.appveyor.com/project/codykonior/hacksql)

Read the [CHANGELOG][3]

## Description

Before [PowerSploit][4] was released there was a script that could be used to run a script with the privileges of an arbitrary
user. I turned that into a module and added functionality to execute under whatever service account SQL Server was using. This
allowed you (if you had Administrator access to the Windows machine) to add an arbitrary login as sysadmin within the engine.

## Installation

- `Install-Module HackSql`

## Major functions

- `Start-HackSql`

## Tips

- This will work even if the Administrators group does not have access within SQL Server, but it will not work if you remove
  the service account's own access or similar access (e.g. NT SERVICE\MSSQLSERVER) from itself. That's commonly used to lock
  down SQL Server in some applications.
- It requires some tweaking for Failover Clusters to extract network names rather than assuming the local computer name is the
  right one to use.

[1]: Images/hacksql.ai.svg
[2]: Images/hacksql.gif
[3]: CHANGELOG.md
[4]: https://github.com/PowerShellMafia/PowerSploit
