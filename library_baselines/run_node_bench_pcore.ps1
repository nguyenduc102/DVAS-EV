# Run a Node benchmark pinned to the P-cores (logical CPUs 0-15 on i7-13700F)
# with High priority, so Windows 11 does not schedule it on E-cores.
# Unpinned runs were ~2x slower and unstable (OZ settlement 3.27 ms vs 1.72 ms).
# Usage: pwsh run_node_bench_pcore.ps1 -Dir <bench dir> -Script <file.mjs> -Input <csv> -OutDir <dir>
param([string]$Dir, [string]$Script, [string]$InputCsv, [string]$OutDir)
$env:INPUT = $InputCsv
$env:OUT_DIR = $OutDir
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = (Get-Command node).Source
$psi.Arguments = $Script
$psi.WorkingDirectory = $Dir
$psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($psi)
$p.ProcessorAffinity = [IntPtr]0xFFFF
$p.PriorityClass = 'High'
$out = $p.StandardOutput.ReadToEnd()
$p.WaitForExit()
$out
exit $p.ExitCode
