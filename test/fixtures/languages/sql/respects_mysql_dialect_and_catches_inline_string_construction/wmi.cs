new ManagementObjectSearcher(
"SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + process.Id);
var searchString = $"Select * From Win32_Process Where ParentProcessID={process.Id}";
using (var searcher = new ManagementObjectSearcher(searchString)) {}
