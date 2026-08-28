new ManagementObjectSearcher(
"SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + process.Id);
var searchString = $"Select * From Win32_Process Where ParentProcessID={process.Id}";
using (var searcher = new ManagementObjectSearcher(searchString)) {}
const string wmiServiceQuery = "Select * from " + WMI_Class_Service + " Where name = 'Winmgmt'";
string queryString = "Select * From Win32_Service Where ProcessId=" + process.Id;
cimSession.QueryInstances("root/cimv2", "WQL", queryString);
