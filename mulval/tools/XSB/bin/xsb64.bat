@echo off
REM Script for running XSB when built natively on Windows x64

set XSBDIR=%~dp0\..
REM set XSBDIR=%0\..\..

"%XSBDIR%"\config\x64-pc-windows\bin\xsb %1 %2 %3 %4 %5 %6 %7
