@echo off
REM Script for running XSB when built natively on Windows x86

REM set XSBDIR=%0\..\..
set XSBDIR=%~dp0\..

"%XSBDIR%"\config\x86-pc-windows\bin\xsb %1 %2 %3 %4 %5 %6 %7
