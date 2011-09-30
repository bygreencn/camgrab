setlocal EnableDelayedExpansion 
for /f "delims=" %%i in ('dir /a/b *.flv') do ( 
  attrib "%%i" -h
  ren "%%i" "%%~ni.tmp"
  attrib "%%~ni.tmp" +h
  )
)