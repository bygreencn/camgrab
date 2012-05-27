setlocal EnableDelayedExpansion 
for /f "delims=" %%i in ('dir /a/b *.flv') do ( 
  attrib "%%i" -h
  ren "%%i" "%%~ni.tvpm"
  attrib "%%~ni.tvpm" +h
  )
)