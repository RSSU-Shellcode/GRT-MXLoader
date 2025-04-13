IFDEF _WIN32
.model flat
ENDIF

.code

IFDEF _WIN32
  _InitPELoader@8 proc
  INCLUDE <inst/pe_loader_x86.inst>
  _InitPELoader@8 endp
ELSE
  InitPELoader proc
  INCLUDE <inst/pe_loader_x64.inst>
  InitPELoader endp
ENDIF

end
