auto ea;
auto end;

ea = SegStart(ScreenEA());
end = SegEnd(ea);

SetLongPrm(INF_STRTYPE, ASCSTR_UNICODE);

while(ea < end)
{
if (Dword(ea) == 0x000204b0)
{
MakeDword(ea-4);
MakeWord(ea);
MakeWord(ea+2);
MakeDword(ea+4);
MakeDword(ea+8);
MakeStr(ea+0x0c, BADADDR);
Jump(ea);
ea = ea + 0x0c;
}
ea = ea + 4;
}
