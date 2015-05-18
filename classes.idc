#include <idc.idc>

static GetClassName(value)
{
  Message("GetClassName %x:%s\n", value, GetString(value, -1, ASCSTR_PASCAL));
  MakeStr(value, -1);  // type must be PASCAL!

  return GetString(value, -1, ASCSTR_PASCAL);
}

static InRange(value, min, max)
{
  if (value >= min && value <= max)
    return 1;
  
  return 0;
}

static CreateFunction(addr, cname, member)
{
     auto mname;
    
     if (GetFunctionAttr(addr, FUNCATTR_START) == -1)
     {     // undefined function!
          MakeFunction(addr, BADADDR);     // Create function!
     }
    
     mname = Name(addr);
    
     if (strlen(member) > 0)
          MakeNameEx(addr, "@" + cname + "@" + member, SN_PUBLIC);
     else
     {     // assign this name
          MakeNameEx(addr, "@" + cname + "@" + "sub_" + ltoa(addr,16), SN_PUBLIC);
     }
    
     return 0;
    
}

static ProcessDynamicMethod(addr, cname)
{
     auto name;
    
     if (addr == 0)
          return -1;
    
     MakeWord(addr);
     MakeDword(addr+2);
    
     name = GetString(addr+4, -1, ASCSTR_PASCAL);
     CreateFunction(Dword(addr+2), cname, name);
}

static ProcessDynamicTable(addr, cname)
{
     auto members;
     auto ptr;
    
     if (addr == 0)
          return -1;     // no dynamic table
    
     MakeWord(addr);          // unnknown value!
     MakeWord(addr+2);     // dynamic methods count
    
     members = Word(addr+2);
     ptr = addr+4;
    
     while(members > 0)
     {
          MakeDword(ptr);
          MakeDword(ptr+4);
          ProcessDynamicMethod(Dword(ptr), cname);
          ptr = ptr + 8;     //
          members = members - 1;
     }
}

static CreateClass(base, min, max)
{
  auto class_name;
  auto base_class;
 
  class_name = GetClassName(Dword(base+0x20));
 
  base_class = base;
  if (class_name == "")
    return;

  MakeDword(base);      // ptr to vtbl
  MakeDword(base+4);    // ?
  MakeDword(base+8);
  MakeDword(base+0x0c);
  MakeDword(base+0x10);
  MakeDword(base+0x14);  // string name!
  MakeDword(base+0x18);
  MakeDword(base+0x1c);  
  MakeDword(base+0x20);
  MakeDword(base+0x24);
  MakeDword(base+0x28);
  MakeDword(base+0x2c);  
  MakeDword(base+0x30);
  MakeDword(base+0x34);
  MakeDword(base+0x38);
  MakeDword(base+0x3c);  
  MakeDword(base+0x40);
  MakeDword(base+0x44);
  MakeDword(base+0x48);
  MakeDword(base+0x4c);  
  MakeDword(base+0x50);
  MakeDword(base+0x54);
   
  class_name = GetClassName(Dword(base+0x20));

  CreateFunction(Dword(base+0x2c), class_name, "Equals$qqrv");
  CreateFunction(Dword(base+0x30), class_name, "GetHashCode$qqrv");
  CreateFunction(Dword(base+0x34), class_name, "ToString$qqrv");
  CreateFunction(Dword(base+0x38), class_name, "SafeCallException$qqrv");
  CreateFunction(Dword(base+0x3c), class_name, "AfterConstruction$qqrv");
  CreateFunction(Dword(base+0x40), class_name, "BeforeConstruction$qqrv");
  CreateFunction(Dword(base+0x44), class_name, "Dispatch$qqrv");
  CreateFunction(Dword(base+0x48), class_name, "DefaultHandler$qqrv");
  CreateFunction(Dword(base+0x4c), class_name, "NewInstance$qqrv");
  CreateFunction(Dword(base+0x50), class_name, "FreeInstance$qqrv");
  CreateFunction(Dword(base+0x54), class_name, "Destroy$qqrv");
 
  Message("Found class %s\n", class_name);

  MakeNameEx(base, "_" + class_name, SN_PUBLIC);
  MakeNameEx(base+0x58, class_name + "_vtbl",   SN_PUBLIC);

  base = base + 0x58;

  while(InRange(Dword(base), min, max) == 1)
  {
    MakeDword(base);
     CreateFunction(Dword(base), class_name, "");
    //MakeFunction(Dword(base), BADADDR);     // try to create!
    base = base + 4;  
  }
 
  ProcessDynamicTable(Dword(base_class + 0x18), class_name);
}


// reverse scan!
static main()
{
  auto ea;
  auto begin;
  auto end;
  auto dw;

  Message("Start...\n");
  ea = ScreenEA();

  begin = SegStart(ea);
  end = SegEnd(ea);

  ea = end-0x58;

  Message("Segment %x %x\n", begin, end);
 
  while(ea > begin)
  {
    dw = Dword(ea);

    if (InRange(dw, begin, end) == 1 && dw == (ea + 0x58))
    {  // class!
       Message("Found pattern at %x!\n", ea);
      CreateClass(ea, begin, end);
      ea = ea - 0x58;
       //return;
    }
    else
      ea = ea - 4;
  }
}