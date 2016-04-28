#include <idc.idc>

static CreateStruct(class_name, size)
{
     auto idx;
     auto field;
     auto pos;
    
     Message("struct %s size %x\n", class_name, size);
    
     idx = GetStrucIdByName(class_name + "_rec");
    
     if (idx != -1)
     {
          Message("\tOld struct removed\n");
          DelStruc(idx);
     }

     if (size > 0x1000)
          return;
         
     idx = AddStrucEx(-1, class_name + "_rec", 0);
    
     size = size - 4;
     AddStrucMember(idx, "vtbl", 0, FF_DWRD, 0, 4);
    
     field = 4;
     pos = 4;
    
     while(size > 0)
     {
          AddStrucMember(idx, "field_" + ltoa(field, 16), pos, FF_DWRD, 0, 4);
          field = field + 4;
          pos = pos + 4;
          size = size - 4;
     }
}

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

static CreateClass(base, min, max)
{
  auto class_name;
  auto class_size;
 
  class_name = GetClassName(Dword(base+0x20));
  class_size = Dword(base+0x24);
   
  Message("Found class %s\n", class_name);
 
  if (class_name == "")
  {
     return;
  }

  CreateStruct(class_name, class_size);
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
