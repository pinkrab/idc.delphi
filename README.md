# idc.delphi
Script in IDC for IDA 4.9/5.x/6.x to support DELPHI classes decompilation.

This script is a porting in IDC of an IDA 5.x plugin wrote to support Delphi malware decompilation.

All classes must be in .text section, and they are identified by pattern TObject[0] == (offset(TObject + 0x4c) ||
offset(TObject+0x58)).

TObject + 4c =
{
	"SelfPtr",
	"IntfTable",
	"AutoTable",
	"InitTable",
	"TypeInfo",
	"FieldTable",
	"MethodTable",
	"DynamicTable",
	"ClassName",
	"InstanceSize",
	"Parent",
	"SafeCallException$qqrv",
	"AfterConstruction$qqrv",
	"BeforeDestruction$qqrv",
	"Dispatch$qqrv",
	"DefaultHandler$qqrv",
	"NewInstance$qqrv",
	"FreeInstance$qqrv",
	"Destroy$qqrv"
};

TObject + 58 =
{
	"SelfPtr",
	"IntfTable",
	"AutoTable",
	"InitTable",
	"TypeInfo",
	"FieldTable",
	"MethodTable",
	"DynamicTable",
	"ClassName",
	"InstanceSize",
	"Parent",
	"Equals$qqrv",
	"GetHashCode$qqrv",
	"ToString$qqrv",
	"SafeCallException$qqrv",
	"AfterConstruction$qqrv",
	"BeforeDestruction$qqrv",
	"Dispatch$qqrv",
	"DefaultHandler$qqrv",
	"NewInstance$qqrv",
	"FreeInstance$qqrv",
	"Destroy$qqrv"
};
