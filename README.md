# OpenVpn-Pool-Overflow

OpenVpn Tap Driver use  NdisReadConfiguration for reading  some Configuration from Registry.
one of the obvious task before using any function, is you must read it manual 

NdisReadConfiguration manual:
https://msdn.microsoft.com/en-us/library/windows/hardware/ff564511(v=vs.85).aspx 
```
Note that NDIS does not validate values that a driver reads from the registry. The caller of NdisReadConfiguration must therefore not make any assumptions about such values and must validate each value read from the registry. If the caller determines that a value is out of bounds, it should use a default value instead.
```
tap0901.sys (IDA-Pro output ) :

```
Keyword.Buffer = (PWSTR)"N";
NdisReadConfiguration(&Status, &ParameterValue, ConfigurationHandle, &Keyword, NdisParameterString);
if ( Status || (v2 = ParameterValue, ParameterValue->ParameterType != 2) )
{
  Status = -1073676267;
}
else
{
  v3 = ParameterValue->ParameterData.StringData.Length;
  *(_WORD *)(v1 + 32) = v3;
  v4 = *(_WORD *)(v1 + 32);
  *(_WORD *)(v1 + 34) = v3;
  *(_DWORD *)(v1 + 36) = v1 + 40;
  memcpy((void *)(v1 + 40), v2->ParameterData.StringData.Buffer, v4);
```

tap0901.sys read some config string from NetCfgInstanceId Value under "\REGISTRY\MACHINE\SYSTEM\CONTROLSET001\CONTROL\CLASS\{4D36E972-E325-11CE-BFC1-08002BE10318}\00XX" key(00XX is something like 0012),
Then it copy this string to alocated Pool,without properley cheking  the size of string.

so if we change NetCfgInstanceId just before driver call  NdisReadConfiguration, We Write a string more than size of the Buffer in allocated Pool.
good news is this Pool is MiniportAdapterContext and i think we can overwrite something interesting to get code execution in Ring0 or just overwrite pool metadata

```
a773b1fa 6a02            push    2
a773b1fc 8d45e8          lea     eax,[ebp-18h]
a773b1ff 50              push    eax
a773b200 ff7508          push    dword ptr [ebp+8]
a773b203 8d45f0          lea     eax,[ebp-10h]
a773b206 50              push    eax
a773b207 8d45fc          lea     eax,[ebp-4]
a773b20a 50              push    eax
a773b20b c745eceee073a7  mov     dword ptr [ebp-14h],offset tap0901+0x40ee (a773e0ee)
a773b212 ffd7            call    edi ;NdisReadConfiguration
a773b214 395dfc          cmp     dword ptr [ebp-4],ebx
a773b217 754e            jne     tap0901+0x1267 (a773b267)
a773b219 8b4df0          mov     ecx,dword ptr [ebp-10h]
a773b21c 833902          cmp     dword ptr [ecx],2
a773b21f 7546            jne     tap0901+0x1267 (a773b267)
a773b221 0fb74104        movzx   eax,word ptr [ecx+4]
a773b225 66894620        mov     word ptr [esi+20h],ax
a773b229 0fb75620        movzx   edx,word ptr [esi+20h]
a773b22d 66894622        mov     word ptr [esi+22h],ax
a773b231 8d4628          lea     eax,[esi+28h]
a773b234 52              push    edx ; size of buffer
a773b235 894624          mov     dword ptr [esi+24h],eax ; soure memory  
a773b238 ff7108          push    dword ptr [ecx+8]
a773b23b 50              push    eax ; Destination memory 
a773b23c e8092b0000      call    tap0901+0x3d4a (a773dd4a) ; memcpy
```

eax is Destination pool pointer ,edx is size of copy
as you see pool size is 538 and it was less than number of byte we write to it 
```
3: kd> r
eax=83b45af8 ebx=00000000 ecx=83a8c7c4 edx=0000ffff esi=83b45ad0 edi=898ac5c9
eip=a773b23c esp=8a6c64c4 ebp=8a6c6518 iopl=0         nv up ei pl zr na pe nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00000246
tap0901+0x123c:
a773b23c e8092b0000      call    tap0901+0x3d4a (a773dd4a)
3: kd> !pool 83b45af8 
Pool page 83b45af8 region is Nonpaged pool
 83b45138 size:    8 previous size:    0  (Allocated)  Frag
 83b45140 size:  1b0 previous size:    8  (Free)       Free
 83b452f0 size:  208 previous size:  1b0  (Allocated)  Irp  Process: 856afd40
 83b454f8 size:  5d0 previous size:  208  (Allocated)  TapR
*83b45ac8 size:  538 previous size:  5d0  (Allocated) *TapA
	Owning component : Unknown (update pooltag.txt)
```


usefull breakPoints and outputs

NdisReadConfiguration lead to RtlQueryRegistryValues function 

```
2: kd> !handle 800009e0 

PROCESS 839ce020  SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 00185000  ObjectTable: 8a401b78  HandleCount: 529.
    Image: System

Kernel handle table at 8d94e000 with 529 entries in use

800009e0: Object: a7ba6a18  GrantedAccess: 000f003f Entry: 8caf63c0
Object: a7ba6a18  Type: (839e77f0) Key
    ObjectHeader: a7ba6a00 (new version)
        HandleCount: 1  PointerCount: 1
        Directory Object: 00000000  Name: \REGISTRY\MACHINE\SYSTEM\CONTROLSET001\CONTROL\CLASS\{4D36E972-E325-11CE-BFC1-08002BE10318}\0012

2: kd> p
nt!RtlQueryRegistryValues+0x26d:
81832470 8944240c        mov     dword ptr [esp+0Ch],eax
2: kd> ln 1832470

```

And BSOD output :

```
DRIVER_IRQL_NOT_LESS_OR_EQUAL (d1)
An attempt was made to access a pageable (or completely invalid) address at an
interrupt request level (IRQL) that is too high.  This is usually
caused by drivers using improper addresses.
If kernel debugger is available get stack backtrace.
Arguments:
Arg1: 03851576, memory referenced
Arg2: 00000002, IRQL
Arg3: 00000001, value 0 = read operation, 1 = write operation
Arg4: 89a76e75, address which referenced memory

Debugging Details:
------------------


WRITE_ADDRESS:  03851576 

CURRENT_IRQL:  2

FAULTING_IP: 
tcpip!TcpTcbHeaderSend+20f
89a76e75 668907          mov     word ptr [edi],ax

DEFAULT_BUCKET_ID:  INTEL_CPU_MICROCODE_ZERO

BUGCHECK_STR:  0xD1

PROCESS_NAME:  System

TRAP_FRAME:  8078f778 -- (.trap 0xffffffff8078f778)
ErrCode = 00000002
eax=038524c0 ebx=83b4a268 ecx=ff578963 edx=00000024 esi=83aed008 edi=03851576
eip=89a76e75 esp=8078f7ec ebp=8078f8ac iopl=0         nv up ei pl nz na po nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00010202
tcpip!TcpTcbHeaderSend+0x20f:
89a76e75 668907          mov     word ptr [edi],ax        ds:0023:03851576=????
Resetting default scope

LAST_CONTROL_TRANSFER:  from 816e1195 to 8166ecf8

STACK_TEXT:  
8078f8ac 89a67201 83aed008 00000010 00000002 tcpip!TcpTcbHeaderSend+0x20f
8078f8e0 89a620dc 83aed008 00000000 00000000 tcpip!TcpAcceptFin+0x6c
8078f8f8 89a7336a 83aed008 8078fa58 83aed008 tcpip!TcpAllowFin+0x56
8078f978 89a825dc 84829f40 83aed008 8078f9a0 tcpip!TcpTcbCarefulDatagram+0x16d5
8078f9e4 89a828fc 84829f40 83aed008 0078fa58 tcpip!TcpTcbReceive+0x228
8078fa4c 89a71a80 84792588 84827080 848270f4 tcpip!TcpMatchReceive+0x237
8078fa9c 89a62e2e 84829f40 8482700c 00005000 tcpip!TcpPreValidatedReceive+0x263
8078fab0 89a89563 8078facc 00000007 00000007 tcpip!TcpNlClientReceivePreValidatedDatagrams+0x15
8078fad4 89a89a68 8078fae0 00000000 00000007 tcpip!IppDeliverPreValidatedListToProtocol+0x33
8078fb70 89aa5c44 8529f778 00000000 839d74c0 tcpip!IpFlcReceivePreValidatedPackets+0x437
8078fb98 81693624 85242410 2228e0f1 847d1418 tcpip!FlReceiveNetBufferListChainCalloutRoutine+0xfc
8078fc00 89aa5cee 89aa5b48 8078fc28 00000000 nt!KeExpandKernelStackAndCalloutEx+0x132
8078fc3c 8989d18d 8529a002 85241400 00000000 tcpip!FlReceiveNetBufferListChain+0x7c
8078fc74 8988b670 8529b708 85241410 00000000 ndis!ndisMIndicateNetBufferListsToOpen+0x188
8078fc9c 8988b5e7 00000000 85241410 84a620e0 ndis!ndisIndicateSortedNetBufferLists+0x4a
8078fe18 89836ca5 84a620e0 00000000 00000000 ndis!ndisMDispatchReceiveNetBufferLists+0x129
8078fe34 8988ba2e 84a620e0 85241410 00000000 ndis!ndisMTopReceiveNetBufferLists+0x2d
8078fe5c 89836c1e 84a620e0 85241410 00000000 ndis!ndisMIndicateReceiveNetBufferListsInternal+0x62
8078fe84 8daf87f4 84a620e0 85241410 00000000 ndis!NdisMIndicateReceiveNetBufferLists+0x52
8078fecc 8daf777e 00000000 85255e38 00000001 E1G60I32!RxProcessReceiveInterrupts+0x108
8078fee4 8988b309 01d11008 00000000 8078ff10 E1G60I32!E1000HandleInterrupt+0x80
8078ff20 898369f4 85255e4c 00255e38 00000000 ndis!ndisMiniportDpc+0xe2
8078ff48 8166b9f5 85255e4c 85255e38 00000000 ndis!ndisInterruptDpc+0xaf
8078ffa4 8166b858 8172dd20 839d74c0 00000000 nt!KiExecuteAllDpcs+0xf9
8078fff4 8166b01c 8a6be874 00000000 00000000 nt!KiRetireDpcList+0xd5
8078fff8 8a6be874 00000000 00000000 00000000 nt!KiDispatchInterrupt+0x2c
WARNING: Frame IP not in any known module. Following frames may be wrong.
8166b01c 00000000 0000001a 00d6850f bb830000 0x8a6be874


STACK_COMMAND:  .trap 0xffffffff8078f778 ; kb

FOLLOWUP_IP: 
E1G60I32!RxProcessReceiveInterrupts+108
8daf87f4 8b45e8          mov     eax,dword ptr [ebp-18h]

SYMBOL_STACK_INDEX:  13

SYMBOL_NAME:  E1G60I32!RxProcessReceiveInterrupts+108

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: E1G60I32

IMAGE_NAME:  E1G60I32.sys

DEBUG_FLR_IMAGE_TIMESTAMP:  483de743

FAILURE_BUCKET_ID:  0xD1_E1G60I32!RxProcessReceiveInterrupts+108

BUCKET_ID:  0xD1_E1G60I32!RxProcessReceiveInterrupts+108

Followup: MachineOwner
---------
````

