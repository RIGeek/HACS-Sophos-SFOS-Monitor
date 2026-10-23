"""Generate a synthetic SFOS 22 snmpsim data file (sfos.snmprec).

Values are invented but follow SFOS-FIREWALL-MIB / IF-MIB structure.
Run: python make_snmprec.py > sfos.snmprec
"""
S = "1.3.6.1.4.1.2604.5.1"
rows = []
def add(oid, typ, val): rows.append((oid, typ, val))
# SNMPv2-MIB
add("1.3.6.1.2.1.1.1.0", 4, "Sophos Firewall SFOS 22.0.1")
add("1.3.6.1.2.1.1.2.0", 6, "1.3.6.1.4.1.2604.5")
add("1.3.6.1.2.1.1.3.0", 67, 123456789)
add("1.3.6.1.2.1.1.5.0", 4, "sfos-home")
# SFOS device info
add(f"{S}.1.1.0", 4, "HOME-XG")
add(f"{S}.1.2.0", 4, "SFVH")
add(f"{S}.1.3.0", 4, "SFOS 22.0.1 GA-Build 411")
add(f"{S}.1.4.0", 4, "S4000ABCDEF1234")
add(f"{S}.1.5.0", 4, "3.1.0.120")
add(f"{S}.1.6.0", 4, "22.1.24")
# stats
add(f"{S}.2.1.0", 4, "Fri Oct 23 13:00:00 2026")
add(f"{S}.2.2.0", 67, 123456789)
add(f"{S}.2.4.1.0", 66, 120000)
add(f"{S}.2.4.2.0", 66, 23)
add(f"{S}.2.5.1.0", 66, 15872)
add(f"{S}.2.5.2.0", 66, 41)
add(f"{S}.2.5.3.0", 66, 4096)
add(f"{S}.2.5.4.0", 66, 2)
add(f"{S}.2.6.0", 66, 3)
add(f"{S}.2.7.0", 70, 9876543)
add(f"{S}.2.8.0", 70, 0)
add(f"{S}.2.9.1.0", 70, 0)
add(f"{S}.2.9.2.0", 70, 0)
add(f"{S}.2.9.3.0", 70, 0)
# services: running(3) for most, untouched(0) for mail/ftp, stopped(1) for drouting
svc = {1:0,2:0,3:0,4:0,5:3,6:3,7:0,8:3,9:1,10:3,11:3,12:3,13:3,14:3,15:3,16:3,17:3,18:3,19:1,20:3,21:3}
for i, v in svc.items(): add(f"{S}.3.{i}.0", 2, v)
# HA
add(f"{S}.4.1.0", 2, 0)
add(f"{S}.4.4.0", 2, 2)
add(f"{S}.4.5.0", 2, 0)
add(f"{S}.4.6.0", 4, "")
add(f"{S}.4.7.0", 2, 0)
# licenses
lic = {1:(3,"Dec 31 2999"),2:(3,"Jan 15 2027"),3:(3,"Jan 15 2027"),4:(2,""),5:(2,""),6:(4,"Mar 01 2025"),7:(2,""),8:(2,""),9:(2,"")}
for i,(st,exp) in lic.items():
    add(f"{S}.5.{i}.1.0", 2, st); add(f"{S}.5.{i}.2.0", 4, exp)
# IPsec tunnel table
vpn = [(1,"Office-S2S","To work",1,3,"Port2",2),(2,"Cabin-Link","Barn/cabin",0,2,"Port2",0)]
E=f"{S}.6.1.1.1.1"
for idx,name,desc,status,ctype,gw,act in vpn:
    add(f"{E}.1.{idx}",2,idx); add(f"{E}.2.{idx}",4,name); add(f"{E}.3.{idx}",4,desc)
    add(f"{E}.4.{idx}",4,"IKEv2"); add(f"{E}.5.{idx}",4,"Main"); add(f"{E}.6.{idx}",2,ctype)
    add(f"{E}.7.{idx}",4,gw); add(f"{E}.8.{idx}",2,act); add(f"{E}.9.{idx}",2,status); add(f"{E}.10.{idx}",2,1)
# IF-MIB
ifs = [ (1,"lo",24,1,0,""), (2,"Port1",6,1,1000,"LAN"), (3,"Port2",6,1,1000,"WAN"),
        (4,"Port3",6,2,0,""), (5,"Port1.10",135,1,1000,"IoT VLAN"), (6,"ipsec0",131,1,0,"") ]
T="1.3.6.1.2.1.2.2.1"; X="1.3.6.1.2.1.31.1.1.1"
for idx,name,typ,oper,spd,alias in ifs:
    add(f"{T}.1.{idx}",2,idx); add(f"{T}.2.{idx}",4,name); add(f"{T}.3.{idx}",2,typ)
    add(f"{T}.4.{idx}",2,1500); add(f"{T}.5.{idx}",66,min(spd*1000000, 4294967295))
    add(f"{T}.6.{idx}","4x","0011223344%02x"%idx); add(f"{T}.7.{idx}",2,1); add(f"{T}.8.{idx}",2,oper)
    # 32-bit counters (static) and 64-bit counters (numeric variation = growing)
    add(f"{T}.10.{idx}",65,1000*idx); add(f"{T}.13.{idx}",65,idx); add(f"{T}.14.{idx}",65,2*idx)
    add(f"{T}.16.{idx}",65,500*idx); add(f"{T}.19.{idx}",65,0); add(f"{T}.20.{idx}",65,idx)
    add(f"{X}.1.{idx}",4,name)
    rate = 1250000*idx if oper == 1 else 0   # bytes/s
    add(f"{X}.6.{idx}","70:numeric",f"rate={rate},initial={10**10*idx}")
    add(f"{X}.10.{idx}","70:numeric",f"rate={rate//4},initial={10**9*idx}")
    add(f"{X}.15.{idx}",66,spd); add(f"{X}.18.{idx}",4,alias)
# IP-MIB ipAdEntIfIndex (index = IP)
for ip, idx in [("127.0.0.1",1),("172.16.16.16",2),("203.0.113.45",3),("10.10.10.1",5)]:
    add(f"1.3.6.1.2.1.4.20.1.2.{ip}",2,idx)
# HOST-RESOURCES hrSystemProcesses + hrProcessorLoad (4 cores)
add("1.3.6.1.2.1.25.1.6.0",66,212)
for core,load in zip(range(196608,196612),[12,20,8,16]): add(f"1.3.6.1.2.1.25.3.3.1.2.{core}",2,load)
# UCD laLoad
for i,v in [(1,"0.42"),(2,"0.35"),(3,"0.30")]: add(f"1.3.6.1.4.1.2021.10.1.3.{i}",4,v)

def key(o): return tuple(int(p) for p in o[0].split("."))
for oid,typ,val in sorted(rows,key=key):
    print(f"{oid}|{typ}|{val}")
