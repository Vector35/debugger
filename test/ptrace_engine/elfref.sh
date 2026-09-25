# reference: readelf on the same file, both symbol tables, same filters
f=$1
readelf -sW "$f" | awk 'NF>=8 && $1 ~ /:$/ { type=$4; ndx=$7; name=$8; val=$2; size=$3;
  if ((type=="FUNC"||type=="OBJECT"||type=="IFUNC") && ndx!="UND" && ndx!="ABS" && ndx!="COM" && name!="") { sub(/@.*/,"",name); printf "%s %s %d %d\n", name, val, size, (type=="OBJECT"?0:1) } }' | \
  python3 -c '
import sys
seen=set()
for l in sys.stdin:
    n,v,s,f=l.split(); v=int(v,16)
    if v==0: continue
    seen.add((n,v,int(s),int(f)))
for n,v,s,f in sorted(seen): print(n,format(v,"x"),s,f)
'
