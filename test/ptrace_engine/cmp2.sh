cd /work
g++ -std=c++20 -I/src -o elfcmp elfcmp.cpp /src/ptraceelf.cpp || exit 1
for f in "$@"; do
  ./elfcmp "$f" | awk '{print $1, $2, $4}' | sort -u > /tmp/ours.txt
  bash elfref.sh "$f" | awk '{print $1, $2, $4}' | sort -u > /tmp/ref.txt
  echo "$f: ours=$(wc -l < /tmp/ours.txt) ref=$(wc -l < /tmp/ref.txt) diff(name,addr,kind)=$(diff /tmp/ours.txt /tmp/ref.txt | grep -c '^[<>]')"
done
