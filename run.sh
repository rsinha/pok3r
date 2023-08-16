ps aux | grep pok3r | grep -v grep | awk '{print "kill -9 " $2}' | sh
rm -f /tmp/pok3r.log

target/debug/pok3r --seed 1 --id 12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X >> /tmp/pok3r.log &
target/debug/pok3r --seed 2 --id 12D3KooWH3uVF6wv47WnArKHk5p6cvgCJEb74UTmxztmQDc298L3 > /dev/null &
target/debug/pok3r --seed 3 --id 12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo > /dev/null &
