ps aux | grep pok3r | grep -v grep | awk '{print "kill -9 " $2}' | sh
rm -f /tmp/pok3r/*
mkdir -p /tmp/pok3r

cargo b -r

# CHANGE THIS
n=5

# UNCOMMENT THIS
target/release/pok3r --parties $n --seed 1 --id 12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X >> /tmp/pok3r/1 &
target/release/pok3r --parties $n --seed 2 --id 12D3KooWH3uVF6wv47WnArKHk5p6cvgCJEb74UTmxztmQDc298L3 >> /tmp/pok3r/2 &
target/release/pok3r --parties $n --seed 3 --id 12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo >> /tmp/pok3r/3 &
target/release/pok3r --parties $n --seed 4 --id 12D3KooWLJtG8fd2hkQzTn96MrLvThmnNQjTUFZwGEsLRz5EmSzc >> /tmp/pok3r/4 &
target/release/pok3r --parties $n --seed 5 --id 12D3KooWSHj3RRbBjD15g6wekV8y3mm57Pobmps2g2WJm6F67Lay >> /tmp/pok3r/5 &
#target/release/pok3r --parties $n --seed 6 --id 12D3KooWDMCQbZZvLgHiHntG1KwcHoqHPAxL37KvhgibWqFtpqUY >> /tmp/pok3r/6 &
#target/release/pok3r --parties $n --seed 7 --id 12D3KooWLnZUpcaBwbz9uD1XsyyHnbXUrJRmxnsMiRnuCmvPix67 >> /tmp/pok3r/7 &
#target/release/pok3r --parties $n --seed 8 --id 12D3KooWQ8vrERR8bnPByEjjtqV6hTWehaf8TmK7qR1cUsyrPpfZ >> /tmp/pok3r/8 &
#target/release/pok3r --parties $n --seed 9 --id 12D3KooWNRk8VBuTJTYyTbnJC7Nj2UN5jij4dJMo8wtSGT2hRzRP >> /tmp/pok3r/9 &
#target/release/pok3r --parties $n --seed 10 --id 12D3KooWFHNBwTxUgeHRcD3g4ieiXBmZGVyp6TKGWRKKEqYgCC1C >> /tmp/pok3r/10 &
#target/release/pok3r --parties $n --seed 11 --id 12D3KooWHbEputWi1fJAxoYgmvvDe3yP7acTACqmXKGYwMgN2daQ >> /tmp/pok3r/11 &
#target/release/pok3r --parties $n --seed 12 --id 12D3KooWCxnyz1JxC9y1RniRQVFe2cLaLHsYNc2SnXbM7yq5JBbJ >> /tmp/pok3r/12 &
#target/release/pok3r --parties $n --seed 13 --id 12D3KooWFNisMCMFB4sxKjQ4VLoTrMYh7fUJqXr1FMwhqAwfdxPS >> /tmp/pok3r/13 &
#target/release/pok3r --parties $n --seed 14 --id 12D3KooW9ubkfzRCQrUvcgvSqL2Cpri5pPV9DuyoHptvshVcNE9h >> /tmp/pok3r/14 &
#target/release/pok3r --parties $n --seed 15 --id 12D3KooWRVJCFqFBrasjtcGHnRuuut9fQLsfcUNLfWFFqjMm2p4n >> /tmp/pok3r/15 &
#target/release/pok3r --parties $n --seed 16 --id 12D3KooWGtVQAq3A8GPyq5ZuwBoE4V278EkDpETijz1dm7cY4LsG >> /tmp/pok3r/16 &
#target/release/pok3r --parties $n --seed 17 --id 12D3KooWGjxVp88DuWx6P6cN5ZLtud51TNWK6a7K1h9cYb8qDuci >> /tmp/pok3r/17 &
#target/release/pok3r --parties $n --seed 18 --id 12D3KooWDWC9G1REgGwHTzVNtXL8x6okkRQzsYb7V9mw9UGKhC1H >> /tmp/pok3r/18 &
#target/release/pok3r --parties $n --seed 19 --id 12D3KooWE92WS4t4UBFxryqsx78hSaFaZMLaAkRwkynjsL1mdt8h >> /tmp/pok3r/19 &
#target/release/pok3r --parties $n --seed 20 --id 12D3KooWPcbijTPjNkihfs3DcJiMb1iQC1B2BCzP3vSggGvUgZsC >> /tmp/pok3r/20 &
#target/release/pok3r --parties $n --seed 21 --id 12D3KooWE1hRi1pECQ6bfxmeybMFEtYcTjJuhjxc75dZZLXwrdwy >> /tmp/pok3r/21 &
#target/release/pok3r --parties $n --seed 22 --id 12D3KooWCxkD42pVy9VZXGPQgBmL2ekc9kxME5YwriN3xTN6aBMx >> /tmp/pok3r/22 &
#target/release/pok3r --parties $n --seed 23 --id 12D3KooWFYZ24pnTgzhPJmznbMQTv8g9xdJANuM8wjkbCGrhWDvP >> /tmp/pok3r/23 &
#target/release/pok3r --parties $n --seed 24 --id 12D3KooWSM6emJRiK1AzUG39eFW42k8AUKLCk3fTFLh7GU1hPMFs >> /tmp/pok3r/24 &
#target/release/pok3r --parties $n --seed 25 --id 12D3KooWM7du63Ft3U51pDpJqNyiGRVU3Us2f4iuiwUEyxsB5P2M >> /tmp/pok3r/25 &
#target/release/pok3r --parties $n --seed 26 --id 12D3KooWCTvrtiEPSzY2UixVRuxVc81TGZjYHGU8YkJ7wuBrRRU8 >> /tmp/pok3r/26 &
#target/release/pok3r --parties $n --seed 27 --id 12D3KooWNLMpwyVysPSUj93RqpTDMxv5V9AsXc7NPgZPRUg4qD28 >> /tmp/pok3r/27 &
#target/release/pok3r --parties $n --seed 28 --id 12D3KooWJQK2dHWVMKPm9e1RPYgtQeix1hmS84B87rzhCP3uBep1 >> /tmp/pok3r/28 &
#target/release/pok3r --parties $n --seed 29 --id 12D3KooWP37FF5aY62MjcP5UJr1e3KJyu9cuARGFnFnTEkVdz6eh >> /tmp/pok3r/29 &
#target/release/pok3r --parties $n --seed 30 --id 12D3KooWNjR7M1659fBQXPpEs9tj959tgpD5T118vLojZKci9d4x >> /tmp/pok3r/30 &
#target/release/pok3r --parties $n --seed 31 --id 12D3KooWLcqHxG25dqsQqZAPz2zofcLrDga83pzsKAxy1G7GVbzg >> /tmp/pok3r/31 &
#target/release/pok3r --parties $n --seed 32 --id 12D3KooWDrAvsiX8hM5yVpDMrPEwSFRfQguLdBCVKgsYbVnqk2P4 >> /tmp/pok3r/32 &

tail -f /tmp/pok3r/1
