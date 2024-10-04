# Simple DoH Server for Blockchain Domains

This is a simple DoH server for blockchain domains. Currently, it can support the following blockchain domains:

- [.sol](https://sns.id/)
- [.bit](https://did.id/)

## Usage

```bash
curl -H "accept: application/dns-json" -X GET "https://dweb-dns.v2ex.pro/dns-query?name=v2ex.bit"
```

```json
{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": false,
  "AD": false,
  "CD": false,
  "Question": [
    {
      "name": "v2ex.bit.",
      "type": 16
    }
  ],
  "Answer": [
    {
      "name": "v2ex.bit",
      "type": 16,
      "TTL": 600,
      "data": "dnslink=/ipns/k51qzi5uqu5dkczezx3wje1dizdk7rta8uc50a5o9ix4wmzqniacrdbfapt8cf"
    }
  ],
  "Authority": [],
  "Additional": []
}
```

## Usage with Kubo (go-ipfs)

You can use this server with [Kubo](https://github.com/ipfs/kubo) by adding the following to your config:

```json
"DNS": {
  "Resolvers": {
    "bit.": "https://dweb-dns.v2ex.pro/dns-query",
    "sol.": "https://dweb-dns.v2ex.pro/dns-query"
  }
}
```

After that, your Kubo gateway will be able to resolve and access blockchain domains like this:

- https://ipfs.v2ex.pro/ipns/planetable.sol/
- https://ipfs.v2ex.pro/ipns/v2ex.bit/
- https://ipfs.v2ex.pro/ipns/planetable.bit/

With the IPFS support in Brave, you can access blockchain domains like this:

<img src="https://i.v2ex.co/kn0qc018.png" width="762" alt="ipns://v2ex.bit in Brave" />