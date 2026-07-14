var regNone = NewRegistrar("none");
var providerCf = DnsProvider(NewDnsProvider("cloudflare"));

var rootDomain = 'stupid.cat';   // the Cloudflare zone
var subdomainSuffix = 'is-a';    // records land at <name>.is-a.stupid.cat

var proxy = { // https://stackexchange.github.io/dnscontrol/providers/cloudflare
  on:  { "cloudflare_proxy": "on" },
  off: { "cloudflare_proxy": "off" }
}

// ---------------------------------------------------------------------------
// helpers
// dnsconfig.js runs in otto (ES5) - its regex engine panics on unmatched
// capture groups, so everything here uses plain string ops instead.
// ---------------------------------------------------------------------------

var ALLOWED_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789-_*.';

function isValidName(name) {
  if (!name || name === '@') return false;
  if (name.charAt(0) === '.') return false;
  if (name.charAt(name.length - 1) === '.') return false;
  if (name.indexOf('..') !== -1) return false;

  for (var i = 0; i < name.length; i++) {
    if (ALLOWED_CHARS.indexOf(name.charAt(i)) === -1) return false;
  }
  return true;
}

function stripJsonExt(filename) {
  if (filename.length > 5 && filename.substring(filename.length - 5) === '.json') {
    return filename.substring(0, filename.length - 5);
  }
  return filename;
}

function getDomainsList(filesPath) {
  var result = [];
  var files = glob.apply(null, [filesPath, true, '.json']);

  for (var i = 0; i < files.length; i++) {
    var parts = files[i].split("/");
    var name = stripJsonExt(parts[parts.length - 1]);

    result.push({ name: name, data: require(files[i]) });
  }

  return result;
}

// ---------------------------------------------------------------------------
// build records
// ---------------------------------------------------------------------------

var domains = getDomainsList('./domains');
var records = [];

for (var idx in domains) {
  var name = domains[idx].name;
  var domainData = domains[idx].data;

  // a bad filename must never escape the is-a namespace
  if (!isValidName(name)) {
    throw "Invalid domain file name: " + name;
  }

  var subdomainName = name + '.' + subdomainSuffix;   // example -> example.is-a
  var proxyState = proxy.off;                         // disabled by default

  if (domainData.proxied === true) {
    proxyState = proxy.on;
  }

  if (domainData.records.A) {
    for (var a in domainData.records.A) {
      records.push(A(subdomainName, IP(domainData.records.A[a]), proxyState));
    }
  }

  if (domainData.records.AAAA) {
    for (var aaaa in domainData.records.AAAA) {
      records.push(AAAA(subdomainName, domainData.records.AAAA[aaaa], proxyState));
    }
  }

  if (domainData.records.CNAME) {
    records.push(CNAME(subdomainName, domainData.records.CNAME + ".", proxyState));
  }

  if (domainData.records.MX) {
    for (var mx in domainData.records.MX) {
      records.push(MX(subdomainName, 10, domainData.records.MX[mx] + "."));
    }
  }

  if (domainData.records.NS) {
    for (var ns in domainData.records.NS) {
      records.push(NS(subdomainName, domainData.records.NS[ns] + "."));
    }
  }

  if (domainData.records.TXT) {
    for (var txt in domainData.records.TXT) {
      records.push(TXT(subdomainName, domainData.records.TXT[txt]));
    }
  }

  if (domainData.records.SRV) {
    for (var srv in domainData.records.SRV) {
      var srvRecord = domainData.records.SRV[srv];
      records.push(
        SRV(subdomainName, srvRecord.priority, srvRecord.weight, srvRecord.port, srvRecord.target + ".")
      );
    }
  }

  if (domainData.records.DS) {
    for (var ds in domainData.records.DS) {
      var dsRecord = domainData.records.DS[ds];
      records.push(
        DS(subdomainName, dsRecord.key_tag, dsRecord.algorithm, dsRecord.digest_type, dsRecord.digest)
      );
    }
  }
}

// ---------------------------------------------------------------------------
// commit
//
// NO_PURGE: DNSControl adds and updates records, but never deletes.
// Removing a domains/*.json will NOT remove the DNS record - do that by hand
// in the Cloudflare dashboard.
// ---------------------------------------------------------------------------

D(rootDomain, regNone, providerCf, NO_PURGE, records);