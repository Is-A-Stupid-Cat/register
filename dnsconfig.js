var regNone = NewRegistrar("none");
var providerCf = DnsProvider(NewDnsProvider("cloudflare"));

var rootDomain = 'stupid.cat';   // the Cloudflare zone
var subdomainSuffix = 'is-a';    // we ONLY own *.is-a.stupid.cat

var proxy = {
  on:  { "cloudflare_proxy": "on" },
  off: { "cloudflare_proxy": "off" }
}

function getDomainsList(filesPath) {
  var result = [];
  var files = glob.apply(null, [filesPath, true, '.json']);

  for (var i = 0; i < files.length; i++) {
    var name = files[i].split("/").pop().replace(/\.json$/, "");
    result.push({ name: name, data: require(files[i]) });
  }

  return result;
}

var domains = getDomainsList('./domains');
var records = [];

for (var idx in domains) {
  var name = domains[idx].name;
  var domainData = domains[idx].data;

  // hard guard: never let a filename escape the is-a namespace
  if (!/^[a-z0-9_*-]+(\.[a-z0-9_*-]+)*$/.test(name) || name === '@') {
    throw "Invalid domain file name: " + name;
  }

  var subdomainName = name + '.' + subdomainSuffix;   // example -> example.is-a
  var proxyState = domainData.proxied === true ? proxy.on : proxy.off;

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
      var s = domainData.records.SRV[srv];
      records.push(SRV(subdomainName, s.priority, s.weight, s.port, s.target + "."));
    }
  }

  if (domainData.records.DS) {
    for (var ds in domainData.records.DS) {
      var d = domainData.records.DS[ds];
      records.push(DS(subdomainName, d.key_tag, d.algorithm, d.digest_type, d.digest));
    }
  }
}

D(
  rootDomain, regNone, providerCf,

  // --- hands off everything that isn't ours ---
  IGNORE("@"),    // apex records of stupid.cat (SOA-ish, MX, TXT, verification, etc.)
  IGNORE("?*"),   // any single-label record: a.stupid.cat, c.stupid.cat, www, mail...
                  // (also covers the bare is-a.stupid.cat apex, which we never manage)

  // add one line per foreign *multi-label* branch you also want protected, e.g.:
  // IGNORE("**.internal"),
  // IGNORE("**.k8s"),

  records
);