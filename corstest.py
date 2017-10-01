#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# python standard library
import re, sys, ssl, signal, urllib2, urlparse, argparse, multiprocessing

# -------------------------------------------------------------------------------------------------

def usage():
  parser = argparse.ArgumentParser(description="Simple CORS misconfigurations checker")
  parser.add_argument("infile", help="File with domain or URL list")
  parser.add_argument("-c", metavar="name=value", help="Send cookie with all requests")
  parser.add_argument("-p", metavar="processes", help="multiprocessing (default: 32)")
  parser.add_argument("-s", help="always force ssl/tls requests", action="store_true")
  parser.add_argument("-q", help="quiet, allow-credentials only", action="store_true")
  parser.add_argument("-v", help="produce a more verbose output", action="store_true")
  return parser.parse_args()

# -------------------------------------------------------------------------------------------------

def main():
  global args; args = usage()
  try:
    urls = [line.rstrip() for line in open(args.infile)]
    procs = min(abs(int(args.p or 32)), len(urls)) or 1
  except (IOError, ValueError) as e: print e; return
  # check domains/urls in parallel but clean exit on ctrl-c
  sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
  pool = multiprocessing.Pool(processes=procs)
  signal.signal(signal.SIGINT, sigint_handler)
  try: pool.map_async(check, urls).get(2**32)
  except KeyboardInterrupt: pass

# -------------------------------------------------------------------------------------------------

# check for vulns/misconfigurations
def check(url):
  if re.findall("^https://", url): args.s = True     # set protocol
  url = re.sub("^https?://", "", url)                # url w/o proto
  host = urlparse.urlparse("//"+url).hostname or ""  # set hostname
  acao = cors(url, url, False, True)                 # perform request
  if acao:
    if args.q and (acao == "no_acac" or "*" == acao): return
    if acao == "*": info(url, "* (without credentials)")
    elif acao in ["//", "://"]: alert(url, "Any origin allowed") # firefox/chrome/safari/opera only
    elif re.findall("\s|,|\|", acao): invalid(url, "Multiple values in Access-Control-Allow-Origin")
    elif re.findall("\*.", acao): invalid(url, 'Wrong use of wildcard, only single "*" is valid')
    elif re.findall("fiddle.jshell.net|s.codepen.io", acao): alert(url, "Developer backdoor")
    elif "evil.org" in cors(url, "evil.org"): alert(url, "Origin reflection")
    elif "null" == cors(url, "null").lower(): alert(url, "Null misconfiguration")
    elif host+".tk" in cors(url, host+".tk"): alert(url, "Post-domain wildcard")
    elif "not"+host in cors(url, "not"+url):
      alert(url, "Pre-domain wildcard") if sld(host) else warning(url, "Pre-subdomain wildcard")
    elif "sub."+host in cors(url, "sub."+url): warning(url, "Arbitrary subdomains allowed")
    elif cors(url, url, True).startswith("http://"): warning(url, "Non-ssl site allowed")
    else: info(url, acao)
  elif acao != None and not args.q: notvuln(url, "Access-Control-Allow-Origin header not present")
  # TBD: maybe use CORS preflight options request instead to check if cors protocol is understood
  sys.stdout.flush()

# -------------------------------------------------------------------------------------------------

# perform request and fetch response header
def cors(url, origin, ssltest=False, firstrun=False):
  url = ("http://" if not (ssltest or args.s) else "https://") + url
  if origin != "null": origin = ("http://" if (ssltest or not args.s) else "https://") + origin
  try:
    request = urllib2.Request(url)
    request.add_header('Origin', origin)
    request.add_header('Cookie', args.c or "")
    request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64)')
    if not "_create_unverified_context" in dir(ssl): response = urllib2.urlopen(request, timeout=10)
    else: response = urllib2.urlopen(request, timeout=10, context=ssl._create_unverified_context())
    acao = response.info().getheader('Access-Control-Allow-Origin')
    acac = str(response.info().getheader('Access-Control-Allow-Credentials')).lower() == "true"
    vary = "Origin" in str(response.info().getheader('Vary'))
    if args.v: print "%s\n%-10s%s\n%-10s%s\n%-10s%s\n%-10s%s" % ("-" * 72, "Resource:", \
               response.geturl(), "Origin:", origin, "ACAO:", acao or "-", "ACAC:", acac or "-")
    if firstrun:
      if args.q and not acac: acao = "no_acac"
      if acac and acao != '*' and not args.q: alert(url, "Access-Control-Allow-Credentials present")
      if vary and not args.q: warning(url, "Access-Control-Allow-Origin dynamically generated")
    if ssltest and response.info().getheader('Strict-Transport-Security'): acao = ""
    return (acao or "") if acac else ""
  except Exception as e:
    if not args.q: error(url, e.message or str(e).splitlines()[-1])
    if not firstrun: return ""

# -------------------------------------------------------------------------------------------------

# check if given hostname is a second-level domain
def sld(host):
  try:
    with open('tldlist.dat') as f: tlds = [line.strip() for line in f if line[0] not in "/\n"][::-1]
  except IOError as e: return True
  for tld in tlds:
    if host.endswith('.' + tld): host = host[:-len(tld)]
  if host.count('.') == 1: return True

# -------------------------------------------------------------------------------------------------

def error(url, msg): print "\x1b[2m" + url, "- Error:", msg + "\x1b[0m"
def alert(url, msg): print "\x1b[97;41m" + url, "- Alert:", msg + "\x1b[0m"
def invalid(url, msg): print "\x1b[30;43m" + url, "- Invalid:", msg + "\x1b[0m"
def warning(url, msg): print "\x1b[30;48;5;202m" + url, "- Warning:", msg + "\x1b[0m"
def notvuln(url, msg): print "\x1b[97;100m" + url, "- Not vulnerable:", msg + "\x1b[0m"
def info(url, msg): print "\x1b[30;42m" + url, "- Access-Control-Allow-Origin:", msg + "\x1b[0m"

# -------------------------------------------------------------------------------------------------

if __name__ == '__main__':
  main()
