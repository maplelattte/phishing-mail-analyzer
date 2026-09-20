#!/usr/bin/env python3

import sys
import email
from email import policy
import dns.resolver
from colorama import init, Fore

init(autoreset=True)


def analyze_header(eml_path):
    print(Fore.CYAN + f"\n[*] Analyzing email file : {eml_path}\n")
    try:
        with open(eml_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
    except Exception as e:
        print(Fore.RED + f"[!] Error Reading file : {e}")
        sys.exit(1)

    # extracting the core headers here
    subject = msg.get("Subject", "N/A")
    sender = msg.get("From", "N/A")
    return_path = msg.get("Return-Path", "N/A")

    print(Fore.YELLOW + "--- Basic Information ---")
    print(f"From : {sender}")
    print(f"Return-Path : {return_path}")
    print(f"Subject : {subject}\n")

    # extracting domain from sender address for dns checks and other stuff
    if "@" in sender:
        domain = sender.split("@")[-1].strip(">")
    else:
        domain = ""
    if domain:
        print(Fore.YELLOW + f"--- Authentication Checks for Domain : {domain} ---")
        check_spf(domain)
        check_dmarc(domain)


def check_spf(doamin):
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        spf_found = False
        for rdata in answers:
            txt_str = rdata.to_text()
            if "v=spf1" in txt_str:
                spf_found = True
                print(Fore.GREEN + f"[+] SPF Record Found : {txt_str}")
        if not spf_found:
            print(Fore.RED + "[-] No SPF record Found.")
    except Exception:
        print(Fore.RED + f"[-] SPF Lookup Failed (No TXT records or domain invalid).")


def check_dmarc(domain):
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        dmarc_found = False
        for rdata in answers:
            txt_str = rdata.to_text()
            if "v=DMARC1" in txt_str:
                dmarc_found = True
                print(Fore.GREEN + f"[+] DMARC Record Found : {txt_str}")
        if not dmarc_found:
            print(Fore.RED + f"[-] No DMARC Record Found.")
    except Exception:
        print(Fore.RED + f"[-] DMARC Record Missing or Lookup Failed.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(Fore.RED + "Usage: python main.py <path_to_email.eml>")
        sys.exit(1)
    analyze_header(sys.argv[1])
