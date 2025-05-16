use clap::Parser;
use colored::*;
use regex::Regex;
use reqwest::blocking::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;
use std::sync::{Arc, Mutex};
use rayon::prelude::*;

/// Ultimate Web Reconnaissance Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target domain to enumerate
    #[arg(short, long)]
    domain: String,

    /// Perform port scanning (requires root privileges for masscan)
    #[arg(long, default_value_t = false)]
    port_scan: bool,

    /// Perform deep crawling with Katana
    #[arg(long, default_value_t = false)]
    deep_crawl: bool,

    /// Perform XSS scanning with Gxss
    #[arg(long, default_value_t = false)]
    xss_scan: bool,

    /// Threads/concurrency level for parallel tasks
    #[arg(short, long, default_value_t = 50)]
    threads: usize,

    /// Rate limit for masscan (packets per second)
    #[arg(long, default_value_t = 10000)]
    scan_rate: usize,

    /// Perform vulnerability scanning with Nuclei
    #[arg(long, default_value_t = false)]
    vuln_scan: bool,

    /// Enable verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    let start_time = Instant::now();
    let args = Args::parse();
    
    // Check and install required tools
    check_required_tools()?;

    let domain = &args.domain;
    print_banner(domain);

    // Create output directory structure
    let base = create_output_structure(domain)?;

    // 1. Comprehensive Subdomain Enumeration
    let subs_txt = comprehensive_subdomain_enum(domain, &base, args.verbose)?;

    // 2. Resolve IPs and perform port scanning if requested
    if args.port_scan {
        let ips_txt = resolve_ips(&subs_txt, &base, args.verbose)?;
        port_scan(&ips_txt, &base, args.scan_rate, args.verbose)?;
    }

    // 3. Find live hosts with multiple verification methods
    let http200_txt = find_live_hosts(&subs_txt, &base, args.threads, args.verbose)?;

    // 4. URL Discovery with multiple tools
    let all_urls = discover_urls(domain, &http200_txt, &base, args.deep_crawl, args.verbose)?;

    // 5. Parameter Discovery
    let params_file = discover_parameters(&all_urls, &base, args.verbose)?;

    // 6. XSS Scanning if requested
    if args.xss_scan {
        xss_scan(&all_urls, &base, args.verbose)?;
    }

    // 7. GF Pattern Matching
    gf_patterns(&all_urls, &base, args.verbose)?;

    // 8. Vulnerability scanning if requested
    if args.vuln_scan {
        run_vulnerability_scan(&http200_txt, &base, args.threads, args.verbose)?;
    }

    // 9. Generate final report
    generate_report(domain, &base, start_time)?;

    Ok(())
}

// --------------------------
// Core Functions
// --------------------------

fn check_required_tools() -> anyhow::Result<()> {
    let tools = [
        "subfinder", "haktrails", "tlsx", "dnsx", "httpx", "anew", 
        "hakrawler", "nuclei", "masscan", "jq", "katana", "gau",
        "paramfinder", "gxss", "gf", "urlfinder", "waybackurls", "unfurl",
    ];

    println!("{}", "[*] Checking required tools...".bright_blue());
    
    for tool in tools {
        let status = Command::new("which")
            .arg(tool)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        
        if !status.success() {
            println!("{} {}", "[!] Tool not found:".bright_yellow(), tool);
            println!("{}", "[*] Attempting to install missing tools...".bright_blue());
            
            // Install based on tool type
            match tool {
                "subfinder" | "httpx" | "dnsx" | "nuclei" | "katana" | "notify" => {
                    Command::new("sh")
                        .arg("-c")
                        .arg(format!("go install github.com/projectdiscovery/{}/cmd/{}@latest", tool, tool))
                        .status()?;
                },
                "haktrails" | "hakrawler" | "anew" => {
                    Command::new("sh")
                        .arg("-c")
                        .arg(format!("go install github.com/hakluke/{}@latest", tool))
                        .status()?;
                },
                "gau" | "gxss" => {
                    Command::new("sh")
                        .arg("-c")
                        .arg(format!("go install github.com/lc/{}@latest", tool))
                        .status()?;
                },
                "paramfinder" => {
                    Command::new("sh")
                        .arg("-c")
                        .arg("go install github.com/obheda12/paramfinder@latest")
                        .status()?;
                },
                "urlfinder" => {
                    Command::new("sh")
                        .arg("-c")
                        .arg("go install github.com/punk-security/urlfinder@latest")
                        .status()?;
                },
                "waybackurls" => {
                    Command::new("sh")
                        .arg("-c")
                        .arg("go install github.com/tomnomnom/waybackurls@latest")
                        .status()?;
                },
                "unfurl" => {
                    Command::new("sh")
                        .arg("-c")
                        .arg("go install github.com/tomnomnom/unfurl@latest")
                        .status()?;
                },
                "gf" => {
                    Command::new("sh")
                        .arg("-c")
                        .arg("go install github.com/tomnomnom/gf@latest")
                        .status()?;
                },
                _ => {
                    println!("{} {}", "[!] Please install manually:".bright_red(), tool);
                }
            }
        }
    }
    
    Ok(())
}

fn print_banner(domain: &str) {
    println!("\n{}", "=".repeat(80).bright_blue());
    println!("{} {}", "ULTIMATE WEB RECON TOOL".bright_green().bold(), format!("(Target: {})", domain).bright_white());
    println!("{}", "=".repeat(80).bright_blue());
    println!();
}

fn create_output_structure(domain: &str) -> anyhow::Result<&Path> {
    let base = Path::new(domain);
    
    // Create main directory
    fs::create_dir_all(base)?;
    
    // Create subdirectories
    let subdirs = ["subdomains", "urls", "params", "scans", "reports"];
    for dir in subdirs {
        fs::create_dir_all(base.join(dir))?;
    }
    
    Ok(base)
}

// --------------------------
// Enumeration Functions
// --------------------------

fn comprehensive_subdomain_enum(domain: &str, base: &Path, verbose: bool) -> anyhow::Result<std::path::PathBuf> {
    let output_file = base.join("subdomains").join("all_subs.txt");
    
    println!("{}", "[*] Starting comprehensive subdomain enumeration...".bright_blue());
    
    // 1. Subfinder - passive enumeration
    run_tool(
        "subfinder",
        &["-d", domain, "-silent"],
        &output_file,
        verbose
    )?;
    
    // 2. Haktrails - API-based enumeration
    run_tool(
        "sh",
        &["-c", &format!("echo {} | haktrails subdomains", domain)],
        &output_file,
        verbose
    )?;
    
    // 3. TLS certificate parsing
    run_tool(
        "sh",
        &["-c", &format!("echo {} | tlsx -san -cn -silent -json | jq -r '.subject_an[], .subject_cn' | grep -v null | sort -u", domain)],
        &output_file,
        verbose
    )?;
    
    // 4. Wayback machine subdomains
    run_tool(
        "sh",
        &["-c", &format!("curl -s 'http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey' | jq -r '.[][]' | sed 's/.*\\/\///' | cut -d'/' -f1 | sort -u", domain)],
        &output_file,
        verbose
    )?;
    
    // 5. DNS brute-forcing (common prefixes)
    let wordlist = if Path::new("/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt").exists() {
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
    } else {
        "/usr/share/wordlists/dns/subdomains-top1million-110000.txt"
    };
    
    run_tool(
        "sh",
        &["-c", &format!("puredns bruteforce {} {} --resolvers /usr/share/wordlists/dns/resolvers.txt | anew {}", wordlist, domain, output_file.display())],
        &output_file,
        verbose
    )?;
    
    // Sort and deduplicate
    run_tool(
        "sh",
        &["-c", &format!("cat {} | sort -u | anew {}", output_file.display(), output_file.display())],
        &output_file,
        verbose
    )?;
    
    println!("{} {}", "[+] Subdomain enumeration completed. Total found:".bright_green(), 
        count_lines(&output_file)?);
    
    Ok(output_file)
}

fn discover_urls(domain: &str, http200_txt: &Path, base: &Path, deep_crawl: bool, verbose: bool) -> anyhow::Result<std::path::PathBuf> {
    let urls_dir = base.join("urls");
    let all_urls = urls_dir.join("all_urls.txt");
    
    println!("{}", "[*] Starting comprehensive URL discovery...".bright_blue());
    
    // 1. Get URLs from live hosts
    run_tool(
        "sh",
        &["-c", &format!("cat {} | unfurl format %s://%d%p", http200_txt.display())],
        &all_urls,
        verbose
    )?;
    
    // 2. Gau - fetch known URLs from archives
    run_tool(
        "gau",
        &["-subs", domain],
        &all_urls,
        verbose
    )?;
    
    // 3. Waybackurls - historical URLs
    run_tool(
        "waybackurls",
        &[domain],
        &all_urls,
        verbose
    )?;
    
    // 4. URLFinder - JavaScript analysis
    if verbose {
        println!("{}", "[*] Running URLFinder on live hosts...".bright_blue());
    }
    let urls_js = urls_dir.join("js_urls.txt");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | xargs -P 10 -I % sh -c 'curl -s % | urlfinder --all' | anew {}",
            http200_txt.display(),
            urls_js.display()
        ))
        .status()?;
    run_tool(
        "sh",
        &["-c", &format!("cat {} | anew {}", urls_js.display(), all_urls.display())],
        &all_urls,
        verbose
    )?;
    
    // 5. Katana deep crawling if requested
    if deep_crawl {
        if verbose {
            println!("{}", "[*] Performing deep crawl with Katana...".bright_blue());
        }
        let katana_urls = urls_dir.join("katana_urls.txt");
        Command::new("katana")
            .args(&[
                "-list", &http200_txt.to_string_lossy(),
                "-jc", "-kf", "all",
                "-d", "5",
                "-c", "10",
                "-o", &katana_urls.to_string_lossy()
            ])
            .status()?;
        run_tool(
            "sh",
            &["-c", &format!("cat {} | anew {}", katana_urls.display(), all_urls.display())],
            &all_urls,
            verbose
        )?;
    }
    
    // Sort and deduplicate all URLs
    run_tool(
        "sh",
        &["-c", &format!("cat {} | sort -u | anew {}", all_urls.display(), all_urls.display())],
        &all_urls,
        verbose
    )?;
    
    println!("{} {}", "[+] URL discovery completed. Total found:".bright_green(), 
        count_lines(&all_urls)?);
    
    Ok(all_urls)
}

fn discover_parameters(all_urls: &Path, base: &Path, verbose: bool) -> anyhow::Result<std::path::PathBuf> {
    let params_dir = base.join("params");
    let all_params = params_dir.join("all_params.txt");
    
    println!("{}", "[*] Starting parameter discovery...".bright_blue());
    
    // 1. Extract parameters from URLs
    run_tool(
        "sh",
        &["-c", &format!("cat {} | unfurl keys | anew {}", all_urls.display(), all_params.display())],
        &all_params,
        verbose
    )?;
    
    // 2. ParamFinder - brute-force common parameters
    run_tool(
        "sh",
        &["-c", &format!("cat {} | xargs -P 10 -I % sh -c 'paramfinder -u %' | anew {}", all_urls.display(), all_params.display())],
        &all_params,
        verbose
    )?;
    
    // 3. Arjun - parameter brute-forcing
    run_tool(
        "sh",
        &["-c", &format!("arjun -i {} -o {} --stable", all_urls.display(), params_dir.join("arjun_results.txt").display())],
        &params_dir.join("arjun_results.txt"),
        verbose
    )?;
    run_tool(
        "sh",
        &["-c", &format!("cat {} | jq -r '.[] | .params | keys[]' | anew {}", 
            params_dir.join("arjun_results.txt").display(), all_params.display())],
        &all_params,
        verbose
    )?;
    
    // 4. Hakrawler for parameter discovery
    run_tool(
        "hakrawler",
        &["-url", &format!("@{}", all_urls.display()), "-plain", "-subs"],
        &all_params,
        verbose
    )?;
    
    // Sort and deduplicate
    run_tool(
        "sh",
        &["-c", &format!("cat {} | sort -u | anew {}", all_params.display(), all_params.display())],
        &all_params,
        verbose
    )?;
    
    println!("{} {}", "[+] Parameter discovery completed. Total found:".bright_green(), 
        count_lines(&all_params)?);
    
    Ok(all_params)
}

fn xss_scan(all_urls: &Path, base: &Path, verbose: bool) -> anyhow::Result<()> {
    let xss_dir = base.join("scans").join("xss");
    fs::create_dir_all(&xss_dir)?;
    
    println!("{}", "[*] Starting XSS scanning with Gxss and Nuclei...".bright_blue());
    
    // 1. Gxss - find potential XSS points
    run_tool(
        "sh",
        &["-c", &format!("cat {} | grep '=' | gxss -c 100 | anew {}", all_urls.display(), xss_dir.join("potential_xss.txt").display())],
        &xss_dir.join("potential_xss.txt"),
        verbose
    )?;
    
    // 2. Nuclei XSS templates
    run_tool(
        "nuclei",
        &["-l", &all_urls.to_string_lossy(), "-t", "xss", "-silent", "-o", &xss_dir.join("nuclei_xss.txt").to_string_lossy()],
        &xss_dir.join("nuclei_xss.txt"),
        verbose
    )?;
    
    println!("{}", "[+] XSS scanning completed.".bright_green());
    Ok(())
}

fn gf_patterns(all_urls: &Path, base: &Path, verbose: bool) -> anyhow::Result<()> {
    let gf_dir = base.join("scans").join("gf_patterns");
    fs::create_dir_all(&gf_dir)?;
    
    println!("{}", "[*] Running GF pattern matching...".bright_blue());
    
    let patterns = [
        "aws-keys", "base64", "cloudflare", "firebase", "google-api", 
        "jwt", "meganz", "microsoft-api", "slack", "sqli", "xss"
    ];
    
    for pattern in patterns {
        let output_file = gf_dir.join(format!("{}.txt", pattern));
        run_tool(
            "sh",
            &["-c", &format!("cat {} | gf {} | anew {}", all_urls.display(), pattern, output_file.display())],
            &output_file,
            verbose
        )?;
        
        if verbose && count_lines(&output_file)? > 0 {
            println!("{} {}", format!("[+] Found {} patterns:", pattern).bright_green(), 
                count_lines(&output_file)?);
        }
    }
    
    println!("{}", "[+] GF pattern matching completed.".bright_green());
    Ok(())
}

// --------------------------
// Helper Functions
// --------------------------

fn run_tool(tool: &str, args: &[&str], output_file: &Path, verbose: bool) -> anyhow::Result<()> {
    if verbose {
        println!("{} {} {}", "[>] Running:".bright_blue(), tool, args.join(" "));
    }
    
    let output = Command::new(tool)
        .args(args)
        .output()?;
    
    if !output.status.success() {
        eprintln!("{} {} {}", "[!] Error running:".bright_red(), tool, args.join(" "));
        if verbose {
            eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        }
        return Ok(());
    }
    
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(output_file)?;
    
    file.write_all(&output.stdout)?;
    
    Ok(())
}

fn count_lines(file: &Path) -> anyhow::Result<usize> {
    if !file.exists() {
        return Ok(0);
    }
    let file = File::open(file)?;
    Ok(BufReader::new(file).lines().count())
}

// ... [Previous functions like resolve_ips, port_scan, find_live_hosts, etc.] ...

fn generate_report(domain: &str, base: &Path, start_time: Instant) -> anyhow::Result<()> {
    let report_file = base.join("reports").join("final_report.txt");
    let mut report = File::create(&report_file)?;
    
    let duration = start_time.elapsed();
    
    writeln!(report, "=== Ultimate Web Recon Report ===")?;
    writeln!(report, "Target: {}", domain)?;
    writeln!(report, "Completed in: {:.2?}", duration)?;
    writeln!(report, "\n=== Summary ===")?;
    
    // Subdomains summary
    let subdomains_count = count_lines(&base.join("subdomains").join("all_subs.txt"))?;
    writeln!(report, "Subdomains found: {}", subdomains_count)?;
    
    // URLs summary
    let urls_count = count_lines(&base.join("urls").join("all_urls.txt"))?;
    writeln!(report, "Unique URLs found: {}", urls_count)?;
    
    // Parameters summary
    let params_count = count_lines(&base.join("params").join("all_params.txt"))?;
    writeln!(report, "Unique parameters found: {}", params_count)?;
    
    // Findings summary
    writeln!(report, "\n=== Key Findings ===")?;
    
    // Check for interesting files
    let interesting_files = [
        ("Potential XSS", "scans/xss/potential_xss.txt"),
        ("GF AWS Keys", "scans/gf_patterns/aws-keys.txt"),
        ("GF SQLi", "scans/gf_patterns/sqli.txt"),
        ("Nuclei Findings", "scans/nuclei.txt"),
    ];
    
    for (label, path) in interesting_files {
        let count = count_lines(&base.join(path))?;
        if count > 0 {
            writeln!(report, "{}: {}", label, count)?;
        }
    }
    
    println!("\n{} {}", "[+] Recon completed in".bright_green(), format!("{:.2?}", duration).bright_white());
    println!("{} {}", "[+] Final report saved to:".bright_green(), report_file.display());
    
    Ok(())
}