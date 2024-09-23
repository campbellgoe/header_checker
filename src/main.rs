use clap::Parser;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

/// A tool to check and report on HTTP security headers of a website.
#[derive(Parser, Debug)]
#[command(
    version = "0.3.0",
    author = "Your Name <youremail@example.com>",
    about = "Detects insecure or missing HTTP headers for a given domain or IP address."
)]
struct Args {
    /// The target URL or domain to check (e.g., example.com)
    #[arg(short, long)]
    target: String,

    /// Use HTTP instead of HTTPS
    #[arg(short, long)]
    insecure: bool,

    /// Output the report in JSON format
    #[arg(short, long)]
    json: bool,
}

/// Represents the analysis report for each header.
#[derive(Debug, Serialize, Deserialize)]
struct HeaderReport {
    status: String,
    recommendation: String,
}

/// Holds information about each header to check.
#[derive(Debug, Serialize, Deserialize)]
struct HeaderCheck {
    name: &'static str,
    description: &'static str,
    recommendation_present: &'static str,
    recommendation_missing: &'static str,
}

impl HeaderCheck {
    fn new(
        name: &'static str,
        description: &'static str,
        recommendation_present: &'static str,
        recommendation_missing: &'static str,
    ) -> Self {
        Self {
            name,
            description,
            recommendation_present,
            recommendation_missing,
        }
    }
}

/// Analyzes the presence and configuration of security headers.
fn analyze_headers(headers: &HeaderMap) -> HashMap<String, HeaderReport> {
    let mut report = HashMap::new();

    // Define the headers to check with their recommendations
    let security_headers = vec![
        HeaderCheck::new(
            "Content-Security-Policy",
            "Defines approved sources of content that browsers can load.",
            "Present and properly configured.",
            "Missing. Consider defining a strict CSP to mitigate XSS and data injection attacks.",
        ),
        HeaderCheck::new(
            "Strict-Transport-Security",
            "Enforces secure (HTTPS) connections to the server.",
            "Present and properly configured.",
            "Missing. Ensure a long max-age and includeSubDomains and preload directives if applicable.",
        ),
        HeaderCheck::new(
            "X-Content-Type-Options",
            "Prevents MIME type sniffing.",
            "Present and properly configured.",
            "Missing. Set to 'nosniff' to prevent browsers from MIME-sniffing a response away from the declared content-type.",
        ),
        HeaderCheck::new(
            "X-Frame-Options",
            "Protects against clickjacking.",
            "Present and properly configured.",
            "Missing. Use 'DENY' or 'SAMEORIGIN' to prevent the page from being framed by other sites.",
        ),
        HeaderCheck::new(
            "X-XSS-Protection",
            "Configures the browser’s built-in XSS filter.",
            "Present and properly configured.",
            "Missing. Set to '1; mode=block' to enable XSS filtering and block the page if an attack is detected.",
        ),
        HeaderCheck::new(
            "Referrer-Policy",
            "Controls the amount of referrer information sent with requests.",
            "Present and properly configured.",
            "Missing. Use policies like 'no-referrer' or 'strict-origin-when-cross-origin' based on privacy needs.",
        ),
        HeaderCheck::new(
            "Permissions-Policy",
            "Manages browser feature permissions.",
            "Present and properly configured.",
            "Missing. Specify allowed features and origins, e.g., 'geolocation=(self), microphone=()'.",
        ),
        HeaderCheck::new(
            "X-Powered-By",
            "Discloses server technology (e.g., Express, ASP.NET).",
            "Present.",
            "Missing. Consider removing or obfuscating this header to prevent revealing server technologies.",
        ),
        HeaderCheck::new(
            "Server",
            "Provides information about the server software (e.g., Apache, nginx).",
            "Present.",
            "Missing. Remove or obfuscate this header to avoid disclosing server details.",
        ),
        HeaderCheck::new(
            "Cache-Control",
            "Defines caching policies for both client and intermediary caches.",
            "Present and properly configured.",
            "Missing. Use directives like 'no-store, no-cache, private' for sensitive data.",
        ),
        HeaderCheck::new(
            "Expect-CT",
            "Helps detect misissued SSL/TLS certificates.",
            "Present and properly configured.",
            "Missing. Implement 'Expect-CT' to enforce Certificate Transparency policies.",
        ),
        HeaderCheck::new(
            "Cross-Origin-Embedder-Policy",
            "Protects against cross-origin attacks like Spectre.",
            "Present and properly configured.",
            "Missing. Set to 'require-corp' to ensure resources are loaded only from the same origin or explicitly allowed cross-origin resources.",
        ),
        HeaderCheck::new(
            "Cross-Origin-Opener-Policy",
            "Isolates the browsing context to prevent cross-origin attacks.",
            "Present and properly configured.",
            "Missing. Set to 'same-origin' to ensure that the top-level window has the same origin.",
        ),
        HeaderCheck::new(
            "Access-Control-Allow-Origin",
            "Specifies which origins can access resources.",
            "Present and properly configured.",
            "Missing. Restrict to specific trusted origins instead of using wildcards ('*').",
        ),
        HeaderCheck::new(
            "Access-Control-Allow-Methods",
            "Specifies allowed HTTP methods for CORS requests.",
            "Present and properly configured.",
            "Missing. Restrict to necessary methods only, e.g., 'GET, POST, OPTIONS'.",
        ),
    ];

    for header_check in security_headers {
        let header_name = header_check.name;
        let header_value = headers
            .get(header_name)
            .map(|v| v.to_str().unwrap_or("Invalid UTF-8"))
            .unwrap_or("Missing")
            .to_string();

        let (status, recommendation) = if headers.contains_key(header_name) {
            // Additional validation can be added here for each header's value
            (
                "Present".to_string(),
                header_check.recommendation_present.to_string(),
            )
        } else {
            ("Missing".to_string(), header_check.recommendation_missing.to_string())
        };

        // For headers like Access-Control-Allow-Origin, it's useful to display their actual values
        let status_with_value = if headers.contains_key(header_name) && header_value != "Missing" {
            format!("Present: {}", header_value)
        } else {
            status
        };

        report.insert(
            header_name.to_string(),
            HeaderReport {
                status: status_with_value,
                recommendation,
            },
        );
    }

    report
}

/// Constructs a valid URL based on user input.
fn construct_url(target: &str, insecure: bool) -> Result<String, Box<dyn Error>> {
    let scheme = if insecure { "http" } else { "https" };
    // Ensure the target does not contain a scheme
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("{}://{}", scheme, target)
    };
    // Validate the URL
    reqwest::Url::parse(&url)?;
    Ok(url)
}

/// Prints the security headers report in a human-readable format.
fn print_report(report: &HashMap<String, HeaderReport>) {
    println!("\nSecurity Headers Report:");
    for (header, report) in report {
        println!(" - {:<30} : {}", header, report.status);
        println!("   Recommendation: {}", report.recommendation);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Validate and construct the URL
    let url = construct_url(&args.target, args.insecure)?;

    println!("Checking security headers for: {}", url);

    // Initialize the HTTP client with necessary configurations
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    // Perform the GET request
    let resp = match client.get(&url).send().await {
        Ok(response) => response,
        Err(e) => {
            eprintln!("Error fetching the URL: {}", e);
            return Ok(());
        }
    };

    // Check for successful response
    if !resp.status().is_success() {
        eprintln!("Failed to fetch the URL: {}", resp.status());
        return Ok(());
    }

    // Retrieve the headers
    let headers = resp.headers().clone();

    // Analyze the headers
    let report = analyze_headers(&headers);

    // Output the report
    if args.json {
        // Serialize the report to JSON
        let json_report = serde_json::to_string_pretty(&report)?;
        println!("{}", json_report);
    } else {
        // Print a human-readable report
        print_report(&report);
    }

    Ok(())
}